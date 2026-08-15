"""
Screwhead — ReAct loop with tiered model routing and auto-escalation.

Flow:
  1. Classify challenge category
  2. Pick starting tier from CATEGORY_ROUTES
  3. Run ReAct loop: Think → Act (tool call) → Observe → repeat
  4. If stuck (loop detection or step limit), escalate to next tier
  5. On flag capture, stop and report
"""

import json
import re
import time
from difflib import SequenceMatcher
import openai
import anthropic
from config import (
    TIERS, CATEGORY_ROUTES, ESCALATION, JUDGE_TIER,
    MAX_STEPS, LOCAL_MAX_STEPS, ESCALATE_AFTER, LOOP_THRESHOLD,
    STEP_TIMEOUT, TIER_TIMEOUT,
)

# Optional Discord event sink (the bot wires this) for timeouts/escalations/recovery.
import threading
_event_sink = None
_ctx = threading.local()   # per-solve-thread context (which CTF is being solved)


def set_event_sink(fn):
    global _event_sink
    _event_sink = fn


def set_solve_ctf(ctf):
    """Tag the current thread's solve with its CTF so _emit can route to that
    CTF's Discord channel (each challenge solves in its own executor thread)."""
    _ctx.ctf = ctf


def _emit(msg: str):
    run_id = getattr(_ctx, "run_id", "------")
    tagged = f"[run:{run_id}] {msg}"
    print(f"[agent] {tagged}")
    fn = _event_sink
    if fn:
        ctf = getattr(_ctx, "ctf", None)
        try:
            fn(tagged, ctf)       # new sink signature (msg, ctf)
        except TypeError:
            try:
                fn(tagged)        # backward-compatible single-arg sink
            except Exception:
                pass
        except Exception:
            pass
from tools import TOOL_SCHEMAS, execute_tool
from fails import log_failure
from judge import FlagJudge
from detector import BullshitDetector


# ── System prompts ───────────────────────────────────────────────

CLASSIFIER_PROMPT = """You are a CTF challenge classifier. Given a challenge description,
respond with ONLY one of these categories: web, crypto, forensics, rev, pwn, misc, ai, unknown.
No explanation, just the single word."""

import importlib
import prompts


def _load_ctf_skill(category: str) -> str:
    """Load the local ctf-skills methodology for this category, if present."""
    from pathlib import Path
    mapping = {"rev": "ctf-reverse", "pwn": "ctf-pwn", "crypto": "ctf-crypto",
               "forensics": "ctf-forensics", "web": "ctf-web", "ai": "ctf-ai-ml",
               "misc": "ctf-misc", "unknown": "ctf-misc"}
    root = Path("/home/lilc/security-skills/ctf-skills") / mapping.get(category, "ctf-misc")
    skill = root / "SKILL.md"
    try:
        text = skill.read_text(errors="replace")
        # Concise mode: if the skill has an actionable "## FIRST ACTIONS" playbook,
        # inject THAT (the executable recipe) and drop the long technique-reference dump.
        # A 20KB encyclopedia overwhelms weaker local models — they freeze and emit no
        # tool call. The full reference stays on disk; point the model there for hard cases.
        if "## FIRST ACTIONS" in text:
            for marker in ("## Additional Resources", "## Supporting", "## References"):
                cut = text.find(marker)
                if cut != -1:
                    text = (text[:cut] +
                            f"\nFull technique reference (ROP/heap/kernel/format-string, etc.) is on disk — "
                            f"use read_file on {skill} ONLY for a hard case the playbook above doesn't cover.\n")
                    break
            return text[:8000]
        # Keep methodology useful without allowing the skill corpus to consume
        # the model's entire context window.
        return text[:24000]
    except Exception:
        return ""


def _load_redteam_skills(description: str, category: str) -> str:
    """Return the one or two offensive skills most relevant to this challenge."""
    from pathlib import Path

    root = Path("/home/lilc/security-skills/Claude-Red/Skills")
    stopwords = {
        "and", "are", "for", "from", "into", "the", "this", "that", "use",
        "using", "when", "with", "your", "challenge", "offensive", "security",
        "attack", "attacks", "methodology", "testing", "test", "covers",
    }

    def words(value: str) -> set[str]:
        return {
            word for word in re.findall(r"[a-z0-9]+", value.lower())
            if len(word) > 2 and word not in stopwords
        }

    entries = []
    try:
        paths = sorted(root.rglob("SKILL.md"))
    except Exception:
        return ""

    for path in paths:
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue

        body = text
        name = path.parent.name
        skill_description = ""
        if text.startswith("---"):
            match = re.match(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", text, re.DOTALL)
            if match:
                frontmatter = match.group(1)
                name_match = re.search(r"(?m)^name:\s*['\"]?([^'\"\n]+)", frontmatter)
                description_match = re.search(
                    r"(?m)^description:\s*['\"]?(.*?)(?:['\"]?\s*$)", frontmatter
                )
                if name_match:
                    name = name_match.group(1).strip()
                if description_match:
                    skill_description = description_match.group(1).strip().strip("'\"")
                body = text[match.end():].lstrip()

        # Some legacy files in the corpus predate YAML frontmatter. Keep all 58
        # searchable by using their equivalent Markdown metadata when needed.
        if not skill_description:
            legacy_name = re.search(r"(?im)^- \*\*Skill Name\*\*:\s*([^\n]+)", text)
            title = re.search(r"(?m)^#\s+(?:SKILL:\s*)?(.+)$", text)
            if legacy_name:
                name = legacy_name.group(1).strip()
            elif title:
                name = title.group(1).strip()
            paragraphs = re.findall(r"(?ms)^(?![#*`>-])([^\n].+?)(?:\n\s*\n|\Z)", text)
            skill_description = next((p.replace("\n", " ").strip() for p in paragraphs), "")

        entries.append((name, skill_description, body))

    query_words = words(f"{category} {description}")
    if not query_words:
        return ""

    ranked = []
    for name, skill_description, body in entries:
        name_words = words(name)
        description_words = words(skill_description)
        name_hits = query_words & name_words
        description_hits = query_words & description_words
        score = (6 * len(name_hits)) + len(description_hits)
        if category.lower() in name_words:
            score += 3
        if score:
            ranked.append((score, len(name_hits), name, body))

    if not ranked:
        return ""
    ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))
    selected = ranked[:1]
    if len(ranked) > 1 and ranked[1][0] >= max(2, ranked[0][0] // 3):
        selected.append(ranked[1])
    return "\n\n".join(item[3][:8000] for item in selected)


def _compact_for_tier(messages: list, tier_name: str) -> list:
    """Assemble the LLM's working set — the 'retrieve only what is needed' stage.

    PROACTIVE, not reactive: every local/fast turn gets system (prompt + RAG) + the
    challenge brief + a bounded rolling window of the most-recent (already-normalized)
    results — never the whole accumulating engagement. Older results are STORED (in
    `trace` + on disk under .step_outputs/) and retrievable on demand via read_file /
    cortex_search, so nothing is lost; it just doesn't ride in context and overwhelm
    the model. Frontier tiers (claude) keep full history (large context, cost aside)."""
    if tier_name not in ("fast", "local"):
        return messages
    # Lean target so local stays sharp: ~10K tokens of working set. The full record is
    # external, so a tight window is safe. (Raise WORKING_SET_CHARS to loosen.)
    WORKING_SET_CHARS = 40000
    MIN_TAIL = 4            # always keep the last few turns verbatim (immediate context)
    max_chars = 96000      # absolute ceiling backstop

    system = messages[:1]
    first_user = messages[1:2]
    tail = messages[2:]

    # Keep most-recent tail messages up to the char budget (min MIN_TAIL).
    used = sum(len(str(m.get("content", ""))) for m in system + first_user)
    kept: list = []
    for m in reversed(tail):
        c = len(str(m.get("content", "")))
        if len(kept) >= MIN_TAIL and used + c > WORKING_SET_CHARS:
            break
        kept.append(m)
        used += c
    kept.reverse()
    dropped = len(tail) - len(kept)

    if dropped <= 0:
        compact = system + first_user + kept
    else:
        # Tactical retention: before archiving old steps, PIN their high-signal findings
        # (flags, open ports, discovered paths, creds) so a key discovery from 20 steps
        # ago survives even though its raw output scrolled off. "Only what he needs" =
        # the findings, not the firehose.
        dropped_msgs = tail[:len(tail) - len(kept)]
        _SIGNAL = ("FLAG-FORMAT HITS", "OPEN PORTS", "PATHS FOUND",
                   "credential", "password", "secret", "api key", "token=", "PRIVATE KEY")
        findings: list = []
        for m in dropped_msgs:
            for line in str(m.get("content", "")).splitlines():
                ls = line.strip()
                if ls and any(s.lower() in ls.lower() for s in _SIGNAL) and ls not in findings:
                    findings.append(ls)
        note = (f"[{dropped} older step(s) archived — full output on disk (read_file the "
                ".step_outputs path shown at capture) and in memory (cortex_search). Work "
                "from KEY FINDINGS + SOLVE BRIEF + recent results; retrieve older evidence "
                "only if needed. Do not repeat actions already listed as failed.]")
        if findings:
            note = ("RETAINED KEY FINDINGS (from earlier, now-archived steps):\n"
                    + "\n".join(f"- {f}" for f in findings[:12]) + "\n\n" + note)
        summary = {"role": "user", "content": note}
        compact = system + first_user + [summary] + kept
    # Backstop: if even the working set is over the hard ceiling, drop oldest kept.
    while sum(len(str(m.get("content", ""))) for m in compact) > max_chars and len(compact) > 5:
        del compact[3]
    # Small-context local tier (122B, 16K): the preserved first_user (SOLVE BRIEF +
    # injected skills ~10K tok) can ALONE overflow the window — compaction only trims
    # middle messages, so it never touched this. Hard-truncate first_user so the full
    # request (messages + tool schemas + output) fits under 16384.
    if tier_name == "local" and len(compact) > 1:
        others = sum(len(str(m.get("content", ""))) for i, m in enumerate(compact) if i != 1)
        cap = max(4000, max_chars - others)
        fu = compact[1]
        if len(str(fu.get("content", ""))) > cap:
            compact[1] = {**fu, "content": str(fu.get("content", ""))[:cap]
                          + "\n[...skills truncated for 16K context...]"}
    return compact


# ── Client factory ───────────────────────────────────────────────

def _get_client(tier_name: str):
    """Return an OpenAI-compatible client for the given tier."""
    tier = TIERS[tier_name]
    # Anthropic uses its own client
    if "anthropic.com" in tier["base_url"]:
        return None  # handled separately
    return openai.OpenAI(
        base_url=tier["base_url"],
        api_key=tier["api_key"] or "not-needed",
    )


def _chat_completion(tier_name: str, messages: list, tools: list | None = None,
                     force_tool: bool = False) -> dict:
    """Unified completion call across all tiers."""
    tier = TIERS[tier_name]

    # ── Codex (ChatGPT subscription) path ────────────────────────
    if tier.get("provider") == "codex":
        return _codex_completion(tier, messages, tools)

    # ── Antigravity path (opt-in) ────────────────────────────────
    if tier.get("provider") == "antigravity":
        return _antigravity_completion(tier, messages, tools)

    # ── Anthropic path ───────────────────────────────────────────
    if "anthropic.com" in tier["base_url"]:
        return _anthropic_completion(tier, messages, tools)

    # ── OpenAI-compatible path (local vLLM, RunPod, OpenAI, Gemini)
    client = _get_client(tier_name)
    messages = _normalize_messages(messages)   # some llama.cpp/vLLM chat templates
                                               # 400 on consecutive assistant messages
    kwargs = {
        "model": tier["model"],
        "messages": messages,
        "temperature": 0.2,
        # 122B is ~10.7 tok/s → a 4096-tok gen = ~383s and blows STEP_TIMEOUT (300s),
        # which is exactly what NOFLAG'd it. Cap the slow local tier so a single call
        # can't time out (2500 tok ≈ 234s). Fast tier keeps the full budget.
        "max_tokens": 2000 if tier_name == "local" else 4096,
        "timeout": STEP_TIMEOUT,   # hard-kill a hung call at STEP_TIMEOUT
    }
    # Qwen3 "thinking" preamble wastes ~100 tok/call, slows the loop, and delays
    # the tool call (why short-max_tokens probes returned no tool_calls). Disable
    # it for the local Qwen tiers via the vLLM chat-template extension.
    if tier_name in ("fast", "local"):
        kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "required" if force_tool else "auto"

    try:
        resp = client.chat.completions.create(**kwargs)
        return _parse_openai_response(resp)
    except Exception as e:
        # Local models commonly fail when a long tool trace leaves too little
        # context headroom for the requested 4096-token answer. Retry once with
        # a small completion budget; preserve the original error only if that
        # conservative request also fails.
        detail = str(e)
        low = detail.lower()
        if ("maximum context" in low or "context length" in low
                or "input_tokens" in low or "too many tokens" in low):
            retry = dict(kwargs)
            retry["max_tokens"] = 1024
            try:
                resp = client.chat.completions.create(**retry)
                result = _parse_openai_response(resp)
                result["context_fallback"] = True
                return result
            except Exception as retry_error:
                return {"error": f"{detail}; context fallback failed: {retry_error}"}
        return {"error": str(e)}


def _codex_completion(tier: dict, messages: list, tools: list | None) -> dict:
    """Escalation via the Codex CLI (ChatGPT subscription). Codex is an autonomous
    agent, not a per-step chat model — so we delegate the WHOLE challenge to one
    `codex exec` run. It works in the challenge dir with real commands; if it prints
    a flag we surface it as a submit_flag tool-call so the normal judge/capture path
    runs. If it doesn't, its findings become context and the loop escalates onward."""
    import re
    system = ""
    convo = []
    for m in messages:
        if m.get("role") == "system":
            system = m.get("content", "") or system
        elif m.get("content"):
            convo.append(f"{m['role'].upper()}: {str(m['content'])[:1500]}")

    prompt = (
        f"{system}\n\n"
        "You are an autonomous CTF solver. Solve the challenge below by running real "
        "commands in the current working directory. When you find the flag, print it on "
        "its own line prefixed EXACTLY with 'FLAG: ' (e.g. 'FLAG: flag{...}'). If the "
        "answer is a literal phrase from the prompt (gate challenge), print that.\n\n"
        "=== CHALLENGE CONTEXT ===\n" + "\n".join(convo[-8:])
    )

    from tools import run_codex
    r = run_codex(prompt)
    out = (r.get("output") or "")
    blob = out + "\n" + (r.get("stderr") or "")

    if r.get("status") == "timeout":
        return {"error": "codex exec timed out", "content": "", "tool_calls": []}
    if r.get("status") == "error" and not out:
        return {"error": f"codex exec failed: {str(r.get('stderr',''))[:160]}",
                "content": "", "tool_calls": []}

    # Look for an explicit FLAG: line first, then any flag{...}-style token.
    m = re.search(r'FLAG:\s*(\S[^\n]*)', blob)
    if not m:
        m = re.search(r'([A-Za-z0-9_]{2,}\{[^}\n]{1,256}\})', blob)
    if m:
        flag = m.group(1).strip().strip('`"\' ')
        return {
            "content": out[:1000],
            "tool_calls": [{"id": "codex-flag", "name": "submit_flag",
                            "arguments": {"flag": flag}}],
        }
    # No flag — hand codex's findings back as reasoning; loop escalates onward.
    return {"content": out[:4000] or "(codex produced no output)", "tool_calls": []}


def _normalize_messages(messages: list) -> list:
    """Merge consecutive same-role messages so strict chat templates (some
    llama.cpp / vLLM servers) don't 400 on '2+ assistant messages in a row'.
    System stays as-is; empty content is dropped."""
    out = []
    for m in messages:
        role = m.get("role")
        content = m.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        if role != "system" and not content.strip():
            continue
        if out and out[-1]["role"] == role and role != "system":
            out[-1]["content"] = (out[-1]["content"] + "\n\n" + content).strip()
        else:
            out.append({"role": role, "content": content})
    return out


def _normalize_anthropic_conv(conv: list) -> list:
    """Anthropic (esp. Claude Code models) requires: non-empty content blocks,
    the conversation to START with a user turn, and to END with a user turn
    (no assistant 'prefill'). The ReAct loop can violate all three when it
    escalates to Claude mid-stream — this repairs the list so Claude stops 400ing.
    """
    # Drop empty-content messages (Anthropic rejects empty text blocks).
    cleaned = [m for m in conv if isinstance(m.get("content"), str) and m["content"].strip()]
    # Must start with a user message.
    while cleaned and cleaned[0]["role"] != "user":
        cleaned.pop(0)
    # Must end with a user message (else it's read as assistant prefill).
    if not cleaned or cleaned[-1]["role"] != "user":
        cleaned.append({
            "role": "user",
            "content": "Continue — take the next concrete action (call a tool, or submit_flag if you have the flag).",
        })
    return cleaned


def _anthropic_completion(tier: dict, messages: list, tools: list | None) -> dict:
    """Call Claude — via the Claude Code OAuth subscription or the SDK/API key."""
    # Convert OpenAI message format → Anthropic format
    system = ""
    conv = []
    for m in messages:
        if m["role"] == "system":
            system = m["content"]
        else:
            conv.append(m)
    conv = _normalize_anthropic_conv(conv)

    # Convert tool schemas to Anthropic format
    anth_tools = []
    if tools:
        for t in tools:
            f = t["function"]
            anth_tools.append({
                "name": f["name"],
                "description": f["description"],
                "input_schema": f["parameters"],
            })

    # ── OAuth path: Claude Code / Claude Max subscription ────────
    if tier.get("auth") == "oauth" and not tier.get("api_key"):
        import claude_auth
        try:
            resp = claude_auth.messages_create(
                model=tier["model"],
                system=system,
                conv=conv,
                tools=anth_tools or None,
                timeout=STEP_TIMEOUT,
            )
            return _parse_anthropic_json(resp)
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", "")
            return {"error": f"{e} {detail}".strip()}

    # ── API-key path: Anthropic SDK ─────────────────────────────
    client = anthropic.Anthropic(api_key=tier["api_key"])
    try:
        kwargs = {
            "model": tier["model"],
            "max_tokens": 4096,
            "system": system,
            "messages": conv,
            "timeout": STEP_TIMEOUT,
        }
        if anth_tools:
            kwargs["tools"] = anth_tools
        resp = client.messages.create(**kwargs)
        return _parse_anthropic_response(resp)
    except Exception as e:
        return {"error": str(e)}


def _antigravity_completion(tier: dict, messages: list, tools: list | None) -> dict:
    """Call the Antigravity gateway (Gemini 3.1 Pro / Claude 4.6) via OAuth."""
    import antigravity_auth
    system = ""
    conv = []
    for m in messages:
        if m["role"] == "system":
            system = m["content"]
        else:
            conv.append(m)
    try:
        return antigravity_auth.chat(tier["model"], system, conv, tools)
    except Exception as e:
        detail = getattr(getattr(e, "response", None), "text", "")
        return {"error": f"{e} {detail}".strip()}


def _parse_anthropic_json(resp: dict) -> dict:
    """Normalize a raw Anthropic Messages JSON response to our internal format."""
    result = {"content": "", "tool_calls": []}
    for block in resp.get("content", []):
        btype = block.get("type")
        if btype == "text":
            result["content"] += block.get("text", "")
        elif btype == "tool_use":
            result["tool_calls"].append({
                "id": block["id"],
                "name": block["name"],
                "arguments": block.get("input", {}),
            })
    return result


def _strip_reasoning(text: str) -> str:
    """Strip a reasoning model's <think>…</think> chain-of-thought.

    Local GB10 models (e.g. the Qwen3-Coder reasoning distill) emit thinking
    before the answer. Downstream — the classifier, flag extraction, the judge,
    and conversational chat — want only the final answer.

    - If a closing </think> exists, keep only what follows the LAST one.
    - If <think> opened but never closed (model hit the token cap mid-thought),
      drop the opening tag and return the remainder rather than leaking the tag.
    """
    if not text:
        return ""
    low = text.lower()
    if "</think>" in low:
        return text[low.rindex("</think>") + len("</think>"):].strip()
    if low.lstrip().startswith("<think>"):
        return re.sub(r"^\s*<think>", "", text, flags=re.IGNORECASE).strip()
    return text.strip()


def _parse_openai_response(resp) -> dict:
    """Normalize an OpenAI-style response."""
    msg = resp.choices[0].message
    result = {"content": _strip_reasoning(msg.content), "tool_calls": []}
    if msg.tool_calls:
        for tc in msg.tool_calls:
            result["tool_calls"].append({
                "id": tc.id,
                "name": tc.function.name,
                "arguments": json.loads(tc.function.arguments),
            })
    return result


def _parse_anthropic_response(resp) -> dict:
    """Normalize an Anthropic response to match our internal format."""
    result = {"content": "", "tool_calls": []}
    for block in resp.content:
        if block.type == "text":
            result["content"] += block.text
        elif block.type == "tool_use":
            result["tool_calls"].append({
                "id": block.id,
                "name": block.name,
                "arguments": block.input,
            })
    return result


# ── Challenge classifier ─────────────────────────────────────────

def classify_challenge(description: str) -> str:
    """Classify a challenge into a category using the fast tier."""
    messages = [
        {"role": "system", "content": CLASSIFIER_PROMPT},
        {"role": "user", "content": description},
    ]
    resp = _chat_completion("fast", messages)
    if "error" in resp:
        return "unknown"
    category = resp.get("content", "unknown").strip().lower()
    if category not in CATEGORY_ROUTES:
        return "unknown"
    return category


# ── Loop detection ────────────────────────────────────────────────

class LoopDetector:
    """Detect when the agent is repeating the same actions."""

    def __init__(self, threshold: int = LOOP_THRESHOLD):
        self.threshold = threshold
        self.recent_actions: list[str] = []

    def record(self, action_signature: str):
        self.recent_actions.append(action_signature)

    def is_looping(self) -> bool:
        if len(self.recent_actions) < self.threshold:
            return False
        last_n = self.recent_actions[-self.threshold:]
        return len(set(last_n)) == 1


def _recall_first_hit(description: str, challenge_name: str = "") -> tuple[str, dict] | None:
    """Return a flag only from a high-confidence memory for this exact challenge."""
    try:
        import cortex
        query = "\n".join(part for part in (challenge_name, description) if part)
        hits = cortex.query_similar_solves(query, "", n=5)
    except Exception as exc:
        print(f"  [cortex] recall-first skipped ({exc})")
        return None

    def normalized(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()

    wanted_name = normalized(challenge_name)
    wanted_description = normalized(description)
    for hit in hits:
        content = str(hit.get("content") or "")
        meta = hit.get("meta") or {}
        relevance = hit.get("relevance", meta.get("relevance_score", meta.get("score", 0))) or 0
        confidence = meta.get("confidence", 0) or 0
        try:
            high_confidence = float(relevance) >= 0.80 and float(confidence) >= 0.80
        except (TypeError, ValueError):
            high_confidence = False
        if not high_confidence:
            continue

        remembered = re.search(r"(?im)^CHALLENGE:\s*(.+)$", content)
        remembered_challenge = normalized(remembered.group(1) if remembered else content)
        same_name = len(wanted_name) >= 4 and wanted_name in normalized(content)
        same_description = (
            len(wanted_description) >= 20
            and (wanted_description in remembered_challenge
                 or remembered_challenge in wanted_description
                 or SequenceMatcher(None, wanted_description, remembered_challenge).ratio() >= 0.90)
        )
        if not (same_name or same_description):
            continue

        match = re.search(r"(?im)^FLAG:\s*([^\r\n]+)", content)
        if not match:
            continue
        flag = match.group(1).strip().strip("`\"' ")
        if flag:
            return flag, hit
    return None


# ── Main agent loop ──────────────────────────────────────────────

_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\n]{1,120}\}")


def _result_text(result) -> str:
    """Concatenate the human-readable text fields of a tool result."""
    if not isinstance(result, dict):
        return str(result)
    parts = [str(result[k]) for k in
             ("stdout", "stderr", "output", "content", "body", "logs", "message")
             if result.get(k)]
    return "\n".join(parts) if parts else json.dumps(result)[:2000]


def _flag_hits(text: str) -> list:
    out = []
    for m in _FLAG_RE.findall(text or ""):
        if m not in out:
            out.append(m)
    return out


def _normalize_by_content(cmd: str, raw: str):
    """Distill noisy security-tool output into a few structured records. Returns a
    compact string, or None if this output has no known shape (falls back to generic)."""
    low = (cmd or "").lower()
    # nmap → open ports/services
    if "nmap" in low or re.search(r"(?m)^\s*PORT\s+STATE\s+SERVICE", raw):
        rows = re.findall(r"(?m)^(\d{1,5}/\w+)\s+(open|filtered|closed)\s+(\S.*)$", raw)
        opens = [f"{p} {svc.strip()[:28]}" for p, st, svc in rows if st == "open"]
        if opens:
            return f"OPEN PORTS ({len(opens)}): " + ", ".join(opens[:25])
    # web dir/content enumeration → found paths + status
    if any(t in low for t in ("gobuster", "ffuf", "dirb", "feroxbuster", "dirsearch")) \
            or re.search(r"Status:\s*\d{3}", raw):
        paths = re.findall(r"(/\S+)\s*\(?Status:?\s*(\d{3})", raw) \
            or [(b, a) for a, b in re.findall(r"(?m)^(\d{3})\s+\S+\s+(/\S+)", raw)]
        found = list(dict.fromkeys(f"{p} [{s}]" for p, s in paths))[:20]
        if found:
            return f"PATHS FOUND ({len(found)}): " + ", ".join(found)
    return None


def _normalize_tool_output(name: str, args, result, step: int) -> str:
    """Compact, structured view of a tool result for the model's context. Surfaces any
    flag-format hit FIRST (so truncation never hides a flag), distills known noisy tools
    into records, and externalizes full output to disk (retrievable via read_file) so
    the model holds a working view — not the whole engagement."""
    raw = _result_text(result)
    status = result.get("status", "?") if isinstance(result, dict) else "?"
    lines = [f"[{name}] status={status}"]

    hits = _flag_hits(raw)
    if hits:
        lines.append("FLAG-FORMAT HITS: " + " | ".join(hits[:5]))

    cmd = ""
    if isinstance(args, dict):
        cmd = str(args.get("command") or args.get("code") or args.get("url") or "")
    norm = _normalize_by_content(cmd, raw)
    if norm:
        lines.append(norm)

    err = result.get("stderr") if isinstance(result, dict) else ""
    if err and status not in ("ok", "success", "captured", ""):
        lines.append("ERROR: " + str(err)[:300])

    body = raw.strip()
    CAP = 1200
    if len(body) <= CAP:
        if body and not norm:
            lines.append(body)
    else:
        ref = f"[{len(body)} chars omitted]"
        try:
            import os as _os
            from workspace import get_workdir
            d = _os.path.join(get_workdir(), ".step_outputs")
            _os.makedirs(d, exist_ok=True)
            path = _os.path.join(d, f"step{step}_{name}.txt")
            with open(path, "w") as fh:
                fh.write(raw)
            ref = f"[full {len(body)} chars saved — read_file {path} for the rest]"
        except Exception:
            pass
        if not norm:
            lines.append(body[:700] + "\n...[truncated]...\n" + body[-200:] + "\n" + ref)
        else:
            lines.append(ref)

    return "\n".join(lines)[:1600]


def solve_challenge(
    description: str,
    challenge_files: list[str] | None = None,
    target_url: str | None = None,
    verbose: bool = True,
    start_tier: str | None = None,
    hint_key: str | None = None,
    name: str | None = None,
    max_steps: int | None = None,
    ctf: str | None = None,
    workspace: str | None = None,
    mode: str = "jeopardy",
    slug: str | None = None,
) -> dict:
    """
    Autonomous CTF solver.

    Args:
        description:     Challenge description / prompt.
        challenge_files: Paths to any provided challenge files (already in workspace).
        target_url:      Target URL/IP if applicable.
        verbose:         Print step-by-step reasoning.
        start_tier:      Force the starting model tier (else routed by category).
                         Used by swarm mode to race different models.

    Returns:
        Dict with flag, steps taken, tier used, and full trace.
    """
    # Short human label for escalation/notification messages.
    # NOTE: use a dedicated var — the tool loop below rebinds a local `name`
    # (name = tc["name"]), which would otherwise clobber the challenge label
    # and mislabel every escalation message with the last tool's name.
    chal_name = (name or (description or "challenge").strip().splitlines()[0])[:48] or "challenge"
    import uuid
    _ctx.run_id = uuid.uuid4().hex[:8]
    step_cap = max_steps or MAX_STEPS
    set_solve_ctf(ctf)   # route this thread's _emit() to the CTF's channel too
    # Each executor thread gets its OWN workspace (thread-local) — never mutate the
    # global config.WORKDIR, which races across concurrent workers.
    from workspace import set_workdir
    set_workdir(workspace)

    def _persist_solve_source(solve_source: str):
        """Best-effort metadata persistence for board-backed challenges."""
        challenge_slug = slug or hint_key
        if not challenge_slug:
            return
        try:
            import scraper
            scraper.update_challenge(challenge_slug, {"solve_source": solve_source})
        except Exception as exc:
            print(f"  [scraper] solve_source persistence skipped ({exc})")

    # Authoritative recall precedes classification as well as the solve cascade:
    # a known solve must consume zero model calls, including classifier calls.
    recalled = _recall_first_hit(description, chal_name)
    if recalled:
        candidate, hit = recalled
        evidence = {
            "status": "ok",
            "content": hit.get("content") or "",
            "relevance": hit.get("relevance"),
            "confidence": (hit.get("meta") or {}).get("confidence"),
        }
        trace = [{"step": 0, "tier": "recall", "type": "tool",
                  "tool": "cortex_recall", "args": {"challenge": chal_name},
                  "result": evidence}]
        submission = execute_tool("submit_flag", {"flag": candidate})
        trace.append({"step": 0, "tier": "recall", "type": "tool",
                      "tool": "submit_flag", "args": {"flag": candidate},
                      "result": submission})
        verdict = FlagJudge().judge(candidate, trace, description=description)
        if submission.get("status") == "captured" and verdict["approved"]:
            solve_source = "recall"
            _emit("🧠 recall-first: submitted known flag")
            _persist_solve_source(solve_source)
            try:
                import archivist
                archivist.archive({
                    "challenge": chal_name, "category": "unknown", "flag": candidate,
                    "tier": "recall", "steps": 0, "trace": trace, "ctf": ctf,
                    "solve_source": solve_source,
                })
            except Exception as _e:
                print(f"  [archivist] skipped: {_e}")
            from workspace import clear_workdir
            clear_workdir()
            return {
                "flag": candidate,
                "category": "unknown",
                "steps": 0,
                "final_tier": "recall",
                "solve_source": solve_source,
                "termination_reason": "solved",
                "trace": trace,
                "judge_verdict": verdict,
            }
        print(f"  [cortex] recall-first candidate rejected: {candidate}")

    # No authoritative recall: classify and enter the normal tier cascade.
    category = classify_challenge(description)
    _active_category[0] = category                    # for the claude escalation cap
    if start_tier is None or start_tier not in ESCALATION:
        start_tier = CATEGORY_ROUTES[category]
    # honor the claude cap even when a caller asks to START on it (e.g. solve_with_recovery)
    if start_tier == "claude" and not _claude_allowed():
        start_tier = "local"
    tier_idx = ESCALATION.index(start_tier)
    if start_tier == "claude":
        _record_claude_call()
    current_tier = start_tier

    # Free-tier grind: when NO paid tier (claude/gpt/…) is reachable+usable from here
    # (local-only mode, or claude capped-out / not eligible for this category), the run
    # costs nothing — so don't let the step ceiling be what quits it. Raise the cap and
    # lean on the LOOP DETECTOR + TIER_TIMEOUT to stop only genuine rabbit holes. Runs
    # that CAN reach claude keep the low MAX_STEPS cap (cost stays bounded).
    if not max_steps:
        _free = {"fast", "local", "vision"}
        _paid_usable = any(t not in _free and _tier_usable(t) for t in ESCALATION[tier_idx:])
        if not _paid_usable and LOCAL_MAX_STEPS > step_cap:
            step_cap = LOCAL_MAX_STEPS
            if verbose:
                print(f"  [budget] free-tier run — step cap raised to {step_cap} "
                      f"(loop detector + {TIER_TIMEOUT}s timeout are the real stops)")

    if verbose:
        print(f"\n{'='*60}")
        print(f"  Category: {category} | Starting tier: {current_tier}")
        print(f"{'='*60}\n")

    # Build initial context
    context_parts = [f"CHALLENGE: {description}"]
    mode = mode if mode in ("jeopardy", "redteam") else "jeopardy"
    context_parts.append(f"MODE: {mode}")
    if mode == "jeopardy":
        context_parts.append(
            "JEOPARDY RULES: prioritize the provided artifact/target, extract a "
            "proven flag, pivot quickly after irrelevant output, and do not assume persistence."
        )
    else:
        context_parts.append(
            "RED TEAM RULES: maintain operation state, track access and pivots, and "
            "justify repeated actions as progress toward the objective."
        )
    if target_url:
        context_parts.append(f"TARGET: {target_url}")
    if challenge_files:
        context_parts.append(f"FILES: {', '.join(challenge_files)}")
    try:
        import cortex
        prior_failures = cortex.recall_failures(name or description)
        if prior_failures:
            context_parts.append(
                "ALREADY TRIED AND FAILED on this challenge: "
                + "; ".join(prior_failures)
                + ". Do NOT repeat these approaches — try a different angle."
            )
    except Exception as exc:
        print(f"  [cortex] failure recall skipped ({exc})")
    skill_text = _load_ctf_skill(category)
    if skill_text:
        context_parts.append("LOCAL CTF METHODOLOGY (follow its phases and pivot rules):\n" + skill_text)
    redteam_skill_text = _load_redteam_skills(description, category)
    if redteam_skill_text:
        context_parts.append("LOCAL OFFENSIVE SKILLS (apply the relevant techniques):\n" + redteam_skill_text)
    initial_context = "\n".join(context_parts)

    # Reload prompts so live Overwatch patches take effect without a restart.
    try:
        importlib.reload(prompts)
    except Exception:
        pass
    system_prompt = prompts.get_system_prompt(category)

    # Inject prior experience from long-term memory (best-effort). Logged
    # unconditionally so we can SEE cortex actually being consulted per solve.
    cortex_experience_injected = False
    try:
        import cortex
        experience = cortex.build_experience_block(description, category)
        if experience:
            system_prompt += "\n\n" + experience
            cortex_experience_injected = True
            _emit(f"🧠 {chal_name}: cortex injected {experience.count(chr(10))} memory line(s)")
        else:
            print(f"  [cortex] no relevant memory for: {chal_name}")
    except Exception as e:
        print(f"  [cortex] skipped ({e})")

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": initial_context},
    ]

    import hints as _hints
    if hint_key:
        _hints.register_active(hint_key, f"{category}: {description[:40]}")

    judge = FlagJudge()
    detector = BullshitDetector(threshold=0.85)   # loosened: only strong/real loops trip
    trace = []
    flag = None
    tier_time: dict = {}   # cumulative wall-clock seconds per tier
    no_tool_nudges = 0
    force_next_action = False   # set when a response had no tool call → next call forces one
    last_step = 0          # actual steps run (result reports THIS, not MAX_STEPS)
    codex_patch_attempted = False

    def _solve_brief() -> str:
        """Small, structured state packet refreshed after each tool action."""
        tools = [t for t in trace if t.get("type") == "tool"]
        actions = []
        errors = []
        for t in tools[-8:]:
            tool = t.get("tool", "?")
            result = t.get("result", {}) or {}
            status = result.get("status", "")
            actions.append(f"{tool}:{status}")
            if status not in ("ok", "success", ""):
                errors.append(f"{tool}: {str(result.get('stderr') or result.get('error') or status)[:120]}")
        return ("SOLVE BRIEF\n"
                f"Phase: {'extract/submit' if any(t.get('tool') == 'submit_flag' for t in tools) else 'investigate'}\n"
                f"Steps used: {last_step}/{step_cap}; tier: {current_tier}; mode: {mode}\n"
                f"Recent actions: {', '.join(actions) or 'none'}\n"
                f"Errors requiring correction: {' | '.join(errors) or 'none'}\n"
                "Next action must be a new, evidence-driven tool call.")

    messages.append({"role": "user", "content": _solve_brief()})

    for step in range(1, step_cap + 1):
        last_step = step
        if current_tier is None:   # tiers exhausted by a prior escalation
            break

        # Drain any live operator hints dropped from Discord (!hint).
        for _h in _hints.drain_hints(hint_key):
            messages.append({
                "role": "user",
                "content": f"OPERATOR HINT (from your operator, mid-solve): {_h}\nFactor this in now.",
            })
            if verbose:
                print(f"  [hint] injected: {_h[:80]}")

        if verbose:
            print(f"── Step {step}/{step_cap} [{current_tier}] ──")

        # Call model (timed; _chat_completion applies a hard STEP_TIMEOUT).
        _t0 = time.time()
        # Local Qwen tiers sometimes emit a plan/prose without entering the tool
        # loop (finish_reason=tool_calls only when tool_choice=required). We force
        # a tool call (a) on the very first fast turn, and (b) whenever the previous
        # response idled — proven to convert idle→action even under the full prompt.
        require_action = force_next_action or (
            current_tier == "fast"
            and not any(t.get("type") == "tool" for t in trace)
            and no_tool_nudges == 0
        )
        force_next_action = False   # consume; re-armed below only if this call idles
        call_messages = _compact_for_tier(messages, current_tier)
        resp = _chat_completion(
            current_tier, call_messages, tools=TOOL_SCHEMAS,
            force_tool=require_action,
        )
        _dur = time.time() - _t0
        tier_time[current_tier] = tier_time.get(current_tier, 0.0) + _dur

        # ── Per-call timeout: kill + escalate immediately ────────────
        _err = str(resp.get("error", "")).lower()
        if _dur >= STEP_TIMEOUT or ("timeout" in _err or "timed out" in _err):
            detector.observe_timeout()
            model = TIERS.get(current_tier, {}).get("model", current_tier)
            tier_idx, current_tier = _escalate(
                tier_idx, current_tier, verbose, name=chal_name, step=step,
                reason=f"timeout — {model[:20]} took {_dur:.0f}s on one step",
                score=detector.score())
            if current_tier is None:
                break
            detector.reset()
            messages.append({
                "role": "user",
                "content": ("ESCALATION: Previous model timed out after 5 minutes on a single "
                            "reasoning step. You are a faster model. Solve this efficiently."),
            })
            continue

        if "error" in resp:
            print(f"  [!] API error: {resp['error']}")
            # Escalate on API failure
            tier_idx, current_tier = _escalate(
                tier_idx, current_tier, verbose, name=chal_name, step=step,
                reason=f"API error — {str(resp['error'])[:60]}",
                score=detector.score())
            if current_tier is None:
                break
            continue

        # Print reasoning
        if resp["content"] and verbose:
            thinking = resp["content"][:500]
            print(f"  Think: {thinking}{'...' if len(resp['content']) > 500 else ''}")

        # Append assistant message
        messages.append({"role": "assistant", "content": resp["content"]})

        # Feed the model's reasoning to the bullshit detector
        if resp["content"]:
            detector.observe_thinking(resp["content"])

        # No tool calls → model idled (planned/prosed instead of acting). Force a
        # tool call on the retry (tool_choice=required) rather than politely asking;
        # a genuinely stuck model then loops on one call and the detector kills it.
        if not resp["tool_calls"]:
            trace.append({"step": step, "tier": current_tier, "type": "think", "content": resp["content"]})
            if current_tier in ("fast", "local") and no_tool_nudges < 2:
                no_tool_nudges += 1
                force_next_action = True
                messages.append({
                    "role": "user",
                    "content": (
                        "ACTION REQUIRED: execute the next reconnaissance step now. "
                        "Your next response must be a tool call, not a plan or explanation."
                    ),
                })
                _emit(f"⚠️ {chal_name}: {current_tier} returned no tool call; forcing a tool call (nudge {no_tool_nudges})")
                continue
            # Check if it's trying to give up
            if step > 3:
                tier_idx, current_tier = _escalate(
                    tier_idx, current_tier, verbose, name=chal_name, step=step,
                    reason="model idle — reasoning but calling no tools",
                    score=detector.score())
                if current_tier is None:
                    break
            continue

        # Execute tool calls — a productive step clears the idle streak so the
        # force-a-tool budget applies per consecutive-idle run, not per challenge.
        no_tool_nudges = 0
        for tc in resp["tool_calls"]:
            name = tc["name"]
            args = tc["arguments"]
            action_sig = f"{name}:{json.dumps(args, sort_keys=True)[:200]}"

            if verbose:
                print(f"  Tool: {name}({_truncate_args(args)})")

            # Execute
            tool_result = execute_tool(name, args)
            detector.observe_action(name, args, tool_result)

            if verbose:
                preview = json.dumps(tool_result, indent=2)[:300]
                print(f"  Result: {preview}")

            trace.append({
                "step": step,
                "tier": current_tier,
                "type": "tool",
                "tool": name,
                "args": args,
                "result": tool_result,
            })

            # Check for flag capture — run through judge first
            if name == "submit_flag" and tool_result.get("status") == "captured":
                candidate = tool_result["flag"]
                # Cross-run dedup guard: consult the SAME persistent ledger auto_submit
                # uses (solved set + rejected-flag receipts). Stops the model from
                # re-proposing a flag the platform already rejected (or grinding a
                # challenge already scored) — which wasted judge calls, steps, and
                # produced the duplicate/failed resubmissions.
                _eff_slug = slug or hint_key
                if ctf and _eff_slug:
                    try:
                        import ctfd as _ctfd
                        _blk, _canned = _ctfd.already_submitted(ctf, _eff_slug, candidate)
                    except Exception:
                        _blk, _canned = False, None
                    if _blk:
                        _canned = _canned or {}
                        trace.append({"type": "tool", "tool": "submit_flag",
                                      "args": {"flag": candidate}, "result": _canned})
                        if _canned.get("status") == "already_solved":
                            from workspace import clear_workdir
                            clear_workdir()
                            return {"flag": None, "category": category, "steps": step,
                                    "final_tier": current_tier, "solve_source": None,
                                    "termination_reason": "already_solved", "trace": trace}
                        messages.append({"role": "user", "content": (
                            f"FLAG ALREADY TRIED — do NOT propose '{candidate}' again. "
                            f"{_canned.get('message', 'previously submitted for this challenge')}. "
                            "Find a different flag from new evidence, or pivot.")})
                        continue
                flag_attempts = sum(1 for t in trace if t.get("tool") == "submit_flag")
                if flag_attempts > 3:
                    messages.append({"role": "user", "content": (
                        "FLAG ATTEMPT LIMIT REACHED: three candidate flags were rejected. "
                        "Stop submitting guesses and return to evidence gathering or pivot."
                    )})
                    continue

                # Judge validates: format, provenance, and a Claude cross-check
                # (the real quality gate). Never judge with the solver's own tier.
                judge_tier = _pick_judge_tier(current_tier)

                def _judge_complete(system, user, _jt=judge_tier, _solver=current_tier):
                    # Try the picked judge; if it errors/empties (gpt-oss busy or
                    # down), fall back across the rest of the supervisor pool so the
                    # quality gate never silently degrades to provenance-only.
                    from config import SUPERVISOR_TIERS
                    order = [_jt] + [t for t in SUPERVISOR_TIERS
                                     if t != _jt and t != _solver and t in TIERS]
                    for t in order:
                        r = _chat_completion(t, [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ])
                        out = "" if r.get("error") else _strip_reasoning(r.get("content") or "")
                        if out.strip():
                            return out
                    return ""

                verdict = judge.judge(candidate, trace, complete_fn=_judge_complete,
                                      description=description)

                if verbose:
                    print(f"\n  [JUDGE] Flag: {candidate}")
                    print(f"  [JUDGE] Format:     {verdict['checks']['format']['reason']}")
                    print(f"  [JUDGE] Provenance: {verdict['checks']['provenance']['reason']}")
                    print(f"  [JUDGE] LLM review: {verdict['checks']['llm_review'].get('reason', 'skipped')}")
                    print(f"  [JUDGE] Verdict:    {'✓ APPROVED' if verdict['approved'] else '✗ REJECTED'}")

                if verdict["approved"]:
                    flag = candidate
                    solve_source = ("seeded" if cortex_experience_injected
                                    else "autonomous")
                    if verbose:
                        print(f"\n  [*] FLAG CAPTURED: {flag}\n")
                    if hint_key:
                        _hints.unregister_active(hint_key)
                    # Archivist: capture the solve as training data (canonical format
                    # summary + raw trace). Runs on judge-approval, before return.
                    # NOTE: this is training-data collection (source='archivist');
                    # verified-only recall ingestion still happens in the bot on CTFd OK.
                    try:
                        import archivist
                        archivist.archive({
                            "challenge": chal_name, "category": category, "flag": flag,
                            "tier": current_tier, "steps": step, "trace": trace, "ctf": ctf,
                            "solve_source": solve_source,
                        })
                    except Exception as _e:
                        print(f"  [archivist] skipped: {_e}")
                    from workspace import clear_workdir
                    _persist_solve_source(solve_source)
                    clear_workdir()
                    return {
                        "flag": flag,
                        "category": category,
                        "steps": step,
                        "final_tier": current_tier,
                        "solve_source": solve_source,
                        "termination_reason": "solved",
                        "trace": trace,
                        "judge_verdict": verdict,
                    }
                else:
                    # Rejected — tell the agent to keep looking
                    if verbose:
                        print(f"  [!] Flag rejected — agent continues")
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The flag '{candidate}' was REJECTED by validation. "
                            f"Reason: {verdict['checks']['provenance']['reason']}. "
                            "The flag must appear in actual tool output. "
                            "Do NOT guess or construct flags. "
                            "Re-examine your tool outputs and extract the real flag."
                        ),
                    })
                    continue

            # Feed back a COMPACT, structured view — not the raw dump. Flags surfaced
            # first, noisy tools distilled to records, full output externalized to disk
            # (read_file) so the model holds a working view, not the whole engagement.
            # The full raw result still lives in `trace` (judge provenance uses that).
            messages.append({
                "role": "user",
                "content": "Tool result:\n" + _normalize_tool_output(name, args, tool_result, step),
            })
            messages.append({"role": "user", "content": _solve_brief()})

            # ── Bullshit detector escalation ─────────────────
            from config import DETECTOR_ENABLED
            should_go, reason = detector.should_escalate() if DETECTOR_ENABLED else (False, "")
            # Give the initial solver a minimum evidence window. A single burst
            # of repeated shell actions at steps 1-4 is not enough to justify a
            # tier handoff; preserve the trace and force a pivot instead.
            if should_go and step < 5:
                should_go = False
                messages.append({
                    "role": "user",
                    "content": (
                        f"LOOP WARNING (step {step}/5 minimum): {reason}. Do not repeat shell. "
                        "Change tools or inspect a new artifact now; escalation is held until step 5."
                    ),
                })
                _emit(f"⚠️ {chal_name}: detector held until step 5 ({reason})")
            if should_go:
                # First detector trip gets one bounded Codex repair opportunity
                # before handing the challenge to the next solver tier.
                if step >= 5 and not codex_patch_attempted:
                    codex_patch_attempted = True
                    try:
                        import monitor as _monitor
                        failure = {
                            "challenge": description[:400], "category": category,
                            "steps": step, "diagnosis": {"looped": True, "reason": reason},
                            "errors": [], "loops": [], "last_actions": trace[-5:],
                        }
                        ow = _monitor.Overwatch(analyst_tier="codex")
                        analysis = ow._call_analyst([failure])
                        if analysis:
                            ow._apply_patch(analysis, [failure])
                            importlib.reload(prompts)
                            detector.reset()
                            messages.append({
                                "role": "user",
                                "content": (
                                    "CODEX PATCH APPLIED: A targeted anti-loop repair was added to your "
                                    "instructions. Reassess the evidence and take a different tool action "
                                    "now. Do not repeat the shell pattern that triggered this repair."
                                ),
                            })
                            _emit(f"🛠️ {chal_name}: Codex patch applied; retrying before escalation")
                            continue
                        _emit(f"⚠️ {chal_name}: Codex produced no patch; escalating")
                    except Exception as _patch_error:
                        _emit(f"⚠️ {chal_name}: Codex patch hook failed ({str(_patch_error)[:100]})")
                if verbose:
                    print(f"  [!] BULLSHIT DETECTED: {reason}")
                    print(f"  [!] Score: {detector.score():.2f} — escalating")
                tier_idx, current_tier = _escalate(
                    tier_idx, current_tier, verbose, name=chal_name, step=step,
                    reason=f"detector tripped — {reason}", score=detector.score())
                if current_tier is None:
                    break
                detector.reset()  # clean slate for new model
                if current_tier == "claude":
                    # Clean-context half of the cascade-Claude fix: hand Claude a CONCISE
                    # digest of what the weak tiers tried — not the raw failed transcript —
                    # and frame it as a fresh solve so it isn't anchored to their dead ends
                    # (which made it idle/repeat instead of solving).
                    messages.append({"role": "user", "content": (
                        "ESCALATION TO CLAUDE — treat this as a FRESH solve. The weaker local "
                        f"models failed ({reason}); do NOT continue their line of attack.\n\n"
                        f"{_solve_brief()}\n\n"
                        "Re-read the original challenge brief at the top, form your own plan "
                        "from scratch, and take a decisive first tool action now.")})
                else:
                    messages.append({
                        "role": "user",
                        "content": (
                            f"ESCALATION: Previous model was failing ({reason}). "
                            f"You are a more powerful model. Review everything above "
                            f"and try a COMPLETELY different approach. "
                            f"Do not repeat what was already tried."
                        ),
                    })

        # ── Cumulative tier timeout: too long on one tier, no flag ───
        if tier_time.get(current_tier, 0.0) >= TIER_TIMEOUT and not flag:
            model = TIERS.get(current_tier, {}).get("model", current_tier)
            detector.observe_timeout()
            tier_idx, current_tier = _escalate(
                tier_idx, current_tier, verbose, name=chal_name, step=step,
                reason=f"tier timeout — {model[:20]} used {tier_time.get(current_tier, 0):.0f}s, no flag",
                score=detector.score())
            if current_tier is None:
                break
            detector.reset()
            messages.append({
                "role": "user",
                "content": (f"ESCALATION: {TIER_TIMEOUT // 60} minutes elapsed on the previous tier "
                            "with no flag. You are a more capable model — try a different approach."),
            })
            continue

        # Auto-escalate after N steps at same tier — but ONLY if a stronger tier
        # actually exists. The step-count heuristic means "give the next tier a turn";
        # on the LAST usable tier there is no next tier, so escalating there just
        # killed it (claude EXHAUSTED at 16 steps, detector 0.00, mid-work). Let the
        # final tier keep working to step_cap; only a real signal (loop/timeout) stops it.
        if step % ESCALATE_AFTER == 0 and not flag:
            if _next_usable_tier_idx(tier_idx) is None:
                if verbose:
                    print(f"  [!] {ESCALATE_AFTER} steps at final tier "
                          f"({current_tier}) — NOT evicting; it keeps working")
            else:
                if verbose:
                    print(f"  [!] {ESCALATE_AFTER} steps without flag — escalating")
                tier_idx, current_tier = _escalate(
                    tier_idx, current_tier, verbose, name=chal_name, step=step,
                    reason=f"{ESCALATE_AFTER} steps at this tier, no flag yet",
                    score=detector.score())
                if current_tier is None:
                    break

    # Why did this run stop? Derived from final state (LIVE loop doesn't thread a
    # reason through every branch — the end state is unambiguous enough).
    if flag:
        termination_reason = "solved"
    elif current_tier is None:
        termination_reason = "tiers_exhausted"
    elif not any(t.get("type") == "tool" for t in trace):
        termination_reason = "no_tool_calls"
    elif last_step >= step_cap:
        termination_reason = "max_steps"
    else:
        termination_reason = "ended_no_flag"

    result = {
        "flag": flag,
        "solve_source": None,
        "category": category,
        "steps": last_step,                       # ACTUAL steps run, not MAX_STEPS
        "final_tier": current_tier or "exhausted",
        "termination_reason": termination_reason,
        "trace": trace,
    }
    # Attach failure diagnosis so Discord/recovery can show WHY it failed.
    result.update(_failure_summary(trace, detector))

    if hint_key:
        _hints.unregister_active(hint_key)

    if not flag:
        log_failure(description, category, trace, result["final_tier"],
                    result["steps"], termination_reason=termination_reason)

    from workspace import clear_workdir
    clear_workdir()   # don't leak this thread's workspace to a later reused thread
    return result


def _failure_summary(trace: list, detector) -> dict:
    """Compact, Discord-ready diagnosis of a run: which patterns tripped, the last
    few tool calls, the last error, and the detector's final score."""
    import fails as _f
    diag = _f._diagnose(trace)
    patterns = [k for k, v in diag.items() if v]                 # e.g. ["looped","timeout"]
    acts = []
    tool_entries = [t for t in trace if t.get("type") == "tool"]
    for t in tool_entries[-3:]:
        a = t.get("args", {}) or {}
        arg = a.get("command") or a.get("url") or a.get("flag") or a.get("code") or ""
        if not arg and a:
            arg = str(next(iter(a.values())))
        acts.append(f"{t.get('tool')}({str(arg)[:40]})")
    errs = _f._extract_errors(trace)
    last_error = errs[-1]["error"][:160] if errs else ""
    try:
        score = float(detector.score())
    except Exception:
        score = None
    return {
        "diagnosis": patterns,
        "last_actions": acts,
        "last_error": last_error,
        "detector_score": score,
    }


def _trace_for_analysis(trace: list, limit: int = 20) -> str:
    """Flatten the last `limit` trace entries into text for Claude to analyze."""
    lines = []
    for t in trace:
        if t.get("type") == "tool":
            a = t.get("args", {}) or {}
            arg = a.get("command") or a.get("url") or a.get("code") or a.get("flag") or a
            res = t.get("result", {}) or {}
            out = (res.get("stdout") or res.get("content") or res.get("body")
                   or res.get("stderr") or res.get("error") or res)
            lines.append(f"[step {t.get('step')} {t.get('tier')}] {t.get('tool')}("
                         f"{str(arg)[:120]}) -> {str(out)[:220]}")
        elif t.get("type") == "think":
            lines.append(f"[step {t.get('step')} {t.get('tier')}] (reasoned, no tool) "
                         f"{str(t.get('content',''))[:160]}")
    return "\n".join(lines[-limit:])


def _claude_analyze_failure(description: str, trace: list) -> str:
    """Ask a SUPERVISOR (Claude / Antigravity / codex, rotated) to diagnose a
    failed run and produce a concrete fix-plan for the retry."""
    prompt = (
        "This CTF challenge failed after exhausting the automated attempt. Here is the "
        "full trace of what was attempted. Analyze what went wrong, identify the correct "
        "approach, and produce a step-by-step plan to solve it. Be specific — exact "
        "commands, exact tools. Keep it under 12 concise steps.\n\n"
        f"CHALLENGE:\n{(description or '')[:1200]}\n\n"
        f"ATTEMPT TRACE:\n{_trace_for_analysis(trace)[:6000]}"
    )
    sup = _pick_supervisor()
    resp = _chat_completion(sup, [
        {"role": "system", "content": "You are an elite CTF operator doing post-mortem failure analysis."},
        {"role": "user", "content": prompt},
    ])
    if resp.get("error"):
        return f"(analysis unavailable from {sup}: {str(resp['error'])[:100]})"
    return _strip_reasoning(resp.get("content", "")).strip()[:1800]


# ── Canonical Screwhead solve format (ONE template for Cortex + writeups) ──
SOLVE_WRITEUP_PROMPT = """You write CTF solve writeups in a STRICT fixed format. Base it ONLY on the
actual solve trace — never invent steps. Output EXACTLY these sections, in this order, nothing else:

FLAG: <the exact flag>
CATEGORY: <category>
APPROACH: <2-4 sentences: the method used and why it works>
STEPS:
1. <concrete step with the exact command / tool / payload used>
2. <next step>
KEY INSIGHT: <the single thing that cracked it>

No markdown headers, no preamble, no fluff. Be specific and factual."""


def build_writeup(name: str, category: str, points, flag: str,
                  description: str, trace: list) -> str:
    """Generate the canonical Screwhead solve writeup (used for BOTH the Cortex
    memory entry and !writeup — single source of truth)."""
    user = (f"CHALLENGE: {name} [{category}] {points}pts\n{(description or '')[:700]}\n\n"
            f"PROPOSED FLAG: {flag}\n\nSOLVE TRACE:\n{_trace_for_analysis(trace)[:5500]}")
    sup = _pick_supervisor()
    r = _chat_completion(sup, [
        {"role": "system", "content": SOLVE_WRITEUP_PROMPT},
        {"role": "user", "content": user},
    ])
    body = "" if r.get("error") else _strip_reasoning(r.get("content", "")).strip()
    if not body:
        body = f"FLAG: {flag}\nCATEGORY: {category}\nAPPROACH: (writeup generation unavailable)"
    return f"SCREWHEAD SOLVE — {name} [{category}] {points}pts\n{body}"[:2600]


def solve_with_recovery(description: str, challenge_files=None, target_url=None,
                        hint_key=None, name: str | None = None, ctf: str | None = None,
                        workspace: str | None = None, mode: str = "jeopardy") -> dict:
    """Solve, and if it fails, run ONE Claude-guided recovery retry, then park.

    Attempt 1 = normal cascade. On failure: Claude analyzes the trace and writes a
    plan, then Attempt 2 runs on the FAST tier seeded with that plan (max 15 steps).
    Never more than two attempts total. Emits live progress to Discord via _emit."""
    label = name or (description or "challenge").strip().splitlines()[0][:48]

    r1 = solve_challenge(description, challenge_files, target_url,
                         verbose=False, hint_key=hint_key, name=label, ctf=ctf,
                         workspace=workspace, mode=mode)
    if r1.get("flag"):
        r1["recovered"] = False
        return r1

    # ── Attempt 1 failed — surface the diagnosis, then recover ──
    diag = ", ".join(r1.get("diagnosis") or []) or "no clear pattern"
    _emit(f"❌ {label} failed after {r1.get('steps','?')} steps — {diag}")
    _emit(f"🔄 Claude analyzing failure...")

    analysis = _claude_analyze_failure(description, r1.get("trace") or [])

    _emit("🔄 Retrying with Claude's plan...")
    seeded = (
        f"PREVIOUS ATTEMPT ANALYSIS (follow this plan instead of your default approach):\n"
        f"{analysis}\n\n"
        f"--- ORIGINAL CHALLENGE ---\n{description}"
    )
    # Retry on CLAUDE (the strong model that WROTE the plan) — not the weak tier
    # that already failed. Claude both plans AND executes its own fix.
    r2 = solve_challenge(seeded, challenge_files, target_url,
                         verbose=False, start_tier="claude", max_steps=20,
                         hint_key=hint_key, name=label, ctf=ctf,
                         workspace=workspace, mode=mode)

    if r2.get("flag"):
        r2["recovered"] = True
        r2["claude_analysis"] = analysis
        return r2

    # ── Failed twice — park it for human eyes ──
    r2 = r2 if isinstance(r2, dict) else r1
    r2["recovered"] = False
    r2["parked"] = True
    r2["claude_analysis"] = analysis
    # one-line summary for the Discord PARKED message
    first_line = next((ln.strip("-* \t") for ln in (analysis or "").splitlines()
                       if ln.strip()), "no analysis")
    r2["claude_summary"] = first_line[:160]
    return r2


_supervisor_rr = [0]


def _pick_supervisor(current_tier: str = None) -> str:
    """Rotate across the SUPERVISOR pool (Claude / Antigravity / codex) to spread
    load off Claude Max, skipping the solver's own tier. These strong models judge
    flags and analyze failures while the local models solve."""
    from config import SUPERVISOR_TIERS
    pool = [t for t in SUPERVISOR_TIERS if t in TIERS and t != current_tier]
    if not pool:
        pool = [t for t in SUPERVISOR_TIERS if t in TIERS] or [JUDGE_TIER]
    tier = pool[_supervisor_rr[0] % len(pool)]
    _supervisor_rr[0] += 1
    return tier


def _pick_judge_tier(current_tier: str) -> str:
    """A supervisor model (never the solver's tier) validates the flag."""
    return _pick_supervisor(current_tier)


def _build_judge_client(judge_tier: str):
    """Return (openai_client, model) for the judge tier, or (None, None).

    Only OpenAI-compatible HTTP tiers get a client; Claude (Anthropic SDK) and
    Antigravity (sentinel base_url) return None, so the judge falls back to
    format + provenance checks without the LLM cross-check rather than crashing.
    """
    jt = TIERS.get(judge_tier, {})
    base = jt.get("base_url", "")
    if base.startswith("http") and "anthropic.com" not in base:
        client = openai.OpenAI(base_url=base, api_key=jt.get("api_key") or "not-needed")
        return client, jt["model"]
    return None, None


# ── Claude escalation cap (category-scoped + hourly rate limit) ────
_active_category = [None]                              # set per solve; read by the claude gate
_CLAUDE_CALLS = "/tmp/ctf-agent/ctfs/claude_calls.json"


def _claude_recent_calls() -> list:
    try:
        import os
        now = time.time()
        if os.path.exists(_CLAUDE_CALLS):
            return [t for t in json.load(open(_CLAUDE_CALLS)) if now - t < 3600]
    except Exception:
        pass
    return []


def _claude_allowed() -> bool:
    """Claude fires only for categories the local tiers can't do, and only N/hour."""
    try:
        from config import CLAUDE_CATEGORIES, CLAUDE_MAX_PER_HOUR
    except Exception:
        return True
    cat = (_active_category[0] or "").lower()
    if CLAUDE_CATEGORIES and cat not in CLAUDE_CATEGORIES:
        return False
    return len(_claude_recent_calls()) < CLAUDE_MAX_PER_HOUR


def _record_claude_call():
    try:
        import time
        calls = _claude_recent_calls()
        calls.append(time.time())
        json.dump(calls, open(_CLAUDE_CALLS, "w"))
    except Exception:
        pass


def _tier_usable(tier_name: str) -> bool:
    """Is this tier actually configured enough to try? Skips placeholder/keyless
    tiers (e.g. burst with the default RunPod URL, or a frontier tier missing its
    key) so escalation doesn't waste a hop on a guaranteed 404/401."""
    if tier_name == "claude" and not _claude_allowed():
        return False                                  # category-scoped + hourly-capped
    t = TIERS.get(tier_name, {})
    if t.get("provider") in ("codex", "antigravity"):
        return True                                   # non-HTTP; validated at call time
    base = (t.get("base_url") or "").lower()
    if not base:
        return False
    if any(ph in base for ph in ("your-runpod-id", "x.x.x", "y.y.y", "your-", "example.com")):
        return False                                  # placeholder URL — not deployed
    if ("openai.com" in base or "generativelanguage" in base) and not t.get("api_key"):
        return False                                  # frontier HTTP tier with no key
    return True


def _next_usable_tier_idx(tier_idx: int) -> int | None:
    """Index of the next USABLE tier above tier_idx, or None if this is the last one.
    Lets callers tell 'a stronger tier exists' from 'this is the final tier' — so the
    step-count escalation heuristic never evicts the last tier (which made Claude die
    at 16 steps with a clean detector, mid-work)."""
    idx = tier_idx
    while idx < len(ESCALATION) - 1:
        idx += 1
        if _tier_usable(ESCALATION[idx]):
            return idx
    return None


def _escalate(tier_idx: int, current_tier: str, verbose: bool,
              name: str = "challenge", step: int = 0,
              reason: str = "", score=None) -> tuple[int, str | None]:
    """Move to the next USABLE tier. Returns (new_idx, new_tier) or (idx, None).

    Single source of truth for escalation logging: prints a debug line to stdout
    (visible in the Kali terminal / journalctl) AND emits a Discord message so the
    operator can watch the cascade live. Every call site routes through here.
    Unconfigured tiers (placeholder URL / missing key) are skipped silently."""
    score_s = f"{score:.2f}" if isinstance(score, (int, float)) else "n/a"
    # Advance to the next tier that's actually usable.
    skipped = []
    idx = tier_idx
    while idx < len(ESCALATION) - 1:
        idx += 1
        if _tier_usable(ESCALATION[idx]):
            new_tier = ESCALATION[idx]
            if new_tier == "claude":
                _record_claude_call()                 # count it against the hourly cap
            note = f" (skipped {', '.join(skipped)})" if skipped else ""
            print(f"[_escalate] step={step} {current_tier} -> {new_tier}{note} | "
                  f"reason={reason or 'n/a'} | detector={score_s}", flush=True)
            _emit(f"⬆️ ESCALATING: {name} — {reason or 'no reason given'}\n"
                  f"{current_tier} → {new_tier}{note}\n"
                  f"Step {step}, detector score {score_s}")
            return idx, new_tier
        skipped.append(ESCALATION[idx])
    # No usable tier left to climb to.
    print(f"[_escalate] step={step} {current_tier} -> EXHAUSTED | "
          f"reason={reason or 'n/a'} | detector={score_s}", flush=True)
    _emit(f"⛔ EXHAUSTED: {name} — no tiers left after {current_tier} "
          f"(reason: {reason or 'n/a'}, step {step}, detector {score_s})")
    return tier_idx, None


def _truncate_args(args: dict, max_len: int = 80) -> str:
    """Short preview of tool arguments for logging."""
    parts = []
    for k, v in args.items():
        sv = str(v)
        if len(sv) > max_len:
            sv = sv[:max_len] + "..."
        parts.append(f"{k}={sv}")
    return ", ".join(parts)
