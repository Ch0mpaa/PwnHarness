"""
Screwhead — Flag judge.
Validates flags before submission to catch hallucinations and bad extractions.
Runs on a DIFFERENT model than the solver to avoid the same blind spots.

Checks:
  1. Format — does it match the expected flag pattern?
  2. Provenance — was this actually in tool output or did the model make it up?
  3. LLM cross-check — second opinion from a different model
"""

import re
import json
from config import TIERS

# ── Flag format patterns ─────────────────────────────────────────
# Add the CTF's actual flag format before the event.
# Most CTFs use one of these.

FLAG_PATTERNS = [
    r"flag\{[^\}]+\}",
    r"FLAG\{[^\}]+\}",
    r"CTF\{[^\}]+\}",
    r"ctf\{[^\}]+\}",
    r"picoCTF\{[^\}]+\}",
    r"HTB\{[^\}]+\}",
    r"MetaCTF\{[^\}]+\}",
    r"DEFCON\{[^\}]+\}",
    r"dc281\{[^\}]+\}",
]

# You can set this at runtime per-CTF
REQUIRED_FORMAT = None  # e.g. r"MetaCTF\{[^\}]+\}" — set before deploying


JUDGE_PROMPT = """You are a strict CTF flag validator. Decide whether a proposed flag is the ACTUAL correct answer to THIS specific challenge — not merely plausible.

You receive: the challenge description, the proposed flag, and the solver's recent tool outputs.

Be skeptical. REJECT (verdict "hallucinated" or "suspect") if ANY of these are true:
- The flag is a generic word/command/URL lifted from the prose (e.g. "whoami", "www.youtube.com", "site:", "GNU/Linux", "account") rather than a real answer to the question asked.
- The challenge poses a specific QUESTION (e.g. "what version did he say?", "what is the password?") and the flag is not a direct, specific answer supported by the tool outputs.
- The flag was invented/guessed from the challenge name or description without evidence in the tool outputs that it's correct.
- It "decoded" something but no tool output actually shows that result.

Accept (verdict "valid") ONLY if the flag is clearly the correct, specific answer — either it appears in tool output as the real result, OR the description explicitly instructs to submit that exact phrase (a gate), OR it directly and verifiably answers the challenge's question.

When unsure, prefer "suspect" over "valid". A wrong submission wastes a real attempt.

Respond with ONLY a JSON object:
{
  "verdict": "valid" or "hallucinated" or "suspect",
  "reason": "one sentence explaining why",
  "found_in": "which tool output supports it, or null"
}
"""


class FlagJudge:
    """Validates flags before they get submitted."""

    def __init__(self, flag_format: str | None = None):
        self.flag_format = flag_format or REQUIRED_FORMAT
        self.verdicts = []  # log of all judgments

    def judge(self, flag: str, trace: list, complete_fn=None,
              description: str = "") -> dict:
        """
        Full validation pipeline. `complete_fn(system, user) -> str` is the judge
        LLM (Claude) — decoupled from any specific SDK so the OAuth Claude tier works.
        Returns: {"approved": bool, "checks": {...}, "flag": str}
        """
        checks = {}

        # Check 1: Format
        checks["format"] = self._check_format(flag)

        # Check 2: Provenance — is the flag in the trace (or the challenge text)?
        checks["provenance"] = self._check_provenance(flag, trace, description)

        # Check 3: LLM cross-check (Claude) — the real quality gate.
        if complete_fn:
            checks["llm_review"] = self._llm_review(flag, trace, complete_fn, description)
        else:
            checks["llm_review"] = {"verdict": "skipped", "reason": "no judge model configured"}

        # Decision logic
        approved = self._decide(checks)

        verdict = {
            "approved": approved,
            "flag": flag,
            "checks": checks,
        }
        self.verdicts.append(verdict)
        return verdict

    def _check_format(self, flag: str) -> dict:
        """Does the flag match expected CTF format?"""
        # Catalogs commonly describe free-form answers with a label rather than
        # a regex.  Do not accidentally treat those labels as required literal
        # flag values (for example, requiring the answer to equal "plaintext").
        format_name = (self.flag_format or "").strip().lower()
        if format_name in {"plaintext", "plain text", "plain", "freeform", "free-form"}:
            return {
                "passed": bool(isinstance(flag, str) and flag.strip()),
                "required": False,
                "reason": "Plaintext answers are allowed; format is advisory",
            }
        if format_name in {"unknown", "any", "unspecified"}:
            return {
                "passed": None,
                "required": False,
                "reason": "Flag format is unknown; format is advisory",
            }

        # If a specific format is required, check it
        if self.flag_format:
            match = bool(re.fullmatch(self.flag_format, flag))
            return {
                "passed": match,
                "required": True,
                "reason": f"{'Matches' if match else 'Does not match'} required format",
            }

        # Otherwise check against common patterns
        for pattern in FLAG_PATTERNS:
            if re.fullmatch(pattern, flag):
                return {
                    "passed": True,
                    "required": False,
                    "reason": f"Matches pattern: {pattern}",
                }

        # Event prefixes are open-ended (for example darknet{}, FLOCK{}, and
        # DC34_ASL{}), so any conventional WORD{value} shape is recognized.
        generic_pattern = r"[A-Za-z0-9_]{2,}\{[^{}]+\}"
        if re.fullmatch(generic_pattern, flag):
            return {
                "passed": True,
                "required": False,
                "reason": f"Matches generic CTF flag shape: {generic_pattern}",
            }

        # No match but could still be valid (some CTFs use weird formats)
        return {
            "passed": None,  # uncertain
            "required": False,
            "reason": "No known flag format matched — could still be valid",
        }

    def _check_provenance(self, flag: str, trace: list, description: str = "") -> dict:
        """Was this flag actually in any tool output — or stated in the challenge
        description itself (GATE challenges: 'Type NEXT', 'submit I Accept the
        Compact', etc. where the answer is a literal phrase from the prompt)?"""
        # GATE case: the answer must appear in an EXPLICIT instruction context
        # ("Type X", "submit X", "the flag is X") — NOT merely somewhere in the
        # description. Otherwise the agent guesses any word from the prose (a URL,
        # a command like `whoami`, "site:") and it wrongly passes.
        if description and isinstance(flag, str) and flag.strip():
            fl = re.escape(flag.strip())
            gate_pat = re.compile(
                r'(?:type|submit|enter|answer(?:\s+is)?|the\s+flag\s+is|respond\s+with|'
                r'reply\s+with|password\s+is)\s*[:\-]?\s*[`"\']?' + fl,
                re.IGNORECASE)
            if gate_pat.search(description):
                return {
                    "passed": True,
                    "reason": "flag follows an explicit gate instruction in the description",
                    "source_tool": "description",
                    "source_step": 0,
                }

        tool_actions = [t for t in trace if t.get("type") == "tool" and t.get("tool") != "submit_flag"]
        # A tool may return the grounded secret without the platform wrapper
        # (for example crack_hash -> "sunshine", while the submitted value is
        # FLAG{sunshine}).  Accept the wrapper only when its inner core is also
        # present in tool evidence; never let an LLM verdict manufacture it.
        core = flag
        wrapped = re.fullmatch(r"[A-Za-z0-9_]{2,}\{([^{}]+)\}", str(flag or ""))
        if wrapped:
            core = wrapped.group(1)

        def _strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for child in value.values():
                    yield from _strings(child)
            elif isinstance(value, (list, tuple, set)):
                for child in value:
                    yield from _strings(child)

        for action in tool_actions:
            result = action.get("result", {})
            for value in _strings(result):
                if flag in value or (core and len(core) >= 4 and core in value):
                    return {
                        "passed": True,
                        "reason": f"Flag/core found in {action['tool']} output (step {action.get('step')})",
                        "source_tool": action["tool"],
                        "source_step": action.get("step"),
                    }

        return {
            "passed": False,
            "reason": "Flag string NOT found in any tool output — possible hallucination",
        }

    def _llm_review(self, flag: str, trace: list, complete_fn, description: str = "") -> dict:
        """Ask Claude (the judge) whether this flag is actually correct for THIS
        challenge — the real quality gate that stops guessed/garbage flags."""
        # Build a summary of recent tool outputs
        tool_outputs = []
        tool_actions = [t for t in trace if t.get("type") == "tool"][-10:]  # last 10
        for action in tool_actions:
            result = action.get("result", {})
            output = result.get("stdout", "") or result.get("content", "") or result.get("body", "")
            if output:
                tool_outputs.append(f"[{action['tool']} step {action.get('step')}]:\n{output[:1000]}")

        context = "\n\n".join(tool_outputs) if tool_outputs else "(no tool outputs in trace)"

        try:
            user = (f"CHALLENGE:\n{(description or '(none)')[:1500]}\n\n"
                    f"PROPOSED FLAG: {flag}\n\nTOOL OUTPUTS:\n{context}")
            raw = (complete_fn(JUDGE_PROMPT, user) or "").strip()
            # Reasoning models prepend <think>...</think>; drop it, then unwrap fences.
            raw = re.sub(r"^\s*<think>.*?</think>\s*", "", raw, flags=re.DOTALL | re.IGNORECASE)
            raw = raw.replace("```json", "").replace("```", "").strip()
            # Keep only the JSON object even if the model added prose around it.
            if "{" in raw and "}" in raw:
                raw = raw[raw.index("{"):raw.rindex("}") + 1]
            result = json.loads(raw)
            return {
                "passed": result.get("verdict") == "valid",
                "verdict": result.get("verdict"),
                "reason": result.get("reason", ""),
            }
        except Exception as e:
            return {"passed": None, "verdict": "error", "reason": str(e)}

    def _decide(self, checks: dict) -> bool:
        """Final approval — Claude (the LLM judge) is AUTHORITATIVE when it ran."""
        format_check = checks["format"]
        provenance = checks["provenance"]
        llm = checks["llm_review"]
        v = llm.get("verdict")

        # A challenge/platform-supplied format is a contract, not a scoring
        # signal.  Apply its veto before every decision path, including when
        # the LLM judge was skipped or errored.  Provenance of the inner value
        # must never authorize changing or dropping a known wrapper.
        if format_check.get("required", False) and format_check.get("passed") is not True:
            return False

        # Claude's veto: it saw the challenge + flag + evidence and rejected it.
        if v in ("hallucinated", "suspect"):
            return False
        # Claude vouched for it.  In particular, a plaintext/unknown-format
        # answer with supporting evidence must not be rejected merely because
        # it lacks a conventional flag{...} wrapper.  Format is only a hard
        # constraint when the challenge supplied an actual required regex.
        if v == "valid":
            # A judge model cannot manufacture provenance.  Even a positive
            # cross-check must be grounded in a tool result or explicit gate
            # instruction before anything reaches a submitter.
            if not provenance.get("passed"):
                return False
            return True

        # Claude didn't run (skipped/error) — fall back to provenance only.
        if not provenance["passed"]:
            return False
        if provenance["passed"]:
            return True

        # Uncertain — approve if at least two checks pass
        passes = sum(1 for c in checks.values() if c.get("passed") is True)
        return passes >= 2
