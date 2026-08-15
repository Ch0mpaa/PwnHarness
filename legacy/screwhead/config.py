"""
Screwhead — Endpoint & tool configuration.

ROUTING LOGIC:
  Each challenge gets classified into a category (web, crypto, rev, etc).
  CATEGORY_ROUTES picks the starting model for that category.
  If the model fails or loops, ESCALATION defines the upgrade path.

  Example: web challenge
    fast (GX10 coder) → local (GB10 Qwen 122B) → burst (RunPod) → claude → gpt → gemini

  All endpoints speak OpenAI-compatible API except Anthropic (own SDK / OAuth)
  and Antigravity (Google Unified Gateway). The agent handles all transparently.
"""

import os


# ── Load .env (next to this file) ────────────────────────────────
# Real environment variables always win; .env only fills in what's unset.
def _load_dotenv() -> None:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return
    try:
        from dotenv import load_dotenv  # honours quoting/expansion if installed
        load_dotenv(path, override=False)
        return
    except ImportError:
        pass
    for line in lines:  # minimal fallback parser
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_dotenv()

# ── All available models ─────────────────────────────────────────
# Every model you have, keyed by a short name.
# The agent picks from these based on category routing + escalation.

TIERS = {
    # ── Local GB10s (free, always on, Tailscale) ─────────────────
    "fast": {
        "base_url": os.getenv("FAST_URL", "http://100.x.x.x:8001/v1"),
        "api_key":  "not-needed",
        "model":    os.getenv("FAST_MODEL", "coder-opus-reasoning"),
        "desc":     "GX10 — fast code gen, exploits, scripts",
    },
    "local": {
        "base_url": os.getenv("LOCAL_URL", "http://100.y.y.y:8000/v1"),
        "api_key":  "not-needed",
        "model":    os.getenv("LOCAL_MODEL", "qwen3.5-122b"),
        "desc":     "GB10 — deep reasoning, hard challenges",
    },

    # ── RunPod (burst, pay per hour) ─────────────────────────────
    "burst": {
        "base_url": os.getenv("BURST_URL", "https://your-runpod-id.api.runpod.ai/v1"),
        "api_key":  os.getenv("BURST_KEY", ""),
        "model":    os.getenv("BURST_MODEL", "glm-5.2"),
        "desc":     "RunPod GLM 5.2 744B — heavy open-weight",
    },

    # ── Frontier APIs (pay per token / subscription) ─────────────
    "claude": {
        "base_url": "https://api.anthropic.com/v1",
        "api_key":  os.getenv("ANTHROPIC_API_KEY", ""),
        "model":    os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"),
        "desc":     "Claude Max — best reasoning + vision",
        # "oauth"   → Claude Max subscription token (~/.claude/.credentials.json),
        #             no ANTHROPIC_API_KEY needed. See claude_auth.py.
        # "api_key" → pay-per-use ANTHROPIC_API_KEY.
        "auth": os.getenv(
            "CLAUDE_AUTH",
            "oauth" if not os.getenv("ANTHROPIC_API_KEY") else "api_key",
        ),
    },
    "gpt": {
        "base_url": "https://api.openai.com/v1",
        "api_key":  os.getenv("OPENAI_API_KEY", ""),
        "model":    os.getenv("GPT_MODEL", "gpt-4o"),
        "desc":     "GPT — strong coding + tool use (needs OPENAI_API_KEY)",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key":  os.getenv("OPENROUTER_API_KEY", ""),
        "model":    os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4-pro"),
        "desc":     "OpenRouter — smart pay-per-token reserve (DeepSeek V4), no infra",
    },
    "codex": {
        # ChatGPT-subscription access via the Codex CLI (`codex exec`). No API key
        # or per-token billing — auth is your ChatGPT login. Delegated agent, not a
        # chat endpoint; handled by the provider branch in agent.py.
        "base_url": "codex-cli",          # sentinel; not an HTTP endpoint
        "api_key":  "",
        "model":    os.getenv("CODEX_MODEL", "gpt-5.6-sol"),
        "provider": "codex",
        "desc":     "Codex (ChatGPT sub) — autonomous OpenAI agent",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key":  os.getenv("GEMINI_API_KEY", ""),
        "model":    os.getenv("GEMINI_MODEL", "gemini-2.5-pro"),
        "desc":     "Gemini — long context + multimodal (AI Studio API key)",
    },
    # ── Local vision (Qwen2.5-VL on Ollama, gx10 :11434) ─────────
    "vision": {
        "base_url": os.getenv("VISION_URL", "http://100.98.154.43:11434/v1"),
        "api_key":  "not-needed",
        "model":    os.getenv("VISION_MODEL", "qwen2.5vl:7b"),
        "desc":     "Qwen2.5-VL 7B — local image analysis (Ollama)",
    },

    # ── Antigravity (Google Unified Gateway) — OPT-IN ────────────
    # Free Gemini 3.1 Pro + Claude 4.6 on the Google-OAuth subscription.
    # ⚠️ Proxying Antigravity violates Google ToS (ban risk). Deliberately
    # kept OUT of ESCALATION so it's only used when explicitly selected.
    # Handled by antigravity_auth.py via the provider branch in agent.py.
    "antigravity": {
        "base_url": "antigravity-oauth",   # sentinel; not an HTTP endpoint
        "api_key":  "",
        "model":    os.getenv("ANTIGRAVITY_MODEL", "gemini-3.1-pro-low"),
        "provider": "antigravity",
        "desc":     "Antigravity — free Gemini 3.1 Pro / Claude 4.6 (opt-in, ToS risk)",
    },
}

# ── Challenge category → starting model ─────────────────────────
# Which model takes FIRST crack at each category.
CATEGORY_ROUTES = {
    "web":       "fast",      # coder model iterates payloads quickly
    "crypto":    "fast",      # coder handles easy crypto in seconds; detector escalates hard ones to the 122B
    "forensics": "fast",      # mostly tool-driving — coder leads, escalates if stuck
    "rev":       "fast",      # coder model reads disassembly well
    "pwn":       "fast",      # coder writes pwntools scripts
    "misc":      "fast",      # try fast, escalate if weird
    "ai":        "fast",      # Qwen3.6-35B first (all-local; was claude)
    "unknown":   "fast",      # cheap fast first attempt, escalate on struggle
}

# ── Escalation order ────────────────────────────────────────────
# When a model fails or loops, move to the next one in this list.
# Left = cheapest/fastest, right = most powerful.
# NOTE: "antigravity" is intentionally NOT here (opt-in only, ToS risk).
ESCALATION = ["fast", "local", "claude"]   # 35B (gx10) → 122B redops (GB10) [free] → Claude Sonnet [flat-rate subscription]. OpenRouter/DeepSeek dropped from SOLVING (402s on full-size solve requests — out of per-request credit); re-add after topping up. Claude only fires after both local tiers fail, so easy challenges stay free. (OpenRouter still fine as the cheap JUDGE — small requests work.)

# ── Claude escalation cap: Claude is a paid/quota tier, so restrict WHEN it can be
# reached. It only fires for categories the local tiers genuinely can't do (pwn/rev),
# and no more than N times per rolling hour — so autosolve can never silently drain the
# Max quota on categories the free tiers already handle (shell/web/crypto).
CLAUDE_CATEGORIES = set(x.strip() for x in os.getenv(
    "CLAUDE_CATEGORIES", "pwn,rev,reverse,reversing,binary,exploit").split(",") if x.strip())
CLAUDE_MAX_PER_HOUR = int(os.getenv("CLAUDE_MAX_PER_HOUR", "8"))

# HalCTF runs under a strict local-only rule.  Set HALCTF_MODE=1 in the
# competition container; this removes every cloud/frontier tier from both the
# normal cascade and any automatic retry path.  The conference endpoint is
# supplied at runtime through FAST_URL/LOCAL_URL, never baked into the image.
HALCTF_MODE = os.getenv("HALCTF_MODE", "0").lower() in ("1", "true", "yes", "on")
LOCAL_ONLY_MODE = os.getenv("LOCAL_ONLY_MODE", "0").lower() in ("1", "true", "yes", "on")
if HALCTF_MODE or LOCAL_ONLY_MODE:
    ESCALATION = ["fast", "local"]
# codex REMOVED from the cascade: `codex exec` flaps on auth (264 failures) and is an
# autonomous agent, not a clean per-step tier — it broke the solve every time it was
# reached. Re-add only if codex auth is made stable. "local" (gpt-oss) has no vLLM tool
# parser so it can't solve — it's the LOCAL JUDGE (SUPERVISOR_TIERS). burst = dead RunPod.
# codex = ChatGPT (via the Codex CLI subscription) — this is the working ChatGPT
# step. The api.openai.com "gpt" tier needs an OPENAI_API_KEY and is left out.
# gemini is OUT: gemini-2.5-pro has 0 free-tier quota (429 RESOURCE_EXHAUSTED on
# every call), so it just poisoned the end of every cascade. Re-add if you get a
# paid Gemini key. burst is auto-skipped until RunPod is deployed.

# ── Vision routing ──────────────────────────────────────────────
# Which model handles image/audio analysis.
# Must support vision (multimodal). Local models usually don't.
VISION_TIER = "vision"        # local Qwen2.5-VL (gx10 Ollama); falls back if down
VISION_FALLBACK = "claude"    # used when the local vision tier is unreachable

# ── Judge routing ───────────────────────────────────────────────
# Which model validates flags. Should be DIFFERENT from the solver.
# Cheap + fast is fine — it's just checking provenance.
JUDGE_TIER = "openrouter"     # DeepSeek-V4 — FAST (~3s vs 122B's 47-234s), INDEPENDENT of both Qwen solvers, ~$0.003/judgment. Solvers stay local; judge is a cheap independent gate.

# ── Supervisor pool ─────────────────────────────────────────────
# Strong models that SUPERVISE (judge flags + analyze failures + write patches).
# "local" = gpt-oss-120b on the gx10 Spark: fast (~5s) + accurate → PRIMARY judge,
# free, no cloud/ToS exposure. Claude is the diverse second opinion (rotated).
# Add "antigravity"/"codex" back for more diversity (antigravity = Google ToS risk).
SUPERVISOR_TIERS = ["openrouter", "local"]   # DeepSeek analyst (fast+independent) → 122B local fallback if OpenRouter is down/out-of-credit

# ── Agent limits ─────────────────────────────────────────────────
DETECTOR_ENABLED = True       # LOOSENED (threshold 0.85, iteration allowed) — keeps
                              # the hard anti-loop stops, drops the false-aborts on
                              # legit cipher brute-force / fuzzing / normal reasoning
MAX_STEPS       = 60          # cap for runs that can reach a PAID tier (claude) — keeps cost bounded
# Free-tier (fast/local only) runs don't burn money, so a step ceiling shouldn't be
# what quits them. When no paid tier is reachable, the LOOP DETECTOR + TIER_TIMEOUT
# are the real stops and local grinds on trial-and-error up to this much higher bound.
LOCAL_MAX_STEPS = int(os.getenv("LOCAL_MAX_STEPS", "240"))
ESCALATE_AFTER  = 16          # give each tier real iteration room before escalating (hard challs need many attempts)
LOOP_THRESHOLD  = 3           # repeated identical actions triggers escalation
TOOL_TIMEOUT    = 120         # seconds per tool execution
STEP_TIMEOUT    = 300         # single model call max seconds — kill + escalate
TIER_TIMEOUT    = 1200        # more wall-clock per tier so long trial-and-error isn't time-clipped

# ── Workspace ────────────────────────────────────────────────────
WORKDIR = os.getenv("CTF_WORKDIR", "/tmp/screwhead")
