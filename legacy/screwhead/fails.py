"""
Screwhead — Failure logger.
Captures failed runs with context so you can diagnose and fix system prompts.

Writes to /tmp/ctf-agent/fails/ with one JSON file per failure.
Review with: python fails.py review
"""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from config import WORKDIR

FAILS_DIR = Path(WORKDIR) / "fails"


def log_failure(challenge_desc: str, category: str, trace: list, final_tier: str,
                steps: int, termination_reason: str = "unknown"):
    """Log a failed challenge run with diagnostic context."""
    FAILS_DIR.mkdir(parents=True, exist_ok=True)

    # Extract the interesting parts from the trace
    diagnosis = _diagnose(trace)

    fail = {
        "timestamp": datetime.now().isoformat(),
        "challenge": challenge_desc[:500],
        "category": category,
        "final_tier": final_tier,
        "steps": steps,
        "termination_reason": termination_reason,   # WHY it stopped (not just a pattern)
        "diagnosis": diagnosis,
        "tool_sequence": [t["tool"] for t in trace if t.get("type") == "tool"],
        "errors": _extract_errors(trace),
        "loops": _find_loops(trace),
        "last_5_actions": _last_n_actions(trace, 5),
        "full_trace": trace,
    }

    # Collision-safe: microsecond ts + uuid suffix so parallel same-category fails
    # in the same second don't overwrite each other (the old 1s filenames did).
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = FAILS_DIR / f"fail-{category}-{ts}-{uuid.uuid4().hex[:8]}.json"
    with open(path, "w") as f:
        json.dump(fail, f, indent=2, default=str)

    try:
        import cortex
        cortex.store_failure(challenge_desc, category, cortex._failed_approaches(trace))
    except Exception as exc:
        print(f"  [cortex] failure memory skipped ({exc})")

    print(f"  [!] Failure logged ({termination_reason}): {path}")
    return path


def _diagnose(trace: list) -> dict:
    """Auto-detect common failure patterns."""
    patterns = {
        "looped": False,
        "empty_output": False,
        "timeout": False,
        "wrong_approach": False,
        "never_tried_tools": False,
        "context_overflow": False,
        "missing_path": False,
        "tool_auth": False,
        "dependency_missing": False,
        "permission_denied": False,
    }

    tool_actions = [t for t in trace if t.get("type") == "tool"]

    # No tool calls at all — model just talked
    if not tool_actions:
        patterns["never_tried_tools"] = True

    # Repeated identical commands
    sigs = [f"{t['tool']}:{json.dumps(t.get('args', {}), sort_keys=True)[:100]}" for t in tool_actions]
    for i in range(len(sigs) - 2):
        if sigs[i] == sigs[i + 1] == sigs[i + 2]:
            patterns["looped"] = True
            break

    # Timeouts
    for t in tool_actions:
        result = t.get("result", {})
        if result.get("status") == "timeout":
            patterns["timeout"] = True

    # Errors
    for t in tool_actions:
        result = t.get("result", {})
        stderr = result.get("stderr", "")
        # Tool adapters use different names for textual failures. Include all
        # standard fields so read_file/http results are diagnosed consistently.
        text = " ".join(str(result.get(k, "") or "")
                         for k in ("stderr", "stdout", "output", "content", "body")).lower()
        if "no such file" in text or "cannot find" in text or "can't cd" in text:
            patterns["missing_path"] = True
        if "not authenticated" in text or "authentication" in text or "login" in text:
            patterns["tool_auth"] = True
        if "modulenotfounderror" in text or "command not found" in text:
            patterns["dependency_missing"] = True
        if "permission denied" in text or "externally-managed-environment" in text:
            patterns["permission_denied"] = True
        if ("maximum context" in text or "context length" in text
                or "input_tokens" in text or "too many tokens" in text):
            patterns["context_overflow"] = True
        if "No such file" in stderr or "command not found" in stderr:
            patterns["wrong_approach"] = True

    return patterns


def _extract_errors(trace: list) -> list:
    """Pull out all error messages from tool results."""
    errors = []
    for t in trace:
        if t.get("type") != "tool":
            continue
        result = t.get("result", {})
        stderr = result.get("stderr", "") or ""
        status = result.get("status", "")
        text = " ".join(str(result.get(k, "") or "")
                         for k in ("stderr", "stdout", "output", "content", "body"))
        if (result.get("exit_code", 0) != 0 or status in {"error", "timeout"}) and text.strip():
            errors.append({
                "step": t.get("step"),
                "tool": t.get("tool"),
                "command": t.get("args", {}).get("command", "")[:200],
                "error": text[:500],
            })
    return errors


def _find_loops(trace: list) -> list:
    """Find sequences where the same action repeated."""
    tool_actions = [t for t in trace if t.get("type") == "tool"]
    loops = []
    sigs = []
    for t in tool_actions:
        sig = f"{t['tool']}:{json.dumps(t.get('args', {}), sort_keys=True)[:100]}"
        sigs.append(sig)

    i = 0
    while i < len(sigs) - 1:
        if sigs[i] == sigs[i + 1]:
            count = 2
            while i + count < len(sigs) and sigs[i + count] == sigs[i]:
                count += 1
            loops.append({
                "action": sigs[i][:200],
                "repeated": count,
                "starting_step": tool_actions[i].get("step"),
            })
            i += count
        else:
            i += 1

    # Models may interleave a repeated request with harmless observations.
    # Record that pattern too so Overwatch can distinguish exploration from
    # thrashing.
    seen = {}
    for idx, sig in enumerate(sigs):
        seen.setdefault(sig, []).append(tool_actions[idx].get("step"))
    consecutive = {item["action"] for item in loops}
    for sig, steps in seen.items():
        if len(steps) >= 3 and sig not in consecutive:
            loops.append({
                "action": sig[:200],
                "repeated": len(steps),
                "starting_step": steps[0],
                "interleaved": True,
            })
    return loops


def _last_n_actions(trace: list, n: int) -> list:
    """Get the last N tool actions for quick review."""
    tool_actions = [t for t in trace if t.get("type") == "tool"]
    return [
        {
            "step": t.get("step"),
            "tool": t.get("tool"),
            "args_preview": str(t.get("args", {}))[:200],
            "result_preview": str(t.get("result", {}))[:200],
        }
        for t in tool_actions[-n:]
    ]


# ── Review CLI ───────────────────────────────────────────────────

def review_fails():
    """Print a summary of all logged failures."""
    if not FAILS_DIR.exists():
        print("No failures logged yet.")
        return

    fails = sorted(FAILS_DIR.glob("fail-*.json"))
    if not fails:
        print("No failures logged yet.")
        return

    print(f"\n{'='*60}")
    print(f"  {len(fails)} failures logged")
    print(f"{'='*60}\n")

    # Category breakdown
    cats = {}
    for f in fails:
        data = json.loads(f.read_text())
        cat = data["category"]
        cats[cat] = cats.get(cat, 0) + 1

    print("By category:")
    for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    # Pattern breakdown
    pattern_counts = {}
    for f in fails:
        data = json.loads(f.read_text())
        for pattern, hit in data.get("diagnosis", {}).items():
            if hit:
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

    if pattern_counts:
        print("\nCommon failure patterns:")
        for pattern, count in sorted(pattern_counts.items(), key=lambda x: -x[1]):
            print(f"  {pattern}: {count}")

    # Prompt fix suggestions
    print("\nSuggested prompt fixes:")
    if pattern_counts.get("looped", 0) > 0:
        print('  → Add: "If a command fails twice, change your approach entirely."')
    if pattern_counts.get("never_tried_tools", 0) > 0:
        print('  → Add: "Always use tools. Do not just reason about the challenge — act."')
    if pattern_counts.get("timeout", 0) > 0:
        print('  → Add: "Use timeouts and limits. Pipe through head. Avoid long-running scans."')
    if pattern_counts.get("wrong_approach", 0) > 0:
        print('  → Add: "Check that tools and files exist before using them."')

    # Show most recent failure detail
    print(f"\n{'─'*60}")
    print("Most recent failure detail:\n")
    latest = json.loads(fails[-1].read_text())
    print(f"  Challenge: {latest['challenge'][:100]}")
    print(f"  Category:  {latest['category']}")
    print(f"  Steps:     {latest['steps']}")
    print(f"  Patterns:  {[k for k, v in latest['diagnosis'].items() if v]}")
    if latest["loops"]:
        print(f"  Loops:     {latest['loops']}")
    if latest["errors"]:
        print(f"  Errors:")
        for e in latest["errors"][:3]:
            print(f"    step {e['step']}: {e['error'][:100]}")
    print(f"\n  Full trace: {fails[-1]}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "review":
        review_fails()
    else:
        print("Usage: python fails.py review")
