"""
Screwhead — Bullshit Detector.
Watches the agent's behavior in real-time and triggers escalation
when it recognizes patterns of failure, not just identical loops.

Catches:
  - Repeated similar (not identical) commands
  - Flip-flopping between two approaches
  - Ignoring tool output and trying the same class of attack
  - Empty or error-only results piling up
  - Model apologizing or saying "let me try" without changing approach
  - Output getting longer without progress (rambling)
  - Same error hit 3+ times
"""

import hashlib
import re
from collections import deque


class BullshitDetector:
    """
    Watches agent trace and returns a confidence score (0.0-1.0)
    that the current model is failing. Escalate when score > threshold.
    """

    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold
        self.actions = deque(maxlen=20)       # recent (tool, args_hash, result_status)
        self.thinking = deque(maxlen=10)      # recent model reasoning text
        self.errors = deque(maxlen=15)        # recent error strings
        self.result_lengths = deque(maxlen=10) # track output sizes
        self.timeouts = 0                     # model-call timeouts since last reset
        self._score = 0.0

    def observe_action(self, tool: str, args: dict, result: dict):
        """Record a tool call and its result."""
        args_hash = hashlib.md5(str(sorted(args.items())).encode()).hexdigest()[:8]
        status = result.get("status", "unknown")
        exit_code = result.get("exit_code", 0)
        stdout = result.get("stdout", "") or result.get("content", "") or result.get("body", "")
        stderr = result.get("stderr", "")

        self.actions.append({
            "tool": tool,
            "args_hash": args_hash,
            "args_preview": str(args)[:200],
            "status": status,
            "exit_code": exit_code,
            "has_output": bool(stdout.strip()),
        })

        if stderr and exit_code != 0:
            self.errors.append(stderr[:200])

        self.result_lengths.append(len(stdout))

    def observe_thinking(self, text: str):
        """Record model's reasoning text."""
        self.thinking.append(text[:500])

    def observe_timeout(self):
        """A model call timed out — a strong failure signal."""
        self.timeouts += 1

    def score(self) -> float:
        """Calculate current bullshit score. Higher = more likely failing."""
        # A model that reasons repeatedly without taking any tool action is
        # stalled before the normal action-window signals can fire.
        if not self.actions and len(self.thinking) >= 2:
            self._score = 0.8
            return self._score
        if len(self.actions) < 3 and self.timeouts == 0:
            return 0.0

        signals = []

        # ── Signal 1: Similar commands (same tool, different args) ────
        recent = list(self.actions)[-8:]
        tool_counts = {}
        for a in recent:
            tool_counts[a["tool"]] = tool_counts.get(a["tool"], 0) + 1
        max_same_tool = max(tool_counts.values()) if tool_counts else 0
        # Loosened: iterating one tool with DIFFERENT args (cipher brute-force,
        # fuzzing) is legit. Only ALL-8-identical-tool is mildly suspicious; the
        # real-loop catch is Signal 7 (identical args) below.
        if max_same_tool >= 8:
            signals.append(("same_tool_spam", 0.6))

        # ── Signal 2: Flip-flopping (A, B, A, B pattern) ─────────────
        if len(recent) >= 4:
            tools = [a["tool"] for a in recent[-6:]]
            for i in range(len(tools) - 3):
                if tools[i] == tools[i+2] and tools[i+1] == tools[i+3] and tools[i] != tools[i+1]:
                    signals.append(("flip_flop", 0.7))
                    break

        # ── Signal 3: Error pileup ───────────────────────────────────
        recent_errors = sum(1 for a in recent if a["exit_code"] != 0 and a["tool"] != "submit_flag")
        if recent_errors >= 5:
            signals.append(("error_storm", 0.9))
        elif recent_errors >= 3:
            signals.append(("error_pileup", 0.5))

        # ── Signal 4: Same error repeating ───────────────────────────
        if len(self.errors) >= 3:
            last_3 = list(self.errors)[-3:]
            if last_3[0] == last_3[1] == last_3[2]:
                signals.append(("same_error_3x", 0.8))

        # ── Signal 5: No useful output ───────────────────────────────
        no_output = sum(1 for a in recent if not a["has_output"])
        if no_output >= 4:
            signals.append(("no_output", 0.6))

        # ── Signal 6: Model is rambling / apologizing ────────────────
        if self.thinking:
            last_think = list(self.thinking)[-1].lower()
            weasel_words = [
                "let me try", "i apologize", "let's try a different",
                "i'll attempt", "perhaps", "maybe i should",
                "sorry", "unfortunately", "let me reconsider",
                "i realize", "my mistake", "let me think",
            ]
            weasel_count = sum(1 for w in weasel_words if w in last_think)
            # Loosened: "let me try / perhaps / reconsider" is NORMAL reasoning, not
            # BS. Only weakly signal, and only if the model is drowning in it.
            if weasel_count >= 4:
                signals.append(("weasel_words", 0.3))

            # Check if thinking is getting longer without action changes
            if len(self.thinking) >= 3:
                lengths = [len(t) for t in list(self.thinking)[-3:]]
                if lengths[-1] > lengths[0] * 1.5 and lengths[-1] > 300:
                    signals.append(("rambling", 0.4))

        # ── Signal 7: Identical args on same tool ────────────────────
        # Count across the whole recent window rather than requiring consecutive
        # calls. Interleaving shell and HTTP variants of a request is still a loop.
        action_counts = {}
        for action in recent:
            key = (action["tool"], action["args_hash"])
            action_counts[key] = action_counts.get(key, 0) + 1
        if max(action_counts.values(), default=0) >= 3:
            signals.append(("exact_repeat_3x", 1.0))

        # ── Signal 8: submit_flag rejected multiple times ────────────
        flag_attempts = sum(1 for a in self.actions if a["tool"] == "submit_flag")
        if flag_attempts >= 3:
            signals.append(("flag_spam", 0.9))
        elif flag_attempts >= 2:
            signals.append(("flag_retry", 0.5))

        # ── Signal 9: model call(s) timed out ────────────────────────
        if self.timeouts > 0:
            signals.append(("model_timeout", 0.9))

        # ── Combine signals ──────────────────────────────────────────
        if not signals:
            self._score = 0.0
            return 0.0

        # Take the max signal, then add diminishing contributions from others
        signals.sort(key=lambda x: -x[1])
        combined = signals[0][1]
        for _, weight in signals[1:]:
            combined = combined + weight * (1 - combined) * 0.3

        self._score = min(1.0, combined)
        return self._score

    def should_escalate(self) -> tuple[bool, str]:
        """Check if we should escalate to the next tier."""
        current = self.score()
        if current < self.threshold:
            return False, f"score={current:.2f} (threshold={self.threshold})"

        # Build a human-readable reason
        reasons = []
        recent = list(self.actions)[-8:]

        tool_counts = {}
        for a in recent:
            tool_counts[a["tool"]] = tool_counts.get(a["tool"], 0) + 1
        if max(tool_counts.values(), default=0) >= 4:
            top_tool = max(tool_counts, key=tool_counts.get)
            reasons.append(f"spamming {top_tool}")

        action_counts = {}
        for action in recent:
            key = (action["tool"], action["args_hash"])
            action_counts[key] = action_counts.get(key, 0) + 1
        repeated = max(action_counts.values(), default=0)
        if repeated >= 3:
            reasons.append(f"identical tool call repeated {repeated} times")

        error_count = sum(1 for a in recent if a["exit_code"] != 0)
        if error_count >= 3:
            reasons.append(f"{error_count} errors in last {len(recent)} actions")

        flag_attempts = sum(1 for a in self.actions if a["tool"] == "submit_flag")
        if flag_attempts >= 2:
            reasons.append(f"submitted {flag_attempts} bad flags")

        if self.thinking:
            last = list(self.thinking)[-1].lower()
            if any(w in last for w in ["apologize", "sorry", "let me try", "perhaps"]):
                reasons.append("model is hedging")

        reason = "; ".join(reasons) if reasons else f"bullshit score {current:.2f}"
        return True, reason

    def reset(self):
        """Reset after escalation to give the new model a clean slate."""
        self.actions.clear()
        self.thinking.clear()
        self.errors.clear()
        self.result_lengths.clear()
        self.timeouts = 0
        self._score = 0.0

    def stats(self) -> dict:
        """Current detector state for logging."""
        return {
            "score": self._score,
            "threshold": self.threshold,
            "actions_tracked": len(self.actions),
            "errors_tracked": len(self.errors),
            "thinking_tracked": len(self.thinking),
        }
