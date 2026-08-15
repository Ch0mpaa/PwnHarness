"""
Screwhead — Team manager.
Assigns challenges to category-specific agent teams and runs them in parallel.

Each "team" is a pool of concurrent agent workers for one challenge category.
Configure team sizes per category based on your available compute.
"""

import asyncio
import json
import os
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import WORKDIR, TIERS
from agent import solve_challenge, solve_with_recovery
from scraper import load_challenges, update_challenge


# ── Team configuration ───────────────────────────────────────────
# How many concurrent agents per category.
# Tune based on your GB10 vLLM concurrency limits.
# More workers = more parallel requests to the same model.

TEAM_SIZES = {
    "web":       4,
    "crypto":    2,
    "rev":       2,
    "pwn":       2,
    "forensics": 2,
    "misc":      3,
    "ai":        2,
    "unknown":   2,
}

# Max total concurrent workers across all teams
MAX_GLOBAL_WORKERS = 8


def challenge_workspace(challenge: dict) -> Path:
    """Return a dedicated workspace, never the shared WORKDIR/state directory."""
    shared_root = Path(WORKDIR).resolve()
    configured = challenge.get("local_dir")
    if configured and Path(configured).resolve() != shared_root:
        return Path(configured)
    return Path(WORKDIR) / "challenges" / challenge["slug"]


class TeamManager:
    """Manages parallel agent teams across challenge categories."""

    def __init__(self, challenges: list[dict] | None = None):
        self.challenges = challenges or load_challenges()
        self.results = []
        self._lock = asyncio.Lock()
        self._active_workers = 0
        # A REAL global cap: acquired for the whole solve, so total concurrent
        # workers across all category teams never exceeds MAX_GLOBAL_WORKERS.
        self._global_sem = asyncio.Semaphore(MAX_GLOBAL_WORKERS)

    def get_teams(self) -> dict[str, list[dict]]:
        """Group challenges by category."""
        teams = {}
        for c in self.challenges:
            cat = c.get("category", "unknown")
            if cat not in teams:
                teams[cat] = []
            teams[cat].append(c)
        return teams

    def get_queued(self) -> list[dict]:
        """Get challenges that haven't been attempted yet."""
        return [c for c in self.challenges if c.get("status") == "queued" and not c.get("flag")]

    def summary(self) -> dict:
        """Current status summary."""
        teams = self.get_teams()
        summary = {"total": len(self.challenges), "teams": {}}
        for cat, chals in teams.items():
            summary["teams"][cat] = {
                "total":   len(chals),
                "queued":  sum(1 for c in chals if c.get("status") == "queued"),
                "running": sum(1 for c in chals if c.get("status") == "running"),
                "solved":  sum(1 for c in chals if c.get("status") == "solved"),
                "failed":  sum(1 for c in chals if c.get("status") == "failed"),
                "workers": TEAM_SIZES.get(cat, 2),
            }
        return summary

    async def run_all(self, callback=None):
        """
        Deploy all teams. Each category runs its challenges with its team size.

        callback: async fn(challenge, result) called after each challenge completes.
                  Use this for Discord notifications.
        """
        teams = self.get_teams()
        tasks = []

        for cat, challenges in teams.items():
            queued = [c for c in challenges if c.get("status") == "queued" and not c.get("flag")]
            if not queued:
                continue
            team_size = min(TEAM_SIZES.get(cat, 2), len(queued))
            tasks.append(self._run_team(cat, queued, team_size, callback))

        await asyncio.gather(*tasks)
        return self.results

    async def run_category(self, category: str, callback=None):
        """Run only one category's team."""
        teams = self.get_teams()
        challenges = teams.get(category, [])
        queued = [c for c in challenges if c.get("status") == "queued" and not c.get("flag")]
        if not queued:
            return []

        team_size = min(TEAM_SIZES.get(category, 2), len(queued))
        await self._run_team(category, queued, team_size, callback)
        return [r for r in self.results if r.get("category") == category]

    async def _run_team(self, category: str, challenges: list[dict], team_size: int, callback=None):
        """Run a team of workers on a queue of challenges."""
        sem = asyncio.Semaphore(team_size)
        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=team_size)

        async def _worker(challenge: dict):
            # Per-team cap AND the shared global cap — both must have a slot, so
            # total concurrency across every category team stays <= MAX_GLOBAL_WORKERS.
            async with sem, self._global_sem:
                async with self._lock:
                    self._active_workers += 1

                try:
                    # Mark running
                    update_challenge(challenge["slug"], {"status": "running"})

                    # HTB challenges need files downloaded + docker spawned first.
                    if str(challenge.get("ctf", "")).startswith("htb"):
                        try:
                            import htb
                            await loop.run_in_executor(executor, lambda: htb.prep(challenge))
                        except Exception as _e:
                            print(f"[teams] htb prep failed: {_e}")

                    # Resolve this challenge's OWN workspace (thread-local, passed
                    # into the solver — never mutate the global config.WORKDIR).
                    workspace = challenge_workspace(challenge)
                    # Discover files already sitting in the workspace so the agent is
                    # explicitly told what it has (downloads land here but local_files
                    # often stays empty otherwise).
                    local_files = _prepare_local_files(challenge, workspace)
                    if challenge.get("local_dir") != str(workspace):
                        update_challenge(challenge["slug"], {"local_dir": str(workspace)})
                        challenge["local_dir"] = str(workspace)
                    if local_files != (challenge.get("local_files") or []):
                        update_challenge(challenge["slug"], {"local_files": local_files})
                        challenge["local_files"] = local_files

                    result = await loop.run_in_executor(
                        executor,
                        lambda: solve_with_recovery(
                            description=challenge.get("description", ""),
                            challenge_files=local_files,
                            target_url=challenge.get("target_url"),
                            hint_key=challenge.get("slug"),
                            name=challenge.get("name"),
                            ctf=challenge.get("ctf"),
                            workspace=str(workspace),
                            mode=challenge.get("mode", "jeopardy"),
                        ),
                    )

                    # Update status. A judge-approved flag is only "captured" — CTFd
                    # confirmation in the deploy callback promotes it to "solved" (or
                    # re-queues it if CTFd rejects). Never mark "solved" here.
                    if result.get("flag"):
                        update_challenge(challenge["slug"], {
                            "status": "captured",
                            "flag": result["flag"],
                            "attempts": challenge.get("attempts", 0) + 1,
                            "final_tier": result.get("final_tier"),
                            "steps": result.get("steps"),
                        })
                        # submit-vs-hold + final solved/queued is decided in the bot's
                        # deploy callback (it has the channel + knows the CTFd result).
                    else:
                        update_challenge(challenge["slug"], {
                            # parked = tried twice (original + Claude fix), needs human
                            "status": "parked" if result.get("parked") else "failed",
                            "attempts": challenge.get("attempts", 0) + 1,
                            "final_tier": result.get("final_tier"),
                            "steps": result.get("steps"),
                            "termination_reason": result.get("termination_reason"),
                            "claude_analysis": result.get("claude_analysis", ""),
                        })

                    entry = {
                        "challenge": challenge["name"],
                        "slug": challenge["slug"],
                        "category": category,
                        "flag": result.get("flag"),
                        "steps": result.get("steps"),
                        "tier": result.get("final_tier"),
                        "points": challenge.get("points", 0),
                        "ctf": challenge.get("ctf"),
                    }
                    self.results.append(entry)

                    if callback:
                        await callback(challenge, result)

                except Exception as exc:
                    # Do not strand a challenge in `running` when preparation,
                    # solving, or the callback fails before a result is written.
                    reason = f"worker_exception: {type(exc).__name__}: {exc}"[:500]
                    try:
                        update_challenge(challenge["slug"], {
                            "status": "failed",
                            "attempts": challenge.get("attempts", 0) + 1,
                            "termination_reason": reason,
                        })
                    except Exception as update_exc:
                        print(f"[teams] failed to record worker error: {update_exc}")
                    print(f"[teams] {challenge.get('name', challenge.get('slug'))}: {reason}")
                finally:
                    async with self._lock:
                        self._active_workers -= 1

        # Launch all workers for this team
        await asyncio.gather(*[_worker(c) for c in challenges])


def _prepare_local_files(challenge: dict, workspace: Path) -> list[str]:
    """Create a challenge-local workspace and put all declared inputs inside it.

    The returned paths are consequently valid from the solve's CWD.  This also
    repairs older registry entries which have files but no ``local_dir``.
    ``challenge.json`` is workspace context, not an artifact handed to the model.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    found = []
    for raw in challenge.get("local_files") or []:
        path = Path(raw)
        # Registry entries may be relative to the challenge workspace. Resolve
        # those there instead of accidentally checking the bot process CWD.
        if not path.is_absolute():
            path = workspace / path
        if path.exists() and path.is_file():
            source = path.resolve()
            destination = workspace / path.name
            if source != destination.resolve():
                shutil.copy2(source, destination)
            found.append(str(destination.resolve()))

    metadata = workspace / "challenge.json"
    if not metadata.exists():
        metadata.write_text(json.dumps(challenge, indent=2, default=str))

    for path in workspace.rglob("*"):
        if path.is_file() and path.name != "challenge.json":
            found.append(str(path.resolve()))
    return sorted(set(found))


def print_scoreboard(results: list[dict]):
    """Print a summary scoreboard."""
    solved = [r for r in results if r["flag"]]
    failed = [r for r in results if not r["flag"]]
    total_points = sum(r.get("points", 0) for r in solved)

    print(f"\n{'='*60}")
    print(f"  SCOREBOARD")
    print(f"{'='*60}")
    print(f"  Solved: {len(solved)}/{len(results)} | Points: {total_points}")
    print()

    if solved:
        print("  Solved:")
        for r in solved:
            print(f"    ✓ [{r['category']:10s}] {r['challenge'][:40]} ({r['points']}pts, {r['steps']} steps)")

    if failed:
        print(f"\n  Failed:")
        for r in failed:
            print(f"    ✗ [{r['category']:10s}] {r['challenge'][:40]} (tier: {r['tier']})")

    print(f"{'='*60}\n")


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "status":
        mgr = TeamManager()
        s = mgr.summary()
        print(f"\n  Total challenges: {s['total']}\n")
        for cat, info in s["teams"].items():
            print(f"  {cat:10s} | {info['workers']} workers | "
                  f"queued:{info['queued']} running:{info['running']} "
                  f"solved:{info['solved']} failed:{info['failed']}")
        print()

    elif len(sys.argv) > 1 and sys.argv[1] == "deploy":
        category = sys.argv[2] if len(sys.argv) > 2 else None
        mgr = TeamManager()

        if category:
            print(f"  Deploying team: {category}")
            results = asyncio.run(mgr.run_category(category))
        else:
            print(f"  Deploying all teams")
            results = asyncio.run(mgr.run_all())

        print_scoreboard(results)

    else:
        print("Usage:")
        print("  python teams.py status          — Show team assignments")
        print("  python teams.py deploy           — Run all teams")
        print("  python teams.py deploy web       — Run one category")
