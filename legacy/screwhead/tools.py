"""
Screwhead — Tool implementations.
Each tool returns a dict with stdout/stderr/status for the agent to reason over.
"""

import subprocess
import os
import base64
import httpx
import config
from config import TOOL_TIMEOUT
from workspace import get_workdir


_INTERNAL_STATE_DIR = os.path.realpath("/tmp/ctf-agent/ctfs")
_INTERNAL_STATE_FILES = {
    "registry.json", "confidence.json", "held.json", "submitted.json", "settings.json",
}


def _workdir() -> str:
    """This thread's challenge workspace (thread-local; falls back to config root).
    Concurrent workers each get their own — never mutate a global."""
    return get_workdir()


def _ensure_workdir():
    os.makedirs(get_workdir(), exist_ok=True)


def _resolve_path(path: str) -> str:
    """Resolve a tool-supplied relative path inside the active workspace."""
    return path if os.path.isabs(path) else os.path.join(get_workdir(), path)


def _is_protected_internal_state(path: str) -> bool:
    """True for private orchestration JSON, including traversal and symlink aliases."""
    resolved = os.path.realpath(path)
    try:
        inside_state = os.path.commonpath((resolved, _INTERNAL_STATE_DIR)) == _INTERNAL_STATE_DIR
    except ValueError:
        inside_state = False
    return inside_state and os.path.basename(resolved) in _INTERNAL_STATE_FILES


def _deny_protected_path(path: str) -> dict | None:
    if _is_protected_internal_state(path):
        return {
            "status": "error",
            "stderr": "Access denied: Screwhead internal state files are not available to solve tools.",
        }
    return None


# ── Available tools (schema sent to the LLM) ────────────────────

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "shell",
            "description": (
                "Execute a shell command. Use for: running exploits, nmap, "
                "gobuster, python scripts, compiling C, netcat, curl, "
                "binwalk, strings, file, xxd, objdump, gdb scripts, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute.",
                    },
                    "workdir": {
                        "type": "string",
                        "description": "Optional working directory. Defaults to challenge workspace.",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send an HTTP request to a target. Use for web challenges: "
                "SQLi, XSS, SSRF, API fuzzing, cookie manipulation, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method":  {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]},
                    "url":     {"type": "string", "description": "Full target URL."},
                    "headers": {"type": "object", "description": "Optional headers dict."},
                    "body":    {"type": "string", "description": "Optional request body."},
                    "follow_redirects": {"type": "boolean", "description": "Follow 3xx. Default true."},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sqlmap",
            "description": (
                "Automated SQL injection detection AND data extraction. Use this for ANY "
                "SQLi (union / blind boolean / error-based / time-based) instead of hand-rolling "
                "injection with repeated http_request calls. Point it at a URL (add `data` for "
                "POST/login forms); it auto-detects the injectable parameter and dumps the data, "
                "returning the injection type, dumped rows, and any flag found."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url":       {"type": "string", "description": "Target URL, e.g. http://host/page?id=1"},
                    "data":      {"type": "string", "description": "Optional POST body to inject, e.g. 'username=a&password=b'."},
                    "level":     {"type": "integer", "description": "sqlmap --level 1-5 (default 2)."},
                    "risk":      {"type": "integer", "description": "sqlmap --risk 1-3 (default 2)."},
                    "technique": {"type": "string", "description": "Optional sqlmap techniques, e.g. 'BEU' (boolean/error/union)."},
                    "dump":      {"type": "boolean", "description": "Dump table data once injectable. Default true."},
                    "extra":     {"type": "string", "description": "Optional raw extra sqlmap args, e.g. '-D db -T users --dump'."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "phantom",
            "description": (
                "Run any of 204 structured RedOps security tools (returns parsed JSON with auto-extracted "
                "flags). USE THIS instead of raw shell for reverse-engineering, pwn, crypto, forensics, and "
                "web when a matching tool exists: e.g. angr_symbolic_execution (crackmes), ghidra_analysis / "
                "radare2_analyze (decompile), one_gadget_search / ropgadget_search / ropper_gadget_search / "
                "gdb_peda_debug (pwn), volatility3_analyze (memory forensics), hashcat_crack / hashpump_attack / "
                "name_that_hash (crypto), sqlmap_scan / nuclei_scan / ffuf_scan / dalfox_xss_scan (web). "
                "FIRST call with list_tools=true (optionally a category like 'pwn'/'crypto'/'rev'/'forensics'/'web') "
                "to see the exact tools + parameters, then run one with its parameters."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name":  {"type": "string", "description": "Phantom tool to run, e.g. 'angr_symbolic_execution'."},
                    "parameters": {"type": "object", "description": "Tool-specific parameters (discover them via list_tools + tool_name)."},
                    "list_tools": {"type": "boolean", "description": "List available tools instead of running one. With tool_name set, returns that tool's parameter schema."},
                    "category":   {"type": "string", "description": "Optional filter when listing. Natural names work (pwn, rev, crypto → mapped to Phantom's binary/exploit/auth), plus: web, forensics, network, osint, exploit, binary, mobile, cloud."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crack_hash",
            "description": (
                "Crack a password hash with john + rockyou. Use this for ANY hash-cracking "
                "(raw MD5/SHA1/SHA256/SHA512, etc.) instead of hand-writing hashcat/john commands. "
                "Auto-detects the hash type by length. Returns the cracked plaintext."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hash_value": {"type": "string", "description": "The hash to crack (hex)."},
                    "hash_type":  {"type": "string", "description": "Optional john format, e.g. 'raw-MD5'. Auto-detected if omitted."},
                    "wordlist":   {"type": "string", "description": "Optional wordlist path. Default rockyou."},
                },
                "required": ["hash_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rsa_attack",
            "description": (
                "Automated RSA break: give n, e, and c (or a file containing them) and this "
                "factors the modulus (small/close primes), handles small-e cube roots, derives "
                "the private key, and decrypts c to plaintext. Use for RSA challenges instead of "
                "hand-rolling the factoring/decrypt math."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "n":        {"type": "string", "description": "RSA modulus (decimal or 0x hex)."},
                    "e":        {"type": "string", "description": "Public exponent."},
                    "c":        {"type": "string", "description": "Ciphertext integer to decrypt."},
                    "filepath": {"type": "string", "description": "Optional file containing n/e/c lines."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a file from the workspace. Use for: examining downloaded "
                "binaries (as hex), source code, config files, extracted data."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path":   {"type": "string", "description": "Path relative to workspace or absolute."},
                    "binary": {"type": "boolean", "description": "If true, return base64-encoded content."},
                    "max_bytes": {"type": "integer", "description": "Max bytes to read. Default 32768."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write content to a file. Use for: saving exploit scripts, "
                "payloads, wordlists, extracted keys, solver scripts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path":    {"type": "string", "description": "Path relative to workspace or absolute."},
                    "content": {"type": "string", "description": "File content (text or base64 if binary)."},
                    "binary":  {"type": "boolean", "description": "If true, decode content from base64 before writing."},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "codex",
            "description": (
                "Delegate a hard sub-task to the OpenAI Codex coding agent, which "
                "runs autonomously in the challenge workspace (reads/writes files, "
                "runs commands in a sandbox). Use for: reverse-engineering a binary, "
                "writing a non-trivial solver/exploit script, decoding complex crypto, "
                "or analyzing large source trees — anything needing deep multi-step "
                "coding. Give a self-contained instruction; Codex returns its findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Self-contained task for Codex. Reference files by name in the workspace.",
                    },
                    "sandbox": {
                        "type": "string",
                        "enum": ["read-only", "workspace-write", "danger-full-access"],
                        "description": "Command-execution sandbox. Default workspace-write. Use danger-full-access only if network/outside access is required.",
                    },
                },
                "required": ["prompt"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cortex_search",
            "description": (
                "Search long-term memory (Cortex) for prior solves, answers, notes, and "
                "techniques related to THIS challenge. Call this EARLY — the answer or a "
                "strong hint may already be stored from a previous solve. Query with "
                "specific keywords from the challenge (names, tool, cipher type, filename)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Keywords / question to look up in memory."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_flag",
            "description": "Submit a captured flag. Call this when you have the flag.",
            "parameters": {
                "type": "object",
                "properties": {
                    "flag": {"type": "string", "description": "The flag string to submit."},
                },
                "required": ["flag"],
            },
        },
    },
]


# ── Tool implementations ─────────────────────────────────────────

def run_shell(command: str, workdir: str | None = None) -> dict:
    """Execute a shell command with timeout (routed via SOCKS when enabled)."""
    _ensure_workdir()
    cwd = workdir or get_workdir()
    import netcfg
    env = {**os.environ, **netcfg.proxy_env()}
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            cwd=cwd,
            env=env,
        )
        stdout = result.stdout[-8000:] if len(result.stdout) > 8000 else result.stdout
        stderr = result.stderr[-4000:] if len(result.stderr) > 4000 else result.stderr
        return {
            # Nonzero exit is an error — models/summaries must not read "ok" as success.
            "status": "ok" if result.returncode == 0 else "error",
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stdout": "", "stderr": f"Command timed out after {TOOL_TIMEOUT}s"}
    except Exception as e:
        return {"status": "error", "stdout": "", "stderr": str(e)}


# sqlmap needs a longer budget than an ordinary shell command (a real scan
# probes many payloads); cap it so a scan can't hang the whole solve loop.
SQLMAP_TIMEOUT = 180


def run_sqlmap(url: str, data: str | None = None, level: int = 2, risk: int = 2,
               technique: str | None = None, dump: bool = True,
               extra: str | None = None) -> dict:
    """Automated SQL injection detection + extraction via sqlmap. Delegates the
    SQLi grind the models otherwise hand-roll into repeated http_request calls
    (which trips the loop detector). Runs non-interactively and parses out the
    injectable params, injection type, dumped rows, and any flag-looking value."""
    import shutil
    import re
    _ensure_workdir()
    binp = shutil.which("sqlmap")
    if not binp:
        return {"status": "error", "stdout": "", "stderr": "sqlmap not installed"}
    cmd = [binp, "-u", url, "--batch", "--disable-coloring", "--flush-session",
           "--level", str(int(level)), "--risk", str(int(risk))]
    if data:
        cmd += ["--data", data]
    if technique:
        cmd += ["--technique", str(technique)]
    if dump:
        cmd.append("--dump")
    if extra:
        import shlex
        cmd += shlex.split(extra)
    import netcfg
    env = {**os.environ, **netcfg.proxy_env()}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=SQLMAP_TIMEOUT, cwd=get_workdir(), env=env)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stdout": "",
                "stderr": f"sqlmap timed out after {SQLMAP_TIMEOUT}s (try a narrower --technique or lower --level)"}
    except Exception as e:
        return {"status": "error", "stdout": "", "stderr": str(e)}

    out = result.stdout or ""
    err = result.stderr or ""
    extracted: dict = {}
    flags = re.findall(r'FLAG\{[^}]*\}', out, re.I)
    if flags:
        extracted["flags"] = sorted(set(flags))
    params = re.findall(r'Parameter:\s*(.+)', out)
    if params:
        extracted["parameters"] = [p.strip() for p in params]
    types = re.findall(r'Type:\s*(.+)', out)
    if types:
        extracted["types"] = [t.strip() for t in types]
    extracted["injectable"] = bool(params) or "is vulnerable" in out or "injectable" in out.lower()
    # capture dumped table blocks (sqlmap renders them with +---+ borders)
    dumps = re.findall(r'(\+[-+]+\+\n(?:.*\n)+?\+[-+]+\+)', out)
    if dumps:
        extracted["dumped"] = "\n".join(dumps)[:4000]
    tail = out[-4000:] if len(out) > 4000 else out
    return {
        "status": "ok" if result.returncode == 0 else "error",
        "exit_code": result.returncode,
        "stdout": tail,
        "extracted": extracted,
        "stderr": err[-2000:] if len(err) > 2000 else err,
    }


def run_crack_hash(hash_value: str, hash_type: str | None = None,
                   wordlist: str | None = None) -> dict:
    """Crack a password hash with john + a wordlist (rockyou by default). Auto-guesses
    the raw hash format by length so the model doesn't have to get john/hashcat args
    right. Returns the cracked plaintext (models kept retrying broken shell commands)."""
    import shutil
    import re
    _ensure_workdir()
    john = shutil.which("john")
    if not john:
        return {"status": "error", "stderr": "john not installed"}
    wl = wordlist or "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wl):
        return {"status": "error", "stderr": f"wordlist not found: {wl} (gunzip rockyou.txt.gz)"}
    h = str(hash_value).strip().split()[0] if hash_value else ""
    hexlen = len(re.sub(r'[^0-9a-fA-F]', '', h))
    by_len = {32: "raw-MD5", 40: "raw-SHA1", 56: "raw-SHA224", 64: "raw-SHA256",
              96: "raw-SHA384", 128: "raw-SHA512"}
    formats = []
    if hash_type:
        formats.append(hash_type)
    if by_len.get(hexlen) and by_len[hexlen] not in formats:
        formats.append(by_len[hexlen])
    formats.append(None)   # let john try to auto-detect as a last resort
    cwd = get_workdir()
    hf = os.path.join(cwd, "._crackhash.txt")
    with open(hf, "w") as f:
        f.write(h + "\n")
    tried = []
    for fmt in formats:
        cmd = [john, f"--wordlist={wl}", hf]
        if fmt:
            cmd.insert(1, f"--format={fmt}")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=SQLMAP_TIMEOUT, cwd=cwd)
        except subprocess.TimeoutExpired:
            tried.append(f"{fmt or 'auto'}:timeout")
            continue
        show_cmd = [john, "--show"] + ([f"--format={fmt}"] if fmt else []) + [hf]
        show = subprocess.run(show_cmd, capture_output=True, text=True, cwd=cwd)
        tried.append(f"{fmt or 'auto'}")
        if "0 password hashes cracked" not in show.stdout:
            for line in show.stdout.splitlines():
                if ":" in line:
                    plain = line.split(":", 1)[1].strip()
                    if plain and "password hash" not in plain:
                        return {"status": "ok", "cracked": plain,
                                "format": fmt or "auto", "hash": h, "tried": tried,
                                # surface into stdout for the flag-provenance check
                                "stdout": f"cracked: {plain}"}
    return {"status": "error", "cracked": None, "hash": h, "tried": tried,
            "stderr": "not cracked with this wordlist — try a different wordlist or rules"}


def run_rsa_attack(n: str | int | None = None, e: str | int | None = None,
                   c: str | int | None = None, filepath: str | None = None) -> dict:
    """Automated RSA recovery: parse n/e/c (from args or a file), factor the modulus
    (small factors / Fermat near-primes), handle small-e cube roots, derive d, and
    decrypt c to plaintext. Removes the multi-step math the models can't orchestrate."""
    import re
    _ensure_workdir()

    def _grab(key, text):
        m = re.search(rf'\b{key}\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)', text)
        return int(m.group(1), 0) if m else None

    if filepath:
        p = _resolve_path(filepath)
        if os.path.exists(p):
            txt = open(p, "r", errors="ignore").read()
            n = n or _grab("n", txt); e = e or _grab("e", txt); c = c or _grab("c", txt)
    n = int(str(n), 0) if n is not None and not isinstance(n, int) else n
    e = int(str(e), 0) if e is not None and not isinstance(e, int) else e
    c = int(str(c), 0) if c is not None and not isinstance(c, int) else c
    if n is None or e is None:
        return {"status": "error", "stderr": "need at least n and e (and c to decrypt)"}

    def _to_bytes(m):
        b = m.to_bytes((m.bit_length() + 7) // 8, "big")
        return b

    # ── small-e / cube-root (no padding, e small, m^e < n or slightly over) ──
    if c is not None and e <= 5:
        import sympy
        for k in range(0, 1 << 14):
            root, exact = sympy.integer_nthroot(c + k * n, e)
            if exact:
                pt = _to_bytes(int(root))
                dec = pt.decode("latin-1", "ignore")
                return {"status": "ok", "method": f"small-e cube root (e={e})",
                        "plaintext": dec, "plaintext_bytes": pt.hex(),
                        # mirror the answer into stdout so the flag-provenance check
                        # (which scans stdout/content/body) can ground it.
                        "stdout": f"recovered plaintext: {dec}"}

    # ── factor n (small factors via sympy, then Fermat for close primes) ──
    factors = None
    try:
        import sympy
        fac = sympy.factorint(n, limit=1 << 22)
        primes = [p for p, k in fac.items() for _ in range(k)]
        if len(primes) >= 2 and all(sympy.isprime(p) for p in primes) and \
                _prod(primes) == n:
            factors = primes
    except Exception:
        pass
    if factors is None:                       # Fermat: n = a^2 - b^2, primes close
        import math
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(1 << 20):
            b2 = a * a - n
            b = math.isqrt(b2)
            if b * b == b2:
                p, q = a - b, a + b
                if p * q == n and p > 1:
                    factors = [p, q]
                    break
            a += 1
    if not factors:
        return {"status": "error", "stderr": "could not factor n (not small/close primes) — try factordb or a dedicated attack"}

    # ── derive d and decrypt ──
    phi = 1
    for p in factors:
        phi *= (p - 1)
    try:
        d = pow(e, -1, phi)
    except Exception:
        return {"status": "error", "factors": [str(f) for f in factors],
                "stderr": "e not invertible mod phi"}
    result = {"status": "ok", "method": "factored modulus",
              "factors": [str(f) for f in factors]}
    if c is not None:
        m = pow(c, d, n)
        pt = _to_bytes(m)
        dec = pt.decode("latin-1", "ignore")
        result["plaintext"] = dec
        result["plaintext_bytes"] = pt.hex()
        result["stdout"] = f"recovered plaintext: {dec}"   # ground the flag for provenance
    return result


def _prod(xs):
    r = 1
    for x in xs:
        r *= x
    return r


def run_phantom(tool_name: str | None = None, parameters: dict | None = None,
                list_tools: bool = False, category: str | None = None) -> dict:
    """Run one of the 204 structured RedOps tools via the Phantom API (angr, ghidra,
    one_gadget, ropgadget, gdb, volatility3, hashcat, hashpump, sqlmap, nuclei, …).
    Returns parsed JSON with auto-extracted flags. This is the dedicated wrapper so the
    solver reaches for these tools instead of hand-curling them (the sqlmap lesson)."""
    import re
    base = os.getenv("PHANTOM_URL")
    tok = os.getenv("PHANTOM_TOKEN")
    if not base:
        return {"status": "error", "stderr": "PHANTOM_URL not configured"}
    H = {"Authorization": f"Bearer {tok}"} if tok else {}
    try:
        # discovery: list tools, or fetch one tool's parameter schema
        if list_tools or not tool_name:
            if tool_name:
                r = httpx.get(f"{base}/api/tools/{tool_name}", headers=H, timeout=15)
                return {"status": "ok", "schema": r.json()}
            r = httpx.get(f"{base}/api/tools", headers=H, timeout=15)
            d = r.json()
            ts = d.get("tools", d) if isinstance(d, dict) else d
            if category:
                cl = category.lower()
                # map natural CTF category names onto Phantom's real categories
                syn = {"pwn": ["binary", "exploit"], "rev": ["binary"], "reverse": ["binary"],
                       "crypto": ["auth"], "reversing": ["binary"], "forensic": ["forensics"]}
                wanted = set([cl] + syn.get(cl, []))
                ts = [t for t in ts if isinstance(t, dict) and (
                        str(t.get("category", "")).lower() in wanted
                        or cl in str(t.get("name", "")).lower())]
            return {"status": "ok", "count": len(ts),
                    "tools": [{"name": t.get("name"), "category": t.get("category"),
                               "description": t.get("description")}
                              for t in ts if isinstance(t, dict)]}
        # run a tool
        r = httpx.post(f"{base}/api/tools/{tool_name}/run",
                       headers={**H, "Content-Type": "application/json"},
                       json={"parameters": parameters or {}}, timeout=SQLMAP_TIMEOUT)
        try:
            d = r.json()
        except Exception:
            d = {"stdout": r.text[:4000]}
        out = str(d.get("stdout") or d.get("output") or "")
        flags = d.get("flags_found") or sorted(set(
            re.findall(r'(?:flag|ctf|picoCTF|HTB|FLAG|CTF)\{[^}]*\}', out)))
        ok = d.get("success", r.status_code == 200) and (d.get("return_code") in (0, None) or bool(flags))
        return {
            "status": "ok" if ok else "error",
            "tool": tool_name,
            "return_code": d.get("return_code"),
            "flags_found": flags,
            "stdout": out[-6000:],
            "argv": d.get("argv"),
            "error": d.get("detail") or d.get("stderr"),
        }
    except Exception as e:
        return {"status": "error", "stderr": f"phantom call failed: {e}"}


def run_http_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    follow_redirects: bool = True,
) -> dict:
    """Send an HTTP request and return status + headers + body (via SOCKS when enabled)."""
    import netcfg
    proxy = netcfg.socks_url()
    try:
        with httpx.Client(timeout=TOOL_TIMEOUT, verify=False, follow_redirects=follow_redirects, proxy=proxy) as client:
            resp = client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
            resp_body = resp.text[:8000] if len(resp.text) > 8000 else resp.text
            return {
                "status": "ok",
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp_body,
            }
    except Exception as e:
        return {"status": "error", "stderr": str(e)}


def run_read_file(path: str, binary: bool = False, max_bytes: int = 32768) -> dict:
    """Read a file from the workspace."""
    _ensure_workdir()
    path = _resolve_path(path)
    denied = _deny_protected_path(path)
    if denied:
        return denied
    try:
        mode = "rb" if binary else "r"
        with open(path, mode) as f:
            data = f.read(max_bytes)
        if binary:
            data = base64.b64encode(data).decode()
        return {"status": "ok", "content": data, "path": path}
    except Exception as e:
        return {"status": "error", "stderr": str(e)}


def run_write_file(path: str, content: str, binary: bool = False) -> dict:
    """Write content to a file."""
    _ensure_workdir()
    path = _resolve_path(path)
    denied = _deny_protected_path(path)
    if denied:
        return denied
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if binary:
            with open(path, "wb") as f:
                f.write(base64.b64decode(content))
        else:
            with open(path, "w") as f:
                f.write(content)
        return {"status": "ok", "path": path, "bytes": os.path.getsize(path)}
    except Exception as e:
        return {"status": "error", "stderr": str(e)}


CODEX_TIMEOUT = int(os.getenv("CODEX_TIMEOUT", "300"))


def run_codex(prompt: str, sandbox: str = "workspace-write", model: str | None = None) -> dict:
    """Delegate a task to the OpenAI Codex CLI (`codex exec`), non-interactively.

    Runs rooted in the challenge workspace with command approvals disabled so it
    never blocks. The agent's final message is captured via --output-last-message.
    Requires a one-time `codex login` (ChatGPT subscription) or an OpenAI API key.
    """
    _ensure_workdir()
    cwd = get_workdir()
    out_file = os.path.join(cwd, ".codex_last_message.txt")
    try:
        if os.path.exists(out_file):
            os.remove(out_file)
    except OSError:
        pass

    cmd = [
        "codex", "exec",
        "--skip-git-repo-check",
        "-C", cwd,
        "-s", sandbox,
        "-c", 'approval_policy="never"',
        "-o", out_file,
    ]
    if model:
        cmd += ["-m", model]
    cmd.append(prompt)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CODEX_TIMEOUT, cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "output": "", "stderr": f"Codex timed out after {CODEX_TIMEOUT}s"}
    except FileNotFoundError:
        return {"status": "error", "output": "", "stderr": "codex CLI not found on PATH"}

    last_message = ""
    if os.path.exists(out_file):
        try:
            with open(out_file) as f:
                last_message = f.read()
        except OSError:
            pass
    if not last_message:  # fall back to stdout tail
        last_message = result.stdout[-8000:] if len(result.stdout) > 8000 else result.stdout

    stderr = result.stderr[-4000:] if len(result.stderr) > 4000 else result.stderr
    status = "ok" if result.returncode == 0 else "error"
    if result.returncode != 0 and ("login" in stderr.lower() or "auth" in stderr.lower()):
        stderr = "Codex not authenticated — run `codex login` (ChatGPT) or set an OpenAI API key. " + stderr
    return {
        "status": status,
        "exit_code": result.returncode,
        "output": last_message,
        "stderr": stderr,
    }


def run_cortex_search(query: str) -> dict:
    """Look up prior solves/answers in Cortex memory."""
    try:
        import cortex
        hits = cortex.search(query, n=5)
    except Exception as e:
        return {"status": "error", "results": [], "note": f"cortex unavailable: {str(e)[:80]}"}
    if not hits:
        return {"status": "ok", "results": [], "note": "no relevant memory found"}
    return {"status": "ok", "count": len(hits),
            "results": [{"score": h.get("score"), "content": h["content"]} for h in hits]}


def run_submit_flag(flag: str) -> dict:
    """Mark a flag as captured. Extend this to POST to a scoreboard."""
    return {"status": "captured", "flag": flag}


# ── Docker (challenge infrastructure) ────────────────────────────

_DOCKER_PREFIX = None   # resolved once: [] if socket is accessible, else ['sudo','-n']

def _docker_prefix():
    """The bot user may not be in the docker group yet (service predates usermod);
    passwordless sudo covers it. Probe once and cache."""
    global _DOCKER_PREFIX
    if _DOCKER_PREFIX is None:
        try:
            r = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=15)
            _DOCKER_PREFIX = [] if r.returncode == 0 else ["sudo", "-n"]
        except Exception:
            _DOCKER_PREFIX = ["sudo", "-n"]
    return _DOCKER_PREFIX


def _docker(args, timeout=None):
    """Run a `docker ...` argv list, return {status, exit_code, stdout, stderr}."""
    try:
        r = subprocess.run([*_docker_prefix(), "docker", *args], capture_output=True,
                           text=True, timeout=timeout or TOOL_TIMEOUT)
        return {"status": "ok" if r.returncode == 0 else "error",
                "exit_code": r.returncode,
                "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:]}
    except FileNotFoundError:
        return {"status": "error", "stderr": "docker not installed"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stderr": f"docker timed out after {timeout or TOOL_TIMEOUT}s"}
    except Exception as e:
        return {"status": "error", "stderr": str(e)}


def run_docker_run(image, ports=None, env=None, command=None, name=None) -> dict:
    """Pull (if needed) + run a container detached. Returns container id + initial logs.
    ports: ["8080:80", ...]  env: {"KEY":"val"}  command: str appended to image."""
    argv = ["run", "-d", "--rm"]
    if name:
        argv += ["--name", name]
    for p in (ports or []):
        argv += ["-p", str(p)]
    for k, v in (env or {}).items():
        argv += ["-e", f"{k}={v}"]
    argv.append(str(image))
    if command:
        argv += ["sh", "-c", str(command)] if " " in str(command) else [str(command)]
    r = _docker(argv, timeout=300)          # allow time for an image pull
    if r["status"] != "ok":
        return r
    cid = r["stdout"].strip().splitlines()[-1][:12] if r["stdout"].strip() else ""
    import time as _t; _t.sleep(1.5)
    logs = _docker(["logs", cid], timeout=20) if cid else {"stdout": "", "stderr": ""}
    insp = _docker(["port", cid], timeout=15) if cid else {"stdout": ""}
    return {"status": "ok", "container_id": cid,
            "ports": insp.get("stdout", "").strip(),
            "logs": (logs.get("stdout", "") + logs.get("stderr", ""))[-4000:]}


def run_docker_build(dockerfile_path=".", tag=None) -> dict:
    """Build an image from a Dockerfile dir (defaults to workspace). Returns build log + tag."""
    _ensure_workdir()
    ctx = dockerfile_path if os.path.isabs(dockerfile_path) else os.path.join(get_workdir(), dockerfile_path)
    if os.path.isfile(ctx):
        ctx = os.path.dirname(ctx) or "."
    tag = tag or f"screwhead-chal-{os.path.basename(os.path.normpath(get_workdir()))}".lower()
    r = _docker(["build", "-t", tag, ctx], timeout=600)
    r["tag"] = tag
    return r


def run_docker_stop(container_id) -> dict:
    """Stop + remove a container (id or name)."""
    return _docker(["stop", str(container_id)], timeout=40)


def run_docker_logs(container_id, tail=200) -> dict:
    return _docker(["logs", "--tail", str(tail), str(container_id)], timeout=30)


# ── Dispatcher ───────────────────────────────────────────────────

from media import analyze_media as _analyze_media, analyze_image_vision, MEDIA_TOOL_SCHEMAS

TOOL_DISPATCH = {
    "shell":        lambda args: run_shell(args["command"], args.get("workdir")),
    "http_request": lambda args: run_http_request(
        args["method"], args["url"],
        args.get("headers"), args.get("body"),
        args.get("follow_redirects", True),
    ),
    "sqlmap":       lambda args: run_sqlmap(
        args["url"], args.get("data"), args.get("level", 2), args.get("risk", 2),
        args.get("technique"), args.get("dump", True), args.get("extra"),
    ),
    "phantom":      lambda args: run_phantom(
        args.get("tool_name"), args.get("parameters"), args.get("list_tools", False), args.get("category"),
    ),
    "crack_hash":   lambda args: run_crack_hash(
        args["hash_value"], args.get("hash_type"), args.get("wordlist"),
    ),
    "rsa_attack":   lambda args: run_rsa_attack(
        args.get("n"), args.get("e"), args.get("c"), args.get("filepath"),
    ),
    "read_file":    lambda args: run_read_file(
        args["path"], args.get("binary", False), args.get("max_bytes", 32768),
    ),
    "write_file":   lambda args: run_write_file(
        args["path"], args["content"], args.get("binary", False),
    ),
    "codex":        lambda args: run_codex(
        args["prompt"], args.get("sandbox", "workspace-write"), args.get("model"),
    ),
    "cortex_search": lambda args: run_cortex_search(args["query"]),
    "submit_flag":  lambda args: run_submit_flag(args["flag"]),
    # Resolve relative media paths against THIS thread's workspace (media.py pins
    # WORKDIR at import time, so a bare relative path would hit the wrong dir).
    "analyze_media": lambda args: _analyze_media(_resolve_path(args["filepath"])),
    "vision_query":  lambda args: analyze_image_vision(_resolve_path(args["filepath"]), prompt=args["question"]),
    "docker_run":    lambda args: run_docker_run(args["image"], args.get("ports"),
                                                 args.get("env"), args.get("command"), args.get("name")),
    "docker_build":  lambda args: run_docker_build(args.get("dockerfile_path", "."), args.get("tag")),
    "docker_stop":   lambda args: run_docker_stop(args["container_id"]),
    "docker_logs":   lambda args: run_docker_logs(args["container_id"], args.get("tail", 200)),
}

DOCKER_TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "docker_run",
        "description": ("Pull + run a container detached (--rm). Use to spin up challenge "
                        "stacks/images, or to run challenge source. Returns container_id, "
                        "mapped ports, and initial logs."),
        "parameters": {"type": "object", "properties": {
            "image": {"type": "string", "description": "Image name/tag (e.g. 'ubuntu:22.04' or a locally-built tag)."},
            "ports": {"type": "array", "items": {"type": "string"},
                      "description": "Port maps like ['1337:1337']."},
            "env": {"type": "object", "description": "Env vars {KEY: value}."},
            "command": {"type": "string", "description": "Optional command to run in the container."},
            "name": {"type": "string", "description": "Optional container name."},
        }, "required": ["image"]}}},
    {"type": "function", "function": {
        "name": "docker_build",
        "description": "Build an image from a Dockerfile in the workspace. Returns build log + image tag.",
        "parameters": {"type": "object", "properties": {
            "dockerfile_path": {"type": "string", "description": "Dir or Dockerfile path (default: workspace root)."},
            "tag": {"type": "string", "description": "Optional image tag."},
        }, "required": []}}},
    {"type": "function", "function": {
        "name": "docker_stop",
        "description": "Stop and remove a running container by id or name.",
        "parameters": {"type": "object", "properties": {
            "container_id": {"type": "string"}}, "required": ["container_id"]}}},
    {"type": "function", "function": {
        "name": "docker_logs",
        "description": "Fetch stdout/stderr logs from a container.",
        "parameters": {"type": "object", "properties": {
            "container_id": {"type": "string"},
            "tail": {"type": "integer", "description": "Lines from the end (default 200)."},
        }, "required": ["container_id"]}}},
]
TOOL_SCHEMAS.extend(DOCKER_TOOL_SCHEMAS)

# Merge media tool schemas into the main list
TOOL_SCHEMAS.extend(MEDIA_TOOL_SCHEMAS)


def execute_tool(name: str, arguments: dict) -> dict:
    """Route a tool call to its implementation."""
    if name not in TOOL_DISPATCH:
        return {"status": "error", "stderr": f"Unknown tool: {name}"}
    return TOOL_DISPATCH[name](arguments)
