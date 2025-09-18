# actions/mac_logs.py — macOS login/auth log retrieval + quick summary
import subprocess, shlex, datetime as dt
from typing import Optional, Dict, Any

def _run(cmd: str) -> str:
    p = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"Command failed: {cmd}")
    return p.stdout

def _build_time_flags(since: Optional[str], until: Optional[str]) -> str:
    """
    Accepts 'YYYY-MM-DD' (or None). Returns --start/--end flags for `log show`.
    """
    flags = []
    if since:
        flags.append(f"--start {since}")
    if until:
        # Add a small day offset to include the end day
        flags.append(f"--end {until} 23:59:59")
    return " ".join(flags)

def action_mac_login_logs(since: Optional[str] = None, until: Optional[str] = None, limit: int = 5000) -> Dict[str, Any]:
    """
    Pulls macOS Unified Log entries related to login/auth and summarizes.
    - since/until: 'YYYY-MM-DD' (optional)
    - limit: max lines to scan (approx via --predicate + --info + greps)

    Returns: {"summary": "...", "lines": [...], "counts": {...}}
    """
    time_flags = _build_time_flags(since, until)
    # Predicates target common auth components: loginwindow, authd, opendirectoryd, securityd, AppleIDAuthAgent
    predicate = r'(process == "loginwindow") || (process == "authd") || (process == "opendirectoryd") || (process == "securityd") || (process == "apsd") || (subsystem == "com.apple.Authorization")'

    #currently takes in the system logs, need to add to get dataset logs
    cmd = f'log show --style syslog --predicate \'{predicate}\' {time_flags} --info --debug --last 14d'
    # If since/until provided, we still leave a safety --last window; log picks earliest of start/last
    out = _run(cmd)

    # Light grep-like filtering for keywords
    keyphrases = [
        "Failed password", "authentication failure", "Invalid user", "LAError", "accepted", "success",
        "unlock", "login", "Logged in", "pam", "Denied", "policy", "AppleIDAuth", "authd"
    ]
    lines = []
    counts = {k: 0 for k in keyphrases}
    for i, line in enumerate(out.splitlines()):
        if len(lines) >= limit:
            break
        low = line.lower()
        matched = False
        for k in keyphrases:
            if k.lower() in low:
                counts[k] += 1
                matched = True
        if matched:
            lines.append(line)

    # Quick-and-dirty summary
    suspicious = counts["Failed password"] + counts["authentication failure"] + counts["Invalid user"] + counts["Denied"]
    successes = counts["accepted"] + counts["success"] + counts["Logged in"]
    summary = (
        f"Scanned ~{min(limit, len(out.splitlines()))} lines; "
        f"matched {len(lines)} auth-related lines. "
        f"Suspected failures: {suspicious}. Successful logins: {successes}."
    )
    return {"summary": summary, "counts": counts, "lines": lines[:limit]}
