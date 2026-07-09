import glob
import pandas as pd
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage


def _is_powershell_scenario(threat: str) -> bool:
    t = (threat or "").lower()
    return "powershell" in t or "t1059.001" in t or "listener" in t


def _compact_cell(value, limit: int = 180) -> str:
    if pd.isna(value):
        return ""
    text = str(value).strip().replace("\r", " ").replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _select_log_columns(df: pd.DataFrame, threat: str) -> list[str]:
    if _is_powershell_scenario(threat):
        preferred = [
            "row_id",
            "EventID",
            "TimeCreated",
            "@timestamp",
            "Hostname",
            "Channel",
            "SourceName",
            "Image",
            "SourceImage",
            "TargetImage",
            "Application",
            "ProcessId",
            "SourceProcessId",
            "TargetProcessId",
            "SourcePort",
            "DestPort",
            "SourceAddress",
            "DestAddress",
            "TargetObject",
            "Message",
            "__source_file",
        ]
    else:
        preferred = [
            "row_id",
            "EventID",
            "TimeCreated",
            "@timestamp",
            "Hostname",
            "Channel",
            "SourceName",
            "TargetUserName",
            "TargetDomainName",
            "IpAddress",
            "IpPort",
            "LogonType",
            "ProcessName",
            "Message",
            "__source_file",
        ]
    return [c for c in preferred if c in df.columns]


def _select_context_rows(df: pd.DataFrame, threat: str) -> pd.DataFrame:
    if not _is_powershell_scenario(threat):
        return df.head(200)

    work = df.copy()
    def _contains(col: str, pattern: str) -> pd.Series:
        if col not in work.columns:
            return pd.Series(False, index=work.index)
        return work[col].fillna("").astype(str).str.contains(pattern, case=False, regex=True)

    powershell_mask = (
        _contains("Image", r"powershell") |
        _contains("SourceImage", r"powershell") |
        _contains("TargetImage", r"powershell") |
        _contains("Application", r"powershell") |
        _contains("Message", r"powershell")
    )
    listener_mask = (
        _contains("Message", r"listen|bind to a local port|port 8000") |
        _contains("Application", r"system") |
        _contains("TargetObject", r"tcpip")
    )
    audit_mask = _contains("Message", r"audit log was cleared")

    port_mask = pd.Series(False, index=work.index)
    for c in ["SourcePort", "DestPort"]:
        if c in work.columns:
            port_mask = port_mask | (pd.to_numeric(work[c], errors="coerce") == 8000)

    event_mask = pd.Series(False, index=work.index)
    if "EventID" in work.columns:
        event_mask = work["EventID"].isin([1102, 5154, 5156, 5158, 22, 7, 12, 13])

    filtered = work[audit_mask | port_mask | (event_mask & (powershell_mask | listener_mask)) | powershell_mask].copy()
    if filtered.empty:
        return work.head(40)

    priority = pd.Series(0, index=filtered.index, dtype="int64")
    priority = priority + audit_mask.reindex(filtered.index, fill_value=False).astype(int) * 5
    priority = priority + port_mask.reindex(filtered.index, fill_value=False).astype(int) * 6
    priority = priority + powershell_mask.reindex(filtered.index, fill_value=False).astype(int) * 4
    priority = priority + listener_mask.reindex(filtered.index, fill_value=False).astype(int) * 3
    if "EventID" in filtered.columns:
        priority = priority + filtered["EventID"].isin([5154, 5158, 1102]).astype(int) * 2
    filtered["_priority"] = priority

    dedup_subset = [c for c in [
        "EventID",
        "Image",
        "SourceImage",
        "TargetImage",
        "Application",
        "SourcePort",
        "DestPort",
        "TargetObject",
        "Message",
    ] if c in filtered.columns]
    if dedup_subset:
        filtered = filtered.drop_duplicates(subset=dedup_subset)

    time_col = next((c for c in ["TimeCreated", "@timestamp", "UtcTime"] if c in filtered.columns), None)
    if time_col:
        filtered = filtered.sort_values(by=["_priority", time_col], ascending=[False, True], kind="stable")
    else:
        filtered = filtered.sort_values(by="_priority", ascending=False, kind="stable")

    return filtered.head(18)

def plan_evidence(state: dict) -> dict:
    """
    Decide which evidence to load based on 'threat'.
    For now we assume CSV Windows Event logs are present in logs/*.csv
    """
    threat = state.get("threat", "")
    state["evidence_plan"] = {
        "need_windows_logs": "windows" in threat.lower() or "4625" in threat,
        "log_csv_glob": state.get("log_csv_glob", "logs/*.csv"),
    }
    return state

def load_logs(state: dict) -> dict:
    """
    Load CSV logs into a dataframe and also stringify for LLM context.
    """
    plan = state.get("evidence_plan", {})
    csv_glob = plan.get("log_csv_glob", "logs/*.csv")
    paths = glob.glob(csv_glob)
    frames = []
    for p in paths:
        try:
            df = pd.read_csv(p)
            df["__source_file"] = p
            frames.append(df)
        except Exception as e:
            print(f"[load_logs] Failed to read {p}: {e}")

    if frames:
        all_df = pd.concat(frames, ignore_index=True)
        state["logs_df"] = all_df
        threat = state.get("threat", "")
        context_df = _select_context_rows(all_df, threat)
        cols = _select_log_columns(context_df, threat) or context_df.columns.tolist()
        rows = []
        for _, row in context_df.iterrows():
            parts = []
            for c in cols:
                cell = _compact_cell(row.get(c, ""), limit=240 if c == "Message" else 120)
                if cell:
                    parts.append(f"{c}={cell}")
            if parts:
                rows.append("; ".join(parts))
        state["logs_text"] = "\n".join(rows)
    else:
        state["logs_df"] = None
        state["logs_text"] = "NO_LOGS_FOUND"

    return state

def analyze_evidence(state: dict) -> dict:
    """
    Have the LLM summarize key indicators from logs (failed logons, IPs, timestamps, accounts).
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    threat = state.get("threat", "")
    if _is_powershell_scenario(threat):
        prompt = f"""You are a cyber analyst. Summarize indicators from the Windows telemetry for a suspected PowerShell-based execution scenario.
Focus on:
- PowerShell-related process activity, process images, hostnames, ports, and timestamps
- Signs of listening services, unexpected exposed ports, suspicious script execution, or log tampering
- Support the summary with specific rows/fields you see

Logs (truncated to 500 rows):
{state.get('logs_text', 'NO_LOGS_FOUND')}
"""
    else:
        prompt = f"""You are a cyber analyst. Summarize indicators from the Windows/OpenSSH logs.
Focus on:
- Event IDs (e.g., 4625), timestamps, source IPs, target accounts
- Count of failures per IP/account, any lockouts, and brute-force indicators
- Support the summary with specific rows/fields you see

Logs (truncated to 500 rows):
{state.get('logs_text', 'NO_LOGS_FOUND')}
"""
    resp = llm.invoke([HumanMessage(content=prompt)])
    state["evidence_summary"] = resp.content
    return state

def derive_required_controls(state: dict) -> dict:
    """
    Map observed indicators (from evidence_summary) to control requirements.
    E.g., for brute-force patterns (4625 bursts -> 4624), we expect lockout policy,
    SSH rate limit/fail2ban, MFA for privileged accounts, alerting on repeated failures, etc.
    Returns a normalized list so compare_policies can filter gaps by evidence.
    """
    evidence = (state.get("evidence_summary") or "").lower()
    threat = (state.get("threat") or "").lower()
    required = []

    # very lightweight heuristics; you can expand later
    if "4625" in evidence or "failed logon" in evidence or "brute force" in evidence or "t1110" in evidence:
        required.extend([
            {"control": "Account lockout policy", "rationale": "Mitigate repeated invalid logons"},
            {"control": "SSH rate limiting / fail2ban", "rationale": "Throttle repeated auth attempts on OpenSSH"},
            {"control": "Alerting on repeated failures", "rationale": "SOC visibility of brute-force attempts"},
            {"control": "MFA for privileged accounts", "rationale": "Reduce impact of guessed credentials"},
        ])

    if _is_powershell_scenario(threat) or "powershell" in evidence or "listener" in evidence or "port 8000" in evidence:
        required.extend([
            {"control": "Network monitoring and alerting", "rationale": "Detect unauthorized listeners and suspicious exposed ports"},
            {"control": "PowerShell logging", "rationale": "Preserve visibility into suspicious script execution"},
            {"control": "Approval for internet-facing or persistent listeners", "rationale": "Prevent unauthorized service exposure"},
            {"control": "Retention of monitoring records", "rationale": "Support investigation and post-incident review"},
        ])

    # De-dup & store
    dedup = {r["control"]: r for r in required}
    state["required_controls_from_evidence"] = list(dedup.values())
    return state
