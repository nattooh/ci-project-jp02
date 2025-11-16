import glob
import pandas as pd
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

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
        # Build concise string for LLM (truncated if huge)
        cols = all_df.columns.tolist()
        rows = []
        for i, row in all_df.head(500).iterrows():  # cap for token safety
            rows.append("; ".join([f"{c}={row.get(c, '')}" for c in cols]))
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
    required = []

    # very lightweight heuristics; you can expand later
    if "4625" in evidence or "failed logon" in evidence or "brute force" in evidence or "t1110" in evidence:
        required.extend([
            {"control": "Account lockout policy", "rationale": "Mitigate repeated invalid logons"},
            {"control": "SSH rate limiting / fail2ban", "rationale": "Throttle repeated auth attempts on OpenSSH"},
            {"control": "Alerting on repeated failures", "rationale": "SOC visibility of brute-force attempts"},
            {"control": "MFA for privileged accounts", "rationale": "Reduce impact of guessed credentials"},
        ])

    # De-dup & store
    dedup = {r["control"]: r for r in required}
    state["required_controls_from_evidence"] = list(dedup.values())
    return state
