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
