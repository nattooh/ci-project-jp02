import glob
from collections import Counter
from pathlib import Path

import pandas as pd

from nodes.policy import keyword_policy_snippets
from utils.pdf import extract_pdf_text


ROOT = Path(__file__).resolve().parent
LOG_GLOB = str(ROOT / "logs" / "*.csv")
POLICIES = [
    ROOT / "policy" / "CIS_Controls_v8.1_Account.pdf",
    ROOT / "policy" / "APN User Account Policy.pdf",
]
KEYWORDS = ["password", "lockout", "failed", "attempt", "account", "authentication", "ssh", "monitor"]


def load_logs() -> pd.DataFrame:
    frames = []
    for path in glob.glob(LOG_GLOB):
        df = pd.read_csv(path)
        df["__source_file"] = path
        frames.append(df)
    if not frames:
        raise RuntimeError("No CSV logs found.")
    return pd.concat(frames, ignore_index=True)


def summarize_logs(df: pd.DataFrame) -> dict:
    event_ids = Counter(df.get("EventID", pd.Series(dtype="object")).dropna().astype(str))
    failed = df[df.get("EventID", "").astype(str) == "4625"].copy()
    success = df[df.get("EventID", "").astype(str) == "4624"].copy()

    target_counts = {}
    if "TargetUserName" in failed.columns:
        target_counts = failed["TargetUserName"].fillna("-").value_counts().to_dict()

    timestamps = []
    if "TimeCreated_SystemTime" in failed.columns:
        timestamps = failed["TimeCreated_SystemTime"].dropna().astype(str).tolist()

    return {
        "event_ids": dict(event_ids),
        "failed_count": len(failed),
        "success_count": len(success),
        "target_counts": target_counts,
        "failed_timestamps": timestamps,
    }


def infer_threat(summary: dict) -> str:
    if summary["failed_count"] >= 3:
        return "Potential brute-force authentication activity based on repeated Event ID 4625 failures."
    return "No strong brute-force indicator found from simple keyword baseline."


def retrieve_policy_snippets() -> dict:
    out = {}
    for policy_path in POLICIES:
        text = extract_pdf_text(str(policy_path))
        out[str(policy_path)] = keyword_policy_snippets(str(policy_path), text, keywords=KEYWORDS)
    return out


def print_report(summary: dict, threat: str, snippets: dict) -> None:
    print("=== KEYWORD BASELINE REPORT ===\n")
    print("Threat Assessment:")
    print(threat)
    print()

    print("Evidence Summary:")
    print(f"- Event counts: {summary['event_ids']}")
    print(f"- Failed logons (4625): {summary['failed_count']}")
    print(f"- Successful logons (4624): {summary['success_count']}")
    print(f"- Target accounts: {summary['target_counts']}")
    if summary["failed_timestamps"]:
        first_ts = summary["failed_timestamps"][0]
        last_ts = summary["failed_timestamps"][-1]
        print(f"- Failed-attempt window: {first_ts} to {last_ts}")
    print()

    print("Policy Retrieval:")
    for policy_path, policy_snips in snippets.items():
        print(f"- {Path(policy_path).name}: {len(policy_snips)} keyword hit windows")
        for snip in policy_snips[:3]:
            print(
                f"  lines {snip['line_start']}-{snip['line_end']}: "
                f"{snip['text'].replace(chr(10), ' ')[:180]}"
            )
    print()

    print("Baseline Notes:")
    print("- This baseline uses deterministic keyword matching only.")
    print("- It does not perform LLM-based reasoning, policy comparison, or evidence-to-gap validation.")


def main() -> int:
    df = load_logs()
    summary = summarize_logs(df)
    threat = infer_threat(summary)
    snippets = retrieve_policy_snippets()
    print_report(summary, threat, snippets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
