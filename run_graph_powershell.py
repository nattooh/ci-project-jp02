import csv
import json
import os
import time
from pathlib import Path

from graph import build_graph
from run_graph import load_env_file, build_openai_embed_model, build_policy_index
from utils.pdf import extract_pdf_text
from utils.report_export import export_final_report_pdf


ROOT = Path(__file__).resolve().parent
SOURCE_JSON = ROOT / "psh_powershell_httplistener_2020-11-0204130683.json"
CSV_DIR = ROOT / "logs_powershell"
CSV_PATH = CSV_DIR / "powershell_http_listener.csv"

APN_PATH = "policy/APN Network Monitoring Policy.pdf"
CIS_PATH = "policy/CIS_Controls_Network_Monitoring.pdf"


def convert_jsonl_to_csv(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "row_id",
        "EventID",
        "TimeCreated",
        "@timestamp",
        "UtcTime",
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
    ]

    with src.open("r", encoding="utf-8") as fin, dst.open("w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        for row_id, line in enumerate(fin, start=1):
            obj = json.loads(line)
            writer.writerow({
                "row_id": row_id,
                "EventID": obj.get("EventID"),
                "TimeCreated": obj.get("TimeCreated"),
                "@timestamp": obj.get("@timestamp"),
                "UtcTime": obj.get("UtcTime"),
                "Hostname": obj.get("Hostname"),
                "Channel": obj.get("Channel"),
                "SourceName": obj.get("SourceName"),
                "Image": obj.get("Image"),
                "SourceImage": obj.get("SourceImage"),
                "TargetImage": obj.get("TargetImage"),
                "Application": obj.get("Application"),
                "ProcessId": obj.get("ProcessId"),
                "SourceProcessId": obj.get("SourceProcessId"),
                "TargetProcessId": obj.get("TargetProcessId"),
                "SourcePort": obj.get("SourcePort"),
                "DestPort": obj.get("DestPort"),
                "SourceAddress": obj.get("SourceAddress"),
                "DestAddress": obj.get("DestAddress"),
                "TargetObject": obj.get("TargetObject"),
                "Message": (obj.get("Message") or "").replace("\r", " ").replace("\n", " "),
            })
    return dst


if __name__ == "__main__":
    load_env_file()
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment.")
    if not SOURCE_JSON.exists():
        raise RuntimeError(f"PowerShell source JSON not found: {SOURCE_JSON}")

    use_vector_indexes = os.getenv("USE_VECTOR_INDEXES", "").lower() in {"1", "true", "yes"}
    embed_model = build_openai_embed_model(openai_key) if use_vector_indexes else None

    csv_path = convert_jsonl_to_csv(SOURCE_JSON, CSV_PATH)
    policy_paths = [CIS_PATH, APN_PATH]

    prebuilt_indexes, prebuilt_texts = {}, {}
    for p in policy_paths:
        if not os.path.exists(p):
            print(f"[run_graph_powershell] WARN: policy file not found: {p}")
            continue
        prebuilt_texts[p] = extract_pdf_text(p) or ""
        if use_vector_indexes:
            try:
                idx = build_policy_index(p, embed_model=embed_model)
                prebuilt_indexes[p] = idx
            except Exception as e:
                print(f"[run_graph_powershell] WARN: vector index failed for {p}: {e}")
                print("[run_graph_powershell] WARN: continuing with keyword snippet fallback.")

    initial_state = {
        "threat": "Suspicious PowerShell-based execution with HTTP listener behaviour on a Windows host (MITRE ATT&CK T1059.001), including a listener observed on TCP port 8000.",
        "log_csv_glob": str(csv_path),
        "policy_paths": policy_paths,
        "policy_indexes": prebuilt_indexes,
        "policy_texts": prebuilt_texts,
        "skip_policy_index_build": True,
        "selected_policy_paths": [CIS_PATH, APN_PATH],
        "max_policy_choices": 2,
    }

    graph = build_graph()
    started = time.perf_counter()
    final_state = graph.invoke(initial_state)
    elapsed_seconds = time.perf_counter() - started
    final_state["elapsed_seconds"] = elapsed_seconds
    print(f"[METRIC] elapsed_seconds={elapsed_seconds:.3f}")

    print("\n=== GAPS VERIFIED AGAINST EVIDENCE (POWERSHELL CASE) ===\n")
    print(final_state.get("gaps_evidence_link") or "No gap→evidence linkage produced.")

    print("\n=== FINAL REPORT (POWERSHELL CASE) ===\n")
    print(final_state.get("final_report", "No report produced."))

    out_dir = ROOT / "outputs" / "powershell_case"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = export_final_report_pdf(
        final_state,
        outfile=str(out_dir / "final_report_powershell.pdf"),
        meta={
            "title": "PowerShell Network Monitoring Analysis",
            "author": "<Insert Author Name>",
            "org": "APN Company",
            "run_id": os.getenv("RUN_ID", ""),
        },
    )
    print(f"\n[OK] CSV written to: {csv_path}")
    print(f"[OK] PDF written to: {pdf_path}")
