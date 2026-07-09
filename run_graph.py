import os
import time

from graph import build_graph
from utils.pdf import extract_pdf_text
from utils.report_export import export_final_report_pdf

from typing import List
from llama_index.core import VectorStoreIndex, Document
from llama_index.core.schema import TextNode


def load_env_file(path: str = ".env") -> None:
    """Load simple KEY=VALUE pairs without adding a python-dotenv dependency."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def load_policy_docs_with_pages(pdf_path: str) -> List[Document]:
    from llama_index.readers.file import PyMuPDFReader

    reader = PyMuPDFReader()
    # version compatibility shim
    try:
        docs = reader.load(file_path=pdf_path)
    except TypeError:
        try:
            docs = reader.load_data(file_path=pdf_path)
        except TypeError:
            docs = reader.load_data(file=pdf_path)
    # ensure every page doc records the exact path (used later for key matching)
    for d in docs:
        d.metadata["source"] = pdf_path
    return docs

def make_line_window_nodes(docs: List[Document], window_chars: int = 600, overlap: int = 5) -> List[TextNode]:
    nodes: List[TextNode] = []
    for d in docs:
        page_label = d.metadata.get("page_label") or d.metadata.get("page") or d.metadata.get("page_number")
        src = d.metadata.get("source")
        lines = (d.text or "").splitlines()
        buf, start_ln, cur_len = [], 1, 0
        for i, line in enumerate(lines, start=1):
            seg = line + "\n"
            if cur_len + len(seg) > window_chars and buf:
                txt = "".join(buf).strip()
                if txt:
                    nodes.append(TextNode(
                        text=txt,
                        metadata={
                            "source": src,
                            "page_label": page_label,
                            "line_start": start_ln,
                            "line_end": i - 1,
                        }
                    ))
                keep = buf[-overlap:] if overlap < len(buf) else buf
                buf = keep.copy()
                start_ln = max(1, i - len(keep) + 1)
                cur_len = sum(len(x) for x in buf)
            buf.append(seg); cur_len += len(seg)
        if buf:
            txt = "".join(buf).strip()
            if txt:
                nodes.append(TextNode(
                    text=txt,
                    metadata={
                        "source": src,
                        "page_label": page_label,
                        "line_start": start_ln,
                        "line_end": len(lines),
                    }
                ))
    return nodes

def build_policy_index(pdf_path: str, embed_model=None) -> VectorStoreIndex:
    docs = load_policy_docs_with_pages(pdf_path)
    for d in docs:
        d.metadata["source"] = pdf_path
    nodes = make_line_window_nodes(docs, window_chars=600, overlap=5)
    return VectorStoreIndex(nodes, embed_model=embed_model)


def build_openai_embed_model(api_key: str):
    from llama_index.embeddings.openai import OpenAIEmbedding

    model = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")
    return OpenAIEmbedding(api_key=api_key, model=model)

APN_PATH = "policy/APN User Account Policy.pdf" 
CIS_PATH = "policy/CIS_Controls_v8.1_Account.pdf"

if __name__ == "__main__":
    load_env_file()
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment.")
    use_vector_indexes = os.getenv("USE_VECTOR_INDEXES", "").lower() in {"1", "true", "yes"}
    embed_model = build_openai_embed_model(openai_key) if use_vector_indexes else None

    policy_paths = [CIS_PATH, APN_PATH]

    prebuilt_indexes, prebuilt_texts = {}, {}
    for p in policy_paths:
        if not os.path.exists(p):
            print(f"[run_graph] WARN: policy file not found: {p}")
            continue
        prebuilt_texts[p] = extract_pdf_text(p) or ""
        if use_vector_indexes:
            try:
                idx = build_policy_index(p, embed_model=embed_model)
                prebuilt_indexes[p] = idx
            except Exception as e:
                print(f"[run_graph] WARN: vector index failed for {p}: {e}")
                print("[run_graph] WARN: continuing with keyword snippet fallback.")

    print("[DEBUG/run_graph] indexed keys:", list(prebuilt_indexes.keys()))
    print("[DEBUG/run_graph] APN text chars:", len(prebuilt_texts.get(APN_PATH, "")))

    initial_state = {
        "threat": "Repeated failed Windows logon attempts via OpenSSH (Event ID 4625) indicating potential brute-force.",
        "log_csv_glob": "logs/*.csv",
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

    # ----- Print ONLY the gaps after evidence analysis, with linkage -----
    print("\n=== GAPS VERIFIED AGAINST EVIDENCE ===\n")
    gaps_link = final_state.get("gaps_evidence_link")
    print(gaps_link or "No gap→evidence linkage produced.")

    # Optional: quick view of what snippets were captured
    snips = final_state.get("policy_snippets", {})
    for k, v in (snips or {}).items():
        print(f"[DEBUG] snippets for {k}: {len(v)}")
        if v:
            print(f"        first: page={v[0]['page']} lines={v[0]['line_start']}-{v[0]['line_end']}")

    # Optional: show per-gap line numbers
    gaps_struct = final_state.get("policy_gaps_structured", [])
    baseline = final_state.get("baseline_policy", "Policy A")
    target = final_state.get("target_policy", "Policy B")
    if gaps_struct:
        print("\n--- Policy Line Citations (per gap) ---\n")
        for g in gaps_struct:
            gap = g.get("gap", "(gap)")
            pa = g.get("refs", {}).get("policy_a", [])
            pb = g.get("refs", {}).get("policy_b", [])
            pa_ranges = [tuple(ref.get("line_numbers") or []) for ref in pa]
            pb_ranges = [tuple(ref.get("line_numbers") or []) for ref in pb]
            print(f"* {gap}")
            print(f"  - {baseline} ranges: {pa_ranges or 'n/a'}")
            print(f"  - {target}  ranges: {pb_ranges or 'missing'}")

    print("\n=== FINAL REPORT ===\n")
    print(final_state.get("final_report", "No report produced."))

    os.makedirs("outputs", exist_ok=True)
    pdf_path = export_final_report_pdf(
        final_state,
        outfile="outputs/final_report.pdf",
        meta={
            "title": "Company Policy Analysis",
            "author": "<Insert Author Name>",
            "org": "APN Company",
            "run_id": os.getenv("RUN_ID", ""),
        },
    )
    print(f"\n[OK] PDF written to: {pdf_path}")
