import os

from graph import build_graph
from utils.pdf import extract_pdf_text
from llama_index.llms.openai import OpenAI

from typing import List
from llama_index.core import VectorStoreIndex, Document
from llama_index.readers.file import PyMuPDFReader
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import TextNode

from utils.pdf import extract_pdf_text
from llama_index.llms.openai import OpenAI


def load_policy_docs_with_pages(pdf_path: str) -> List[Document]:
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

def build_policy_index(pdf_path: str, llm=None) -> VectorStoreIndex:
    docs = load_policy_docs_with_pages(pdf_path)
    # ensure the 'source' is EXACT path
    for d in docs:
        d.metadata["source"] = pdf_path
    nodes = make_line_window_nodes(docs, window_chars=600, overlap=5)
    return VectorStoreIndex(nodes, llm=llm)



def make_line_window_nodes(docs: List[Document], window_chars: int = 400, overlap: int = 60) -> List[TextNode]:
    """
    Split each page's text into small windows and record approximate line ranges.
    We approximate line numbers by splitting on '\n'; good enough for citations.
    """
    nodes: List[TextNode] = []
    for d in docs:
        page_text = d.text or ""
        lines = page_text.splitlines()  # keep "line" notion
        # Rebuild windows while tracking line ranges
        buf, start_ln = [], 1
        cur_len = 0
        for i, line in enumerate(lines, start=1):
            seg = (line + "\n")
            if cur_len + len(seg) > window_chars and buf:
                txt = "".join(buf).strip()
                if txt:
                    n = TextNode(text=txt, metadata={
                        **d.metadata,
                        "line_start": start_ln,
                        "line_end": i-1,
                    })
                    nodes.append(n)
                # start new window with overlap: keep last few lines
                overlap_lines = buf[-overlap:] if overlap < len(buf) else buf
                buf = overlap_lines.copy()
                start_ln = max(1, i - len(overlap_lines) + 1)
                cur_len = sum(len(x) for x in buf)

            buf.append(seg)
            cur_len += len(seg)

        # flush
        if buf:
            txt = "".join(buf).strip()
            if txt:
                n = TextNode(text=txt, metadata={
                    **d.metadata,
                    "line_start": start_ln,
                    "line_end": len(lines),
                })
                nodes.append(n)
    return nodes



# Use the exact path of your uploaded Pan policy
PAN_PATH = "policy/Pan User Account Policy.pdf"  
CIS_PATH = "policy/CIS_Controls_v8.1_Account.pdf"

if __name__ == "__main__":
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment.")
    llm = OpenAI(api_key=openai_key, model="gpt-4o-mini")

    policy_paths = [CIS_PATH, PAN_PATH]

    # PREBUILD: page/line-aware indexes + full texts under the SAME keys we'll reference later
    prebuilt_indexes, prebuilt_texts = {}, {}
    for p in policy_paths:
        if not os.path.exists(p):
            print(f"[run_graph] WARN: policy file not found: {p}")
            continue
        prebuilt_texts[p] = extract_pdf_text(p) or ""
        idx = build_policy_index(p, llm=llm)
        prebuilt_indexes[p] = idx

    print("[DEBUG/run_graph] indexed keys:", list(prebuilt_indexes.keys()))
    print("[DEBUG/run_graph] Pan text chars:", len(prebuilt_texts.get(PAN_PATH, "")))

    initial_state = {
        "threat": "Repeated failed Windows logon attempts via OpenSSH (Event ID 4625) indicating potential brute-force.",
        "log_csv_glob": "logs/*.csv",
        "policy_paths": policy_paths,

        # supply prebuilt assets so nodes/policy.build_policy_indexes is a no-op
        "policy_indexes": prebuilt_indexes,
        "policy_texts": prebuilt_texts,

        # Force CIS vs Pan for this run (exact same strings as above)
        "selected_policy_paths": [CIS_PATH, PAN_PATH],

        "max_policy_choices": 2,
    }

    graph = build_graph()
    final_state = graph.invoke(initial_state)

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
