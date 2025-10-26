import os
from llama_index.core import VectorStoreIndex, Document
from utils.pdf import extract_pdf_text
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

def build_policy_indexes(state: dict) -> dict:
    """
    Build in-memory indexes for each provided policy PDF.
    """
    if state.get("policy_indexes") and state.get("policy_texts"):
        return state
    policy_paths = state.get("policy_paths", [])
    indexes = {}
    texts = {}

    for p in policy_paths:
        if not os.path.exists(p):
            continue
        text = extract_pdf_text(p)
        texts[p] = text
        idx = VectorStoreIndex.from_documents([Document(text=text, metadata={"source": p})])
        indexes[p] = idx

    state["policy_indexes"] = indexes
    state["policy_texts"] = texts
    return state

def select_policies(state: dict) -> dict:
    """
    If caller preselected policies, trust that selection.
    Otherwise, ask the LLM to pick up to max_k relevant documents.
    """
    # ---- NEW: honor manual selection ----
    pre = state.get("selected_policy_paths")
    if pre and isinstance(pre, list) and len(pre) >= 2:
        return state
    # -------------------------------------

    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    threat = state.get("threat", "")
    evidence_summary = state.get("evidence_summary", "")
    candidates = list(state.get("policy_texts", {}).keys())
    max_k = int(state.get("max_policy_choices", 2))

    selection_prompt = f"""Given this threat and evidence, pick up to {max_k} most relevant policy documents (by file path) to review first.
Return as a JSON array of strings (file paths), no commentary.

Threat:
{threat}

Evidence summary:
{evidence_summary}

Candidate policy files:
{candidates}
"""
    resp = llm.invoke([HumanMessage(content=selection_prompt)])
    try:
        chosen = json.loads(resp.content)
        if not isinstance(chosen, list):
            chosen = candidates[:max_k]
    except Exception:
        chosen = candidates[:max_k]

    state["selected_policy_paths"] = chosen[:max_k]
    return state


def read_policies(state: dict) -> dict:
    """
    Query the selected policy documents for controls related to accounts/auth/brute-force,
    and capture retrieved snippets with page/line metadata for verified citations later.
    """
    selected = state.get("selected_policy_paths", [])
    indexes = state.get("policy_indexes", {})
    llm_focus_q = (
        "As an IT auditor, list controls relevant to user accounts, authentication, "
        "password policy, lockout thresholds, monitoring/alerting, SSH/RDP hardening, and brute-force mitigation."
    )

    summaries = {}
    all_snippets = {}
    for p in selected:
        idx = indexes.get(p)
        if not idx:
            continue

        # ↑ a bit more recall; response_mode to ensure source_nodes is populated
        engine = idx.as_query_engine(similarity_top_k=10)
        resp = engine.query(llm_focus_q)
        summaries[p] = str(resp)

        # Primary: take source_nodes from the response
        snips = []
        for sn in getattr(resp, "source_nodes", []) or []:
            meta = getattr(sn.node, "metadata", {}) or {}
            snips.append({
                "source": meta.get("source"),
                "page": meta.get("page_label") or meta.get("page") or meta.get("page_number"),
                "line_start": meta.get("line_start"),
                "line_end": meta.get("line_end"),
                "text": (sn.node.text or ""),
            })

        # Fallback: if nothing came back, directly query the retriever by keywords
        if not snips:
            retr = idx.as_retriever(similarity_top_k=8)
            for q in ["password", "lockout", "failed attempt", "account", "SSH", "RDP", "review", "monitor"]:
                for n in retr.retrieve(q) or []:
                    meta = getattr(n.node, "metadata", {}) or {}
                    snips.append({
                        "source": meta.get("source"),
                        "page": meta.get("page_label") or meta.get("page") or meta.get("page_number"),
                        "line_start": meta.get("line_start"),
                        "line_end": meta.get("line_end"),
                        "text": (n.node.text or ""),
                    })
            # de-dup by (source,page,range)
            seen, uniq = set(), []
            for s in snips:
                k = (s["source"], s["page"], s["line_start"], s["line_end"])
                if k not in seen:
                    seen.add(k); uniq.append(s)
            snips = uniq

        all_snippets[p] = snips

    state["policy_control_summaries"] = summaries
    state["policy_snippets"] = all_snippets   # ← critical: expose to compare_policies
    return state
