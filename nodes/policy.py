import json
import os
from llama_index.core import VectorStoreIndex, Document
from utils.pdf import extract_pdf_text
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage


def _policy_focus_query(threat: str) -> str:
    t = (threat or "").lower()
    if "powershell" in t or "t1059.001" in t or "listener" in t:
        return (
            "As an IT auditor, list controls relevant to PowerShell execution, network monitoring, "
            "logging and alerting, suspicious listeners or exposed ports, remote administration, "
            "and retention of monitoring records."
        )
    return (
        "As an IT auditor investigating repeated failed OpenSSH logons and possible brute force, "
        "retrieve controls for account lockout thresholds, repeated failed authentication attempts, "
        "monitoring and alerting on account activity, SSH/RDP hardening, MFA for privileged accounts, "
        "and brute-force mitigation. Prioritize incident-relevant controls over generic password ageing or complexity."
    )


def _keyword_list(threat: str):
    t = (threat or "").lower()
    if "powershell" in t or "t1059.001" in t or "listener" in t:
        return [
            "powershell", "network", "monitor", "listener", "port", "logging",
            "alert", "remote administration", "service", "firewall", "retain"
        ]
    return ["password", "lockout", "failed", "attempt", "account", "authentication", "ssh", "rdp", "monitor"]

def build_policy_indexes(state: dict) -> dict:
    """
    Build in-memory indexes for each provided policy PDF.
    """
    if state.get("skip_policy_index_build"):
        return state

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


def keyword_policy_snippets(policy_path: str, text: str, keywords=None, window: int = 3, max_snips: int = 10):
    """
    Deterministic fallback when vector embeddings are unavailable.
    Returns line-window snippets with the same metadata shape as LlamaIndex snippets.
    """
    if keywords is None:
        keywords = ["password", "lockout", "failed", "attempt", "account", "authentication", "ssh", "rdp", "monitor"]

    lines = (text or "").splitlines()
    hits = []
    for i, line in enumerate(lines):
        lower = line.lower()
        if any(k in lower for k in keywords):
            start = max(0, i - window)
            end = min(len(lines), i + window + 1)
            snippet_text = "\n".join(lines[start:end]).strip()
            if snippet_text:
                hits.append({
                    "source": policy_path,
                    "page": None,
                    "line_start": start + 1,
                    "line_end": end,
                    "text": snippet_text,
                })

    seen, uniq = set(), []
    for s in hits:
        key = (s["source"], s["line_start"], s["line_end"], s["text"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq[:max_snips]

def select_policies(state: dict) -> dict:
    """
    If caller preselected policies, trust that selection.
    Otherwise, ask the LLM to pick up to max_k relevant documents.
    """

    pre = state.get("selected_policy_paths")
    if pre and isinstance(pre, list) and len(pre) >= 2:
        return state

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
    policy_texts = state.get("policy_texts", {})
    threat = state.get("threat", "")
    llm_focus_q = _policy_focus_query(threat)
    fallback_keywords = _keyword_list(threat)

    summaries = {}
    all_snippets = {}
    for p in selected:
        idx = indexes.get(p)
        if not idx:
            text = policy_texts.get(p, "")
            summaries[p] = text[:1500] if text else "No policy text available."
            all_snippets[p] = keyword_policy_snippets(p, text, keywords=fallback_keywords)
            continue

        snips = []
        retr = idx.as_retriever(similarity_top_k=10)
        for n in retr.retrieve(llm_focus_q) or []:
            meta = getattr(n.node, "metadata", {}) or {}
            snips.append({
                "source": meta.get("source"),
                "page": meta.get("page_label") or meta.get("page") or meta.get("page_number"),
                "line_start": meta.get("line_start"),
                "line_end": meta.get("line_end"),
                "text": (n.node.text or ""),
            })

        # Hybridize semantic retrieval with deterministic keyword windows so short
        # target policies do not lose line-window support for obvious clauses.
        text = policy_texts.get(p, "")
        snips.extend(keyword_policy_snippets(p, text, keywords=fallback_keywords))

        # Fallback: if nothing came back, directly query the vector retriever by keywords.
        if not snips:
            for q in fallback_keywords:
                for n in retr.retrieve(q) or []:
                    meta = getattr(n.node, "metadata", {}) or {}
                    snips.append({
                        "source": meta.get("source"),
                        "page": meta.get("page_label") or meta.get("page") or meta.get("page_number"),
                        "line_start": meta.get("line_start"),
                        "line_end": meta.get("line_end"),
                        "text": (n.node.text or ""),
                    })
        # De-dup by source/page/range/text while preserving vector-first ordering.
        seen, uniq = set(), []
        for s in snips:
            k = (s.get("source"), s.get("page"), s.get("line_start"), s.get("line_end"), s.get("text"))
            if k not in seen:
                seen.add(k)
                uniq.append(s)
        snips = uniq[:12]

        summaries[p] = "\n\n".join(s.get("text", "") for s in snips if s.get("text"))[:1500]
        all_snippets[p] = snips

    state["policy_control_summaries"] = summaries
    state["policy_snippets"] = all_snippets   # ← critical: expose to compare_policies
    return state
