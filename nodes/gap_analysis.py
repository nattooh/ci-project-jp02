from __future__ import annotations

import json
import difflib
from typing import Dict, List, Tuple, Any, Optional
import re

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage



def number_lines(text: str) -> List[Tuple[int, str]]:
    """
    Split text into lines and return list of (1-based line_number, line_text).
    Empty lines are preserved and count towards numbering.
    """
    lines = text.splitlines()
    return [(i + 1, lines[i]) for i in range(len(lines))]


def build_numbered_policy_cache(state: dict) -> None:
    """
    Expect state["policy_texts"] = { "<path or key>": "<full_policy_text>" }.
    Build numbered cache: state["_numbered_policies"] = { key: [(ln, txt), ...] }.
    Non-destructive if already present.
    """
    if "_numbered_policies" in state:
        return

    policy_texts: Dict[str, str] = state.get("policy_texts", {}) or {}
    numbered = {}
    for key, text in policy_texts.items():
        numbered[key] = number_lines(text or "")
    state["_numbered_policies"] = numbered


def find_best_line_numbers(
    numbered_lines: List[Tuple[int, str]],
    quote: str,
    max_fuzzy_candidates: int = 3,
    cutoff: float = 0.80,
) -> List[int]:
    """
    Try exact containment first; if not found, use fuzzy line matching to locate likely lines.

    Returns a (possibly multi-line) list of 1-based line numbers.
    """
    if not quote:
        return []

    quote_norm = " ".join(quote.split())  # normalize spaces
    hits = []

    # Exact containment search
    for ln, txt in numbered_lines:
        if quote_norm in " ".join(txt.split()):
            hits.append(ln)

    if hits:
        return hits

    # Fuzzy line matching fallback (per-line)
    candidates = difflib.get_close_matches(
        quote_norm,
        [" ".join(t.split()) for _, t in numbered_lines],
        n=max_fuzzy_candidates,
        cutoff=cutoff,
    )
    if not candidates:
        return []

    # Map back to line numbers
    ln_hits = []
    normalized_map = { " ".join(t.split()): ln for ln, t in numbered_lines }
    for c in candidates:
        ln = normalized_map.get(c)
        if ln:
            ln_hits.append(ln)
    return ln_hits


def normalize_llm_json(text: str) -> Any:
    """
    Extract first valid JSON object/array from the LLM response.
    """
    text = text.strip()
    # Fast path: already JSON
    try:
        return json.loads(text)
    except Exception:
        pass

    # Heuristic: find the first '{' or '[' and last '}' or ']'
    start_brace = text.find("{")
    start_brack = text.find("[")
    start = min(x for x in [start_brace, start_brack] if x != -1) if (start_brace != -1 or start_brack != -1) else -1
    if start == -1:
        raise ValueError("No JSON found in LLM output")

    # Try progressively trimming to last closing brace/bracket
    for end in range(len(text), start, -1):
        snippet = text[start:end]
        try:
            return json.loads(snippet)
        except Exception:
            continue
    raise ValueError("Could not parse JSON from LLM output")


# ----------------------------
# Core steps
# ----------------------------

def compare_policies(state: dict) -> dict:
    """
    Compare CIS vs Pan (if present), else compare any two selected policies.
    Prefer verified snippet-based comparison (with page/line citations).
    Fall back to summary-based comparison + line-hint mapping if snippets are missing.
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)

    summaries: Dict[str, str] = state.get("policy_control_summaries", {}) or {}
    snippets: Dict[str, List[Dict[str, Any]]] = state.get("policy_snippets", {}) or {}
    selected: List[str] = state.get("selected_policy_paths", []) or []



    # Prefer auto-detect CIS vs Pan
    cis_key = next((p for p in (snippets or summaries) if "CIS_Controls" in p or "CIS" in p), None)
    pan_key = next((p for p in (snippets or summaries) if "Pan User Account Policy" in p or "Pan" in p), None)

    print(f"[DEBUG] snippet counts: CIS={len(snippets.get(cis_key,[]))}, "
      f"PAN={len(snippets.get(pan_key,[]))}")
    
    print("[DEBUG] snippet keys:", list(snippets.keys()))
    print("[DEBUG] selected:", state.get("selected_policy_paths"))

    

    if not (cis_key and pan_key) and len(selected) >= 2:
        cis_key, pan_key = selected[:2]
    if not (cis_key and pan_key):
        keys = list((snippets or summaries).keys())
        if len(keys) >= 2:
            cis_key, pan_key = keys[:2]
        else:
            raise ValueError("Not enough policies to compare.")

    # ---------- Path A: snippet-based verified comparison ----------
    baseline_snips = snippets.get(cis_key) or []
    target_snips   = snippets.get(pan_key) or []

    if baseline_snips and target_snips:
        # Give ONLY these snippets; ask model to return JSON gaps with refs into these snippets
        context = {
            "baseline_snippets": [
                {"source": s["source"], "page": s["page"], "line_start": s["line_start"], "line_end": s["line_end"], "text": s["text"][:1200]}
                for s in baseline_snips if s.get("text")
            ],
            "target_snippets": [
                {"source": s["source"], "page": s["page"], "line_start": s["line_start"], "line_end": s["line_end"], "text": s["text"][:1200]}
                for s in target_snips if s.get("text")
            ],
        }

        sys = (
            "You are an auditor. Compare Baseline (Policy A) vs Target (Policy B). "
            "Use ONLY the provided snippets; do not invent citations. "
            "Return JSON list of gaps; each gap has: "
            "{'gap','why','remediation','cis_refs':[{source,page,line_start,line_end,quote}],"
            "'pan_refs':[{source,page,line_start,line_end,quote}]} . "
            "Copy 'quote' verbatim from the snippet text you used."
        )
        prompt = f"{sys}\n\nSNIPPETS JSON:\n{json.dumps(context, ensure_ascii=False)}\n\nReturn JSON only."
        resp = llm.invoke([HumanMessage(content=prompt)])
        raw = resp.content
        try:
            gaps = normalize_llm_json(raw)
            if not isinstance(gaps, list):
                raise ValueError("LLM JSON is not a list")
        except Exception as e:
            raise RuntimeError(f"Failed to parse LLM JSON (snippet compare): {e}\nRaw:\n{raw}")

        # Verify quotes are actually in the cited snippet text
        def verify_and_convert(refs, pool):
            out = []
            ok = True
            for r in refs or []:
                # match on source+page+range
                matches = [s for s in pool
                           if str(s.get("source")) == str(r.get("source"))
                           and str(s.get("page")) == str(r.get("page"))
                           and s.get("line_start") == r.get("line_start")
                           and s.get("line_end") == r.get("line_end")]
                if not matches:
                    r["__verify_error"] = "no_matching_snippet"
                    ok = False
                    continue
                text = matches[0].get("text") or ""
                quote = (r.get("quote") or "").strip()
                if quote and quote not in text:
                    r["__verify_error"] = "quote_not_in_snippet"
                    ok = False
                # convert to our internal ref format (line_numbers as [start,end] range)
                out.append({
                    "line_hint": quote or "",
                    "line_numbers": [r.get("line_start"), r.get("line_end")],
                })
            return ok, out

        gaps_structured = []
        for g in gaps:
            cis_ok, cis_refs = verify_and_convert(g.get("cis_refs", []), baseline_snips)
            pan_ok, pan_refs = verify_and_convert(g.get("pan_refs", []),   target_snips)
            gaps_structured.append({
                "gap": g.get("gap",""),
                "why": g.get("why",""),
                "remediation": g.get("remediation",""),
                "refs": {"policy_a": cis_refs, "policy_b": pan_refs},
                "__verified": bool(cis_ok and pan_ok),
            })

        # Build human-readable bullets for backward compatibility
        bullets = []
        for g in gaps_structured:
            pa_rng = [tuple(ref.get("line_numbers") or []) for ref in g["refs"]["policy_a"]]
            pb_rng = [tuple(ref.get("line_numbers") or []) for ref in g["refs"]["policy_b"]]
            bullets.append(
                f"- **{g.get('gap','(gap)')}** — {g.get('why','')}\n"
                f"  - Remediation: {g.get('remediation','')}\n"
                f"  - Policy A ({cis_key}) ranges: {pa_rng or 'n/a'}\n"
                f"  - Policy B ({pan_key}) ranges: {pb_rng or 'missing'}"
            )

        state["policy_gaps_structured"] = gaps_structured
        state["policy_gaps"] = "\n".join(bullets)
        state["baseline_policy"] = cis_key
        state["target_policy"] = pan_key
        return state

    # ---------- Path B: FALLBACK to your existing summary-based flow ----------
    # (kept as-is, uses line-hint + fuzzy mapping; you can also drop in the regex fallback we discussed earlier.)
    build_numbered_policy_cache(state)
    numbered = state.get("_numbered_policies", {})

    comp_prompt = f"""You are an auditor. Compare the two policy summaries below and produce a list of concrete gaps
("Gaps in Policy B" vs Policy A baseline). For each gap, include:
- gap: short title
- why: 1-2 sentence risk rationale
- remediation: specific, actionable fix
- refs: object with **both** policy_a and policy_b arrays of citations:
    Each citation: {{ "line_hint": <short quote or clause you relied on>, "line_numbers": [] }}
Return **ONLY** valid JSON as an array of gap objects (no prose).

Important:
- Policy A is the baseline (CIS or equivalent).
- Use **short quotes** for line_hint that we can search for in the original full-text.
- If Policy B is missing a control, say so; the B refs can include a short hint like "missing" with empty line_numbers.

=== BASELINE POLICY (baseline: {cis_key}) SUMMARY ===
{summaries.get(cis_key, 'N/A')}

=== CURRENT POLICY (target: {pan_key}) SUMMARY ===
{summaries.get(pan_key, 'N/A')}
"""
    resp = llm.invoke([HumanMessage(content=comp_prompt)])
    raw = resp.content
    try:
        gaps_structured = normalize_llm_json(raw)
        if not isinstance(gaps_structured, list):
            raise ValueError("LLM JSON is not a list")
    except Exception as e:
        raise RuntimeError(f"Failed to parse LLM JSON: {e}\nRaw:\n{raw}")

    def attach_lines(policy_key: str, refs: List[Dict[str, Any]]):
        out = []
        policy_lines = numbered.get(policy_key, [])
        for r in refs or []:
            hint = (r or {}).get("line_hint", "") or ""
            line_numbers = find_best_line_numbers(policy_lines, hint) if policy_lines else []
            out.append({"line_hint": hint, "line_numbers": line_numbers})
        return out

    for g in gaps_structured:
        g.setdefault("refs", {})
        g["refs"].setdefault("policy_a", [])
        g["refs"].setdefault("policy_b", [])
        g["refs"]["policy_a"] = attach_lines(cis_key, g["refs"]["policy_a"])
        g["refs"]["policy_b"] = attach_lines(pan_key, g["refs"]["policy_b"])

    bullets = []
    for g in gaps_structured:
        pa_lines = sorted({ln for ref in g["refs"]["policy_a"] for ln in (ref.get("line_numbers") or [])})
        pb_lines = sorted({ln for ref in g["refs"]["policy_b"] for ln in (ref.get("line_numbers") or [])})
        bullets.append(
            f"- **{g.get('gap','(gap)')}** — {g.get('why','')}\n"
            f"  - Remediation: {g.get('remediation','')}\n"
            f"  - Policy A ({cis_key}) lines: {pa_lines or 'n/a'}\n"
            f"  - Policy B ({pan_key}) lines: {pb_lines or 'missing'}"
        )

    state["policy_gaps_structured"] = gaps_structured
    state["policy_gaps"] = "\n".join(bullets)
    state["baseline_policy"] = cis_key
    state["target_policy"] = pan_key
    return state



def validate_vs_evidence(state: dict) -> dict:
    """
    Validate the identified gaps against actual evidence summary (logs) to show impact/path of exploitation.

    Consumes:
      - state["policy_gaps_structured"]
      - state["evidence_summary"]
      - state["baseline_policy"], state["target_policy"]

    Produces:
      - state["gaps_evidence_link_structured"] (list)
      - state["gaps_evidence_link"] (readable)
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)

    gaps_struct = state.get("policy_gaps_structured", [])
    evidence = state.get("evidence_summary", "")
    cis_key = state.get("baseline_policy", "Policy A")
    pan_key = state.get("target_policy", "Policy B")

    # Ask for compact, structured mapping we can render nicely later
    prompt = f"""You are a cyber incident investigator.
Given the **structured gaps** (JSON) and the evidence summary, return a JSON array.
For each gap, include:
- gap
- evidence_linkage: 1-2 sentences citing concrete indicators (event IDs, timestamps, IPs, accounts)
- likely_impact: short phrase
- confidence: low/medium/high

Return ONLY valid JSON (no prose).

Structured Gaps JSON:
{json.dumps(gaps_struct, ensure_ascii=False)}

Evidence Summary:
{evidence}
"""
    resp = llm.invoke([HumanMessage(content=prompt)])
    raw = resp.content

    try:
        mapping = normalize_llm_json(raw)
        if not isinstance(mapping, list):
            raise ValueError("LLM JSON is not a list")
    except Exception as e:
        raise RuntimeError(f"Failed to parse LLM JSON (gap→evidence): {e}\nRaw:\n{raw}")

    # Keep readable bullets for convenience
    bullets = []
    for m in mapping:
        bullets.append(
            f"- **{m.get('gap','(gap)')}** → {m.get('evidence_linkage','')}"
            f" | Impact: {m.get('likely_impact','')} | Confidence: {m.get('confidence','')}"
        )

    state["gaps_evidence_link_structured"] = mapping
    state["gaps_evidence_link"] = "\n".join(bullets)
    return state


def finalize_report(state: dict) -> dict:
    """
    Produce a cohesive report that keeps line-level citations visible.

    Inputs:
      - state["threat"]
      - state["evidence_summary"]
      - state["selected_policy_paths"]
      - state["policy_gaps_structured"] + state["policy_gaps"]
      - state["_numbered_policies"]
      - state["baseline_policy"], state["target_policy"]
      - state["gaps_evidence_link_structured"] + state["gaps_evidence_link"]

    Output:
      - state["final_report"] (markdown)
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)

    threat = state.get("threat", "")
    sel = state.get("selected_policy_paths", [])
    evidence_summary = state.get("evidence_summary", "")
    gaps_hr = state.get("policy_gaps", "")
    gaps_struct = state.get("policy_gaps_structured", [])
    linkage_hr = state.get("gaps_evidence_link", "")
    cis_key = state.get("baseline_policy", "Policy A")
    pan_key = state.get("target_policy", "Policy B")

    # Build a compact citation block showing lines + quotes for each policy
    def render_citations(policy_key: str, refs: List[Dict[str, Any]]) -> str:
        # merge refs by line number and keep hints
        merged: Dict[int, List[str]] = {}
        for r in refs or []:
            for ln in r.get("line_numbers") or []:
                merged.setdefault(ln, []).append(r.get("line_hint", ""))
        if not merged:
            return "_none_"
        out = []
        for ln in sorted(merged.keys()):
            hints = "; ".join(sorted({h for h in merged[ln] if h}))
            out.append(f"Line {ln}: {hints or '(no hint)'}")
        return "\n".join(out)

    per_gap_citations = []
    for g in gaps_struct:
        pa = render_citations(cis_key, g.get("refs", {}).get("policy_a", []))
        pb = render_citations(pan_key, g.get("refs", {}).get("policy_b", []))
        per_gap_citations.append(
            f"- **{g.get('gap','(gap)')}**\n"
            f"  - {cis_key} refs:\n{indent_block(pa, 4)}\n"
            f"  - {pan_key} refs:\n{indent_block(pb, 4)}"
        )

    citations_block = "\n".join(per_gap_citations) if per_gap_citations else "_No line citations were generated._"

    # Ask LLM to stitch a crisp final with a dedicated citations section
    prompt = f"""Create a post-incident review report (markdown):

1) Threat (≤1 short paragraph)
2) Evidence Highlights (bullet list with concrete indicators)
3) Policies Consulted (list)
4) Gaps Identified (clear bullets; keep it short)
5) Gap→Evidence Linkage (compact bullets)
6) Actionable Recommendations (prioritized: quick wins then longer-term)
7) **Policy Line Citations** (per-gap, show which line numbers were relied on for the comparison)

Use the provided content faithfully.
Do not invent citations.

Threat:
{threat}

Evidence Summary:
{evidence_summary}

Policies Consulted:
{sel}

Gaps (human-readable):
{gaps_hr}

Gap→Evidence Linkage (bullets):
{linkage_hr}

Policy Line Citations (pre-rendered):
{citations_block}
"""
    resp = llm.invoke([HumanMessage(content=prompt)])
    state["final_report"] = resp.content
    return state


# ----------------------------
# Small helper to indent blocks in the final render
# ----------------------------

def indent_block(text: str, spaces: int = 2) -> str:
    pad = " " * spaces
    return "\n".join(pad + line for line in (text or "").splitlines()) or pad + "(none)"
