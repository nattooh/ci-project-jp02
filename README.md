# run_graph.py

This script orchestrates the full policy–evidence reasoning workflow, where:

Baseline policy: CIS Controls v8.1 (Account Management)
Target policy: Pan User Account Policy
Evidence: Windows Event ID 4625 logs (failed logon attempts / brute-force activity)

The goal is to automatically identify whether organizational policies are aligned and enforced based on real evidence.

---

## Features
- Prebuilds line-aware document indexes for all policy PDFs.
- Splits text into sliding windows with page and line references for citation accuracy.
- Uses PyMuPDFReader + LlamaIndex for efficient chunking and embedding.
- Initializes the LangGraph workflow using build_graph()
- Nodes include evidence analysis, policy reading, comparison, and report generation.
- Injects prebuilt indexes and extracted text into the shared workflow state
- Ensures consistent policy references across the pipeline.
- Runs the graph end-to-end
- Compares baseline (CIS) vs target (Pan)
- Validates each gap against log-based evidence
- Generates structured gap summaries and citations

Outputs
- Gap–evidence linkage
- Policy line ranges for each identified gap
- Final compliance report
---

## Quick Start

1. python3 run_graph.py

## Expected output

=== GAPS VERIFIED AGAINST EVIDENCE ===
Gaps listed
--- Policy Line Citations (per gap) ---
Policy line citations
=== FINAL REPORT ===
Final report