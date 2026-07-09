# CI Project

This repository contains an LLM-assisted post-incident policy-gap analysis workflow and the accompanying conference paper materials.

## Repository layout

- `run_graph.py`  
  Primary brute-force / Windows OpenSSH workflow runner.

- `run_graph_powershell.py`  
  Supplementary PowerShell HTTP-listener workflow runner.

- `run_consistency.py`  
  Repeated-run consistency script for the brute-force case.

- `run_consistency_powershell.py`  
  Repeated-run consistency script for the PowerShell case.

- `run_keyword_baseline.py`  
  Deterministic keyword-search baseline.

- `nodes/`  
  LangGraph node implementations for evidence analysis, policy retrieval, comparison, validation, and reporting.

- `policy/`  
  Baseline and APN policy documents used in the experiments.

- `report/CI.tex`  
  Main conference paper source.

- `report/references.bib`  
  BibTeX references for the paper.

- `response_to_reviewers.md`  
  Draft point-by-point response to reviewers.

## Environment setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the repository root with:

```env
OPENAI_API_KEY=your_key_here
```

Optional:

```env
USE_VECTOR_INDEXES=true
OPENAI_EMBEDDING_MODEL=text-embedding-3-small
```

When `USE_VECTOR_INDEXES` is not enabled, the workflow uses deterministic keyword
snippet retrieval. When it is enabled, policy PDFs are split into line-window
nodes and retrieved with LlamaIndex/OpenAI embeddings before the LLM comparison
step.

## Running the workflows

### Primary brute-force case

```bash
python3 run_graph.py
```

Main output:

- `outputs/final_report.pdf`

### Supplementary PowerShell case

```bash
python3 run_graph_powershell.py
```

Main outputs:

- `logs_powershell/powershell_http_listener.csv`
- `outputs/powershell_case/final_report_powershell.pdf`

## Repeated-run consistency

### Brute-force case

```bash
python3 run_consistency.py
```

Outputs:

- `outputs/consistency_runs/summary.txt`
- `outputs/consistency_runs/run_01.log` ... `run_05.log`
- `outputs/consistency_runs/run_01.pdf` ... `run_05.pdf`

### PowerShell case

```bash
python3 run_consistency_powershell.py
```

Outputs:

- `outputs/powershell_consistency_runs/summary.txt`
- `outputs/powershell_consistency_runs/run_01.log` ... `run_05.log`
- `outputs/powershell_consistency_runs/run_01.pdf` ... `run_05.pdf`

## Keyword baseline

```bash
python3 run_keyword_baseline.py
```

This provides a deterministic non-LLM baseline using keyword-based policy retrieval.

## Building the paper

The paper source is kept in `report/`, and generated build artifacts are kept in `report/build/`.

Build command:

```bash
latexmk -pdf report/CI.tex
```

Canonical PDF output:

- `report/build/CI.pdf`

Canonical LaTeX build artifacts:

- `report/build/CI.aux`
- `report/build/CI.bbl`
- `report/build/CI.blg`
- `report/build/CI.fdb_latexmk`
- `report/build/CI.fls`
- `report/build/CI.log`
- `report/build/CI.out`

## Current paper-related artifacts

- Main paper source: `report/CI.tex`
- References: `report/references.bib`
- Built PDF: `report/build/CI.pdf`
- Rebuttal draft: `response_to_reviewers.md`

## Notes

- The workflow is intended as analyst-supporting decision support, not autonomous audit judgment.
- Repeated runs show stable incident themes, but some gap wording and prioritization still vary.
- Public supplementary telemetry may omit command-line and richer process-context fields, which limits downstream policy assessment depth.
