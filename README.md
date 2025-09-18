# agent.py

A tiny **tool-router agent**: the LLM picks exactly **one action** and Python executes the mapped function.  
Ships with a macOS login-log action and a clarification fallback.  
**Multi-step orchestration is not included yet (single-step only).**

> ⚠️ Note: this agent **does not read from `dataset/` yet**.  
> You’ll need to configure any external log sources/actions before the agent can use them.

---

## Features
- Strict JSON tool selection via hardened system prompt.
- Action registry with per-action arg schemas and Python callables.
- Type-checked arguments (minimal validator).
- Dry-run & debug modes for safe inspection.
- Time-boxed model call (`timeout=120s`) and clear error paths.

---

## Requirements
- Python 3.9+
- [Ollama](https://ollama.com) installed with a local model pulled (e.g. `ollama pull llama3.1`)
- macOS (for the included mac log action) or replace with your own actions.

Optional (future data sources):
- Access to your own logs / log hub.
- Any credentials your custom actions require.

---

## Quick Start

1. Pull an Ollama model:
   ollama pull llama3.1
2. Run in dry-run mode (no execution):
python agent.py -q "Check for suspicious logins last week" --dry-run
3. python agent.py -q "Check mac login failures since 2025-09-01 until 2025-09-08"
4. python agent.py -q "Check SSH login anomalies" -m qwen2.5
5. python agent.py -q "Check mac login failures" --debug --dry-run

## Expected output
{
  "action": "go_to_mac_login_logs",
  "args": {"since": "2025-09-01", "until": "2025-09-08", "limit": 10000},
  "reason": "Query mentions mac login logs over a time window."
}


## Actions

### `go_to_mac_login_logs`
- **Description:** Inspect macOS login/auth logs and summarize findings.  
- **Arguments:**
  - `since` *(string, optional)* — e.g. `"2025-09-01"`  
  - `until` *(string, optional)* — e.g. `"2025-09-17"`  
  - `limit` *(integer, optional)* — e.g. `5000`  

---

### `ask_clarification`
- **Description:** Fallback action when no other action fits or arguments are insufficient.  
- **Arguments:** none  

---

### (Optional) `say_hello` *(currently commented out in code)*
- **Description:** Example/demo action to greet a user.  
- **Arguments:**
  - `name` *(string, required)* — e.g. `"Alice"`  

---

To add more actions, define them in `actions/` and register inside the `ACTIONS` dictionary in `agent.py`.  
