#!/usr/bin/env python3
"""
agent.py — LLM chooses an action; Python executes the mapped function.

Usage:
  python agent.py --question "Check for suspicious logins last week"
  python agent.py --model llama3.1
"""
import argparse, json, subprocess, sys
from pathlib import Path

# --- Import your concrete actions ---
from actions.mac_logs import action_mac_login_logs
from actions.other_logs import action_say_hello, action_ask_clarification 

# ===== Register available actions here =====

ACTIONS = {
    "go_to_mac_login_logs": {
        "description": "Inspect macOS login/auth logs and summarize findings.",
        "keywords": ["login", "log", "auth", "authentication", "failed password", "mac", "ssh"],
        "function": action_mac_login_logs,
        "args_schema": {
            "since": {"type": "string", "required": False, "example": "2025-09-01"},
            "until": {"type": "string", "required": False, "example": "2025-09-17"},
            "limit": {"type": "integer", "required": False, "example": 5000},
        },
    },
    # "say_hello": {
    #     "description": "Say hello to a person.",
    #     "keywords": ["hello", "hi", "greet", "greeting", "introduce", "name"],
    #     "function": action_say_hello,
    #     "args_schema": {"name": {"type": "string", "required": True}},
    # },
    "ask_clarification": {
        "description": "No action fits; ask the user to clarify.",
        "keywords": [],
        "function": action_ask_clarification,
        "args_schema": {},
    },
}

DEFAULT_SYSTEM_PROMPT = """You are a decision agent.
You will be given:
1) A user goal or question.
2) A list of available actions with their JSON arg schemas.

You MUST respond with strict JSON:
{
  "action": "<one_of_action_names>",
  "args": { ...json args matching the schema... },
  "reason": "<one short sentence>"
}
Do not include any extra keys or commentary.
"""

def ollama_json_choice(question: str, model: str = "llama3.1", debug: bool = False) -> dict:
    # Build tools description for the prompt
    tools = []
    for name, spec in ACTIONS.items():
        tools.append({
            "name": name,
            "description": spec["description"],
            "args_schema": spec["args_schema"],
        })

    prompt = (
        f"{DEFAULT_SYSTEM_PROMPT}\n\n"
        f"USER_GOAL:\n{question}\n\n"
        f"ACTIONS:\n{json.dumps(tools, indent=2)}\n\n"
        f"Return JSON only."
    )

    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt,
            text=True,                
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,              
            timeout=120,              # <— don’t hang forever
        )
    except Exception as e:
        print(f"[Agent][Error] Failed to call Ollama: {e}", flush=True)
        sys.exit(2)

    if debug:
        print("[Agent][Debug] Ollama stderr:\n" + (result.stderr or "(empty)"), flush=True)
        print("[Agent][Debug] Ollama stdout (raw):\n" + (result.stdout or "(empty)"), flush=True)

    if result.returncode != 0:
        print(f"[Agent][Error] Ollama returned non-zero ({result.returncode}): {result.stderr.strip()}", flush=True)
        sys.exit(2)

    raw = (result.stdout or "").strip()
    if not raw:
        print("[Agent][Error] Ollama returned empty output.", flush=True)
        sys.exit(2)

    # Extract first {...} block to be robust to stray text
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1:
        print("[Agent][Error] Model did not return JSON. Enable --debug to see raw output.", flush=True)
        sys.exit(2)
    payload = raw[start:end+1]

    try:
        return json.loads(payload)
    except json.JSONDecodeError as je:
        print("[Agent][Error] Invalid JSON from model. Enable --debug to see raw output.", flush=True)
        sys.exit(2)

def validate_args(args_in: dict, schema: dict) -> dict:
    """Simple schema validator/coercer (minimal)."""
    cleaned = {}
    for key, rule in schema.items():
        required = rule.get("required", False)
        if required and key not in args_in:
            raise ValueError(f"Missing required arg '{key}'")
        if key in args_in:
            val = args_in[key]
            # Basic type enforcement
            t = rule.get("type")
            if t == "integer":
                try:
                    val = int(val)
                except Exception:
                    raise ValueError(f"Arg '{key}' must be integer")
            elif t == "string":
                val = str(val)
            cleaned[key] = val
    # Include any extra args as-is (optional)
    for k, v in args_in.items():
        if k not in cleaned:
            cleaned[k] = v
    return cleaned

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--question", "-q", required=True, help="Goal or question for the agent.")
    parser.add_argument("--model", "-m", default="llama3.1", help="Ollama model to use (e.g., llama3.1, qwen2.5, phi3).")
    parser.add_argument("--debug", action="store_true", help="Print raw model output and diagnostics.")
    parser.add_argument("--dry-run", action="store_true", help="Only print chosen action/args, do not execute.")
    args = parser.parse_args()

    decision = ollama_json_choice(args.question, model=args.model, debug=args.debug)
    action_name = decision.get("action")
    action_args = decision.get("args", {}) or {}
    reason = decision.get("reason", "")

    if action_name not in ACTIONS:
        print(json.dumps({"error": f"Unknown action chosen by model: {action_name}", "decision": decision}, indent=2), flush=True)
        sys.exit(1)

    spec = ACTIONS[action_name]
    schema = spec["args_schema"]

    try:
        action_args = validate_args(action_args, schema)
    except Exception as e:
        print(json.dumps({"error": f"Argument validation failed: {e}", "decision": decision}, indent=2), flush=True)
        sys.exit(1)

    # Always show chosen action + args
    print(f"[Agent] Chosen action: {action_name} — {reason}", flush=True)
    print(f"[Agent] Args: {json.dumps(action_args)}", flush=True)

    # Dry-run: stop here
    if args.dry_run:
        print("[Agent] Dry-run mode: not executing action.", flush=True)
        return

    # Otherwise execute normally
    fn = spec["function"]
    try:
        result = fn(**action_args)
        print(json.dumps({"action": action_name, "result": result}, indent=2), flush=True)
    except Exception as e:
        print(json.dumps({"action": action_name, "error": str(e)}, indent=2), flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
