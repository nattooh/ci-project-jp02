def action_ask_clarification() -> dict:
    return {
        "summary": "No available action fits the request. Ask the user to clarify or add a new action.",
        "next": "Please clarify what you want me to do (e.g., read login logs, greet someone, control an app, etc.)."
    }

def action_say_hello(name: str) -> dict:
    return {"summary": f"Hello, {name}!", "echo": {"name": name}}
