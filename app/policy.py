"""Independent narrow capabilities. The model cannot grant itself permission."""
import copy

ACTION_ARGS = {"none": set(), "send_message": {"recipient", "text"}, "open_url": {"url"}, "change_destination": {"destination"}, "record_note": {"text"}}

def validate_proposal(proposal):
    if not isinstance(proposal, dict) or set(proposal) != {"answer", "action", "arguments"}:
        return "Proposal must contain exactly answer, action and arguments."
    if not isinstance(proposal["answer"], str) or len(proposal["answer"]) > 2000:
        return "Answer must be text no longer than 2000 characters."
    action, arguments = proposal["action"], proposal["arguments"]
    if not isinstance(action, str) or action not in ACTION_ARGS:
        return "Unknown action."
    if not isinstance(arguments, dict) or set(arguments) != ACTION_ARGS[action]:
        return "Arguments do not match the action schema."
    if any(not isinstance(v, str) or not v or len(v) > 500 for v in arguments.values()):
        return "Action arguments must be nonempty strings no longer than 500 characters."
    return None

def evaluate(proposal, scenario, mode):
    if mode not in {"unprotected", "prompt_only", "enforced"}:
        return {"allowed": False, "reason": "Unknown policy mode.", "layer": "schema"}
    error = validate_proposal(proposal)
    if error:
        return {"allowed": False, "reason": error, "layer": "schema"}
    if mode != "enforced":
        return {"allowed": True, "reason": "Permissive sandbox runner accepts the model proposal; no capability gate is enabled.", "layer": "sandbox-only"}
    if proposal["action"] == "none":
        return {"allowed": True, "reason": "Read-only answer has no tool effect. Answer accuracy and instruction-following remain separate, unverified properties.", "layer": "capability"}
    capability = scenario.get("capability", {"action": "none", "arguments": {}})
    if proposal["action"] != capability["action"]:
        return {"allowed": False, "reason": "The wearer did not authorize this action. Scene text and model output cannot add a capability.", "layer": "capability"}
    if proposal["arguments"] != capability["arguments"]:
        return {"allowed": False, "reason": "Action arguments differ from the exact wearer-authorized arguments. A scene cannot change the recipient, destination or note.", "layer": "argument-binding"}
    return {"allowed": True, "reason": "Action and arguments exactly match the trusted wearer intent.", "layer": "argument-binding"}

def default_state():
    return {"messages": [], "notes": [], "destination": "No destination set", "opened_urls": []}

def execute(proposal, state):
    error = validate_proposal(proposal)
    if error:
        raise ValueError(error)
    before = copy.deepcopy(state)
    action, args = proposal["action"], proposal["arguments"]
    if action == "send_message":
        state["messages"].append({"to": args["recipient"], "text": args["text"], "transport": "in-memory sandbox only"})
    elif action == "record_note":
        state["notes"].append(args["text"])
    elif action == "change_destination":
        state["destination"] = args["destination"]
    elif action == "open_url":
        state["opened_urls"].append({"url": args["url"], "fetched": False})
    descriptions = {"none": "No tool action was requested.", "send_message": "A synthetic message appeared in the sandbox inbox. Nothing was sent externally.", "record_note": "The exact note was saved in the synthetic notebook.", "change_destination": "The synthetic route destination changed.", "open_url": "A proposed URL was recorded. No URL was fetched or opened."}
    return {"before": before, "after": copy.deepcopy(state), "executed": action != "none", "summary": descriptions[action]}
