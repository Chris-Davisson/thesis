from db import get_db
import json

def inspect_doc():
    db = get_db()
    doc = db.model_runs.find_one()
    if doc:
        # Remove large fields for brevity
        if "conversation_history_json" in doc:
            doc["conversation_history_json"] = "<truncated>"
        if "raw_response" in doc:
            doc["raw_response"] = "<truncated>"
        print(json.dumps(doc, indent=2, default=str))

if __name__ == "__main__":
    inspect_doc()
