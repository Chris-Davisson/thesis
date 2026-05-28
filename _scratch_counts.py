from db import get_db
import json

db = get_db()

# Top models
pipeline = [
    {"$group": {"_id": "$model.name", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}},
]
models = list(db.model_runs.aggregate(pipeline))

# Sample run keys
sample = db.model_runs.find_one({})
sample_keys = sorted(sample.keys()) if sample else []

# Models by backend
backend_pipeline = [
    {"$group": {"_id": "$model.backend", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}},
]
backends = list(db.model_runs.aggregate(backend_pipeline))

# Doubled by model — first 30 models
doubled_check = list(db.model_runs.aggregate([
    {"$group": {
        "_id": "$model.name",
        "doubled_true": {"$sum": {"$cond": [{"$eq": ["$doubled", True]}, 1, 0]}},
        "doubled_false": {"$sum": {"$cond": [{"$eq": ["$doubled", False]}, 1, 0]}},
        "total": {"$sum": 1},
    }},
    {"$sort": {"total": -1}},
    {"$limit": 40},
]))

# Prompts
prompts_used = list(db.model_runs.aggregate([
    {"$group": {"_id": "$prompt_id", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}},
]))
prompt_docs = list(db.prompts.find({}, {"prompt_name": 1, "prompt_version": 1, "_id": 1}))

# Devices
devices = list(db.devices.find({}, {"device_code": 1, "ground_truth": 1}))
devices_with_truth = sum(1 for d in devices if d.get("ground_truth"))

# Has any model_run ever had a scores array?
sample_with_scores = db.model_runs.find_one({"scores": {"$exists": True, "$ne": None}})
scorer_version_field = db.model_runs.count_documents({"scorer_version": {"$exists": True}})

print(json.dumps({
    "model_run_distinct_models": len(models),
    "models_top_30": models[:30],
    "backends": backends,
    "doubled_by_model_top_40": doubled_check,
    "prompts_used_in_runs": prompts_used,
    "prompt_docs": [{"_id": p["_id"], "name": p["prompt_name"], "version": p["prompt_version"]} for p in prompt_docs],
    "devices_count": len(devices),
    "devices_with_ground_truth": devices_with_truth,
    "device_codes": [d.get("device_code") for d in devices],
    "any_run_with_scores_array": sample_with_scores is not None,
    "runs_with_scorer_version": scorer_version_field,
    "sample_run_keys": sample_keys,
}, indent=2, default=str))
