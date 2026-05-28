from db import get_db

def list_models():
    db = get_db()
    models = db.model_runs.distinct("model.name")
    for model in models:
        print(model)

if __name__ == "__main__":
    list_models()
