import re
from db import get_db

_SIZE_TRILLION_RE = re.compile(r"(\d+(?:\.\d+)?)t\b")
_SIZE_MOE_RE      = re.compile(r"(\d+)x(\d+(?:\.\d+)?)b\b")
_SIZE_BILLION_RE  = re.compile(r"(\d+(?:\.\d+)?)b\b")

def _model_size(name: str):
    """Parse parameter count in billions from a model name; None if not found."""
    s = (name or "").lower()
    m = _SIZE_TRILLION_RE.search(s)
    if m:
        return float(m.group(1)) * 1000.0
    m = _SIZE_MOE_RE.search(s)
    if m:
        return float(m.group(1)) * float(m.group(2))
    m = _SIZE_BILLION_RE.search(s)
    if m:
        return float(m.group(1))
    return None

def main():
    db = get_db()
    models = db.model_runs.distinct("model.name")
    
    output_path = "model_sizes.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"{'Model Name':<60} | {'Size (B)':<10}\n")
        f.write("-" * 75 + "\n")
        
        for model_name in sorted(models):
            size = _model_size(model_name)
            size_str = f"{size:.1f}B" if size is not None else "Unknown"
            f.write(f"{model_name:<60} | {size_str:<10}\n")
            print(f"Logged: {model_name} -> {size_str}")

    print(f"\nResults written to {output_path}")

if __name__ == "__main__":
    main()
