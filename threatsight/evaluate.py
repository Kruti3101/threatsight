from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .detector import detect


def ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate(dataset_path: Path) -> dict:
    rows = [json.loads(line) for line in dataset_path.read_text().splitlines() if line.strip()]
    counts: Counter[str] = Counter()
    errors: list[dict] = []
    per_category: dict[str, dict] = {}
    for row in rows:
        findings = detect(row["prompt"])
        categories = {item.threat_category for item in findings}
        actual = row["label"] != "benign"
        predicted = bool(findings)
        if actual and predicted:
            counts["true_positive"] += 1
        elif not actual and predicted:
            counts["false_positive"] += 1
        elif actual:
            counts["false_negative"] += 1
        else:
            counts["true_negative"] += 1
        if (actual != predicted) or (actual and row["label"] not in categories):
            errors.append({"id": row["id"], "label": row["label"], "predicted_categories": sorted(categories)})
        if actual:
            category = per_category.setdefault(row["label"], {"examples": 0, "matched_category": 0})
            category["examples"] += 1
            category["matched_category"] += int(row["label"] in categories)
    tp, fp, fn, tn = (counts[key] for key in ("true_positive", "false_positive", "false_negative", "true_negative"))
    for category in per_category.values():
        category["category_recall"] = ratio(category["matched_category"], category["examples"])
    return {
        "dataset": str(dataset_path),
        "samples": len(rows),
        "confusion_matrix": dict(counts),
        "metrics": {
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, fp + tn),
            "false_negative_rate": ratio(fn, fn + tp),
        },
        "category_results": per_category,
        "error_cases": errors,
        "limitations": "Results describe this labeled dataset only; they do not establish resistance to paraphrase attacks or prove real-world compromise.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ThreatSight on a labeled JSONL dataset.")
    parser.add_argument("--dataset", type=Path, default=Path("data/evaluation_prompts.jsonl"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate(args.dataset)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
