# Baseline evaluation

Run on 2026-10-18 with:

```bash
python3 -m threatsight.evaluate --output reports/evaluation.json
```

Dataset: `data/evaluation_prompts.jsonl` (16 hand-labeled prompts)

| Measure | Result |
| --- | ---: |
| True positives | 12 |
| True negatives | 4 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| False-positive rate | 0.0000 |
| False-negative rate | 0.0000 |

Each of the four adversarial categories has three examples and category recall of 1.0000.

This is a small, transparent regression dataset designed to make detector changes measurable. It is not a representative sample of real traffic, does not test paraphrase resistance, and should not be used to claim real-world detection accuracy. Add independently authored prompts, difficult near-misses, and realistic indirect-content samples before using it as a release gate.
