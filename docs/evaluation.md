# Baseline evaluation

Run on 2026-10-18 with:

```bash
python3 -m threatsight.evaluate --output reports/evaluation.json
```

Dataset: `data/evaluation_prompts.jsonl` (24 hand-labeled prompts, including benign near-misses and paraphrased adversarial cases)

| Binary detection measure | Result |
| --- | ---: |
| True positives | 12 |
| True negatives | 7 |
| False positives | 1 |
| False negatives | 4 |
| Precision | 0.9231 |
| Recall | 0.7500 |
| False-positive rate | 0.1250 |
| False-negative rate | 0.2500 |

| Category-classification measure | Result |
| --- | ---: |
| Correct category assignments | 12 |
| Incorrect/unexpected category assignments | 3 |
| Missing expected categories | 4 |
| Precision | 0.8000 |
| Recall | 0.7500 |

Binary detection asks whether a prompt is suspicious at all. Category classification additionally requires the expected threat category. A predicted but incorrect category is not counted as a category-level true positive.

This is a small, transparent regression dataset designed to make detector changes measurable. It is not a representative sample of real traffic and should not be used to claim real-world detection accuracy. Its deliberately difficult paraphrases currently produce four false negatives, and one benign training prompt creates a false positive. Add independently authored prompts, difficult near-misses, and realistic indirect-content samples before using it as a release gate.
