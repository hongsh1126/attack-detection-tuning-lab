# Experiment results

Synthetic scenario-level evaluation; not real-world efficacy.

| Rule | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| baseline | 16 | 16 | 16 | 32 | 0.5 | 0.3333 | 0.5 |
| tuned | 32 | 0 | 32 | 16 | 1.0 | 0.6667 | 0.0 |

Selected configuration: `{"threshold": 8, "window": 300, "spray_threshold": 5}`.

Slow guessing remains a deliberate blind spot. Separate seeds use the same generator, so this is not external validation.
