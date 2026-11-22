# Results and analysis

All numbers come from `results/pair1_results.json` and `results/pair2_results.json`, written by the notebooks themselves and re-checked by `python scripts/run_analysis.py` (see [TEST_REPORT.md](TEST_REPORT.md)). Random seed 42 everywhere.

## 1. Question and data

**Question.** HoneyBadger records attacks but has no ground-truth labels. Using a public labeled dataset, how well can a model (1) detect attacks when labels exist, and (2) detect them when they do not? What does that tell us about what HoneyBadger should record?

**Dataset.** [Network Intrusion Detection](https://www.kaggle.com/datasets/sampadab17/network-intrusion-detection), Kaggle, published by Sampada Bhosale. License listed as *Unknown*: the files are not committed; notebooks download them and verify SHA-256 checksums.

| | Train_data.csv | Test_data.csv |
|---|---|---|
| Rows | 25,192 | 22,544 |
| Columns | 41 features + `class` | 41 features, **no label** |
| Classes | 13,449 normal (53.4%), 11,743 anomaly (46.6%) | unknown |
| Missing values | 0 | 0 |

One row is one network connection summarised by 41 KDD-style features in four groups: basic (duration, protocol, service, TCP flag, bytes), content (failed logins, root access...), traffic in the last 2 seconds (`count`, error rates...) and the last 100 connections to the same host (`dst_host_*`). The row counts match the NSL-KDD "20% training" and "KDDTest+" files, so this is very likely a re-packaged NSL-KDD subset.

**Data quality.** Two constant columns (`num_outbound_cmds`, `is_host_login`) are dropped. One feature vector appears twice with opposite labels. 118 test rows repeat a training vector. The 58 labeled SSH rows are all attacks; HTTP has 7,564 normal and 439 attack rows.

## 2. Method shared by both objectives

- **Validation split.** 80% of labeled rows for training, 20% (5,039 rows: 2,349 attacks, 2,690 normal) held out for evaluation. Identical feature vectors are grouped so they never appear on both sides, and the split keeps the class balance. The split code is written out explicitly so it is identical across library versions.
- **No leakage.** Encoders and scalers live inside scikit-learn pipelines fitted on training rows only. Hyperparameters were chosen on training rows only. The held-out rows are used once.
- **The test file has no labels**, so it is only used for predictions; no metric is computed on it.

## 3. Objective 1: supervised classification (Pair 1)

Notebook: `pair1_attack_classification.ipynb`. Models tuned with 5-fold grouped cross-validation on the training rows, maximising anomaly F1.

| Model | Tuned settings | Precision | Recall | F1 | ROC-AUC | False alarms | Missed attacks |
|---|---|---|---|---|---|---|---|
| Majority baseline | always "normal" | 0.000 | 0.000 | 0.000 | 0.500 | 0 | 2,349 |
| Logistic regression | C = 10, log1p + scaling | 0.989 | 0.977 | 0.983 | 0.997 | 25 | 53 |
| Decision tree | max_depth = 12 | 0.997 | 0.995 | 0.996 | 0.995 | 8 | 11 |
| **Random forest** | 150 trees, max_features = 0.3 | **1.000** | **0.996** | **0.998** | **1.000** | **0** | **10** |

Cross-validated F1 for the random forest: 0.9975 ± 0.0007, consistent with the held-out score.

**Threshold.** At the default threshold of 0.5 the forest misses 10 attacks with 0 false alarms; at 0.3 it misses 4 with 2 false alarms; at 0.1 it misses 1 with 30 false alarms. The team can choose the trade-off.

**What the model uses.** Bytes sent each way (`src_bytes`, `dst_bytes`), the TCP `flag`, the `service` and same-service rates dominate. A 3-level tree gives a readable rule: connections that send almost nothing and get almost nothing back are attacks (typical of floods and scans).

**Feature selection.**

| Feature set | Features | F1 | False alarms | Missed |
|---|---|---|---|---|
| All | 39 | 0.998 | 0 | 10 |
| Top 15 by importance | 15 | 0.997 | 1 | 11 |
| HoneyBadger-compatible | 11 | 0.984 | 21 | 56 |

**Test file.** 8,617 of 22,544 rows predicted as attacks.

## 4. Objective 2: anomaly detection without labels (Pair 2)

Notebook: `pair2_anomaly_detection.ipynb` (objective 2, Siwar and Shayma). Models are trained on **normal rows only** (8,607 rows); the alert threshold is the 99th percentile of scores on 2,152 other normal rows, so about 1% of normal traffic is flagged. Labels are only used to grade.

| Model | ROC-AUC | Recall at 1% false alarms | At the alert threshold: caught | False alarms | Missed |
|---|---|---|---|---|---|
| Isolation Forest (200 trees) | 0.983 | 0.832 | 1,973 | 32 | 376 |
| **One-Class SVM** (RBF, nu = 0.01, 5,000-row sample) | 0.977 | **0.843** | 1,849 | 21 | 500 |
| Local Outlier Factor (20 neighbours) | 0.932 | 0.196 | 269 | 21 | 2,080 |
| Random score (no skill) | 0.503 | 0.009 | 28 | 32 | 2,321 |
| Random forest *with labels* (reference) | 1.000 | 1.000 | 2,339 | 0 | 10 |

- Isolation Forest and One-Class SVM are a **near tie**: One-Class SVM wins the chosen metric by 0.011, Isolation Forest catches more attacks at its own threshold.
- **Local Outlier Factor misses 100% of the 1,340 `S0` attacks** (connection requests that never got an answer, typical of SYN floods). LOF compares a point's density with that of its nearest normal neighbours; when those neighbours are themselves sparse, the attack looks ordinary.
- Isolation Forest and One-Class SVM mostly miss attacks that completed like normal connections (flag `SF`). That is why their HTTP recall is only about 51%.
- **False-alarm budget** (One-Class SVM): 0.5% → 16 false alarms, 809 missed; 1% → 21, 500; 5% → 161, 174; 10% → 303, 141.
- **HoneyBadger-compatible features only**: recall at 1% false alarms drops from 0.843 to 0.459.
- **Test file**: 8,301 rows flagged; the flags agree with Pair 1's predictions on 86.1% of rows.

## 5. Interpretation: false positives and false negatives

| Error | In this project | Real-world cost |
|---|---|---|
| False positive (false alarm) | Normal connection flagged as attack | Analyst time; too many and alerts get ignored |
| False negative (missed attack) | Attack labeled normal | The attack goes unnoticed: the worse error for security |

With labels, almost every attack is caught with almost no false alarms. Without labels, about 4 in 5 attacks are caught at a 1% false-alarm rate. The missed ones look like normal completed connections. The difference between the two is the value of labeled data.

## 6. Why the high scores must be read with care

- **Benchmark data, not HoneyBadger data.** These are KDD-style connection summaries. HoneyBadger stores application events (a login, a command, an HTTP request). The scores show the methods work on this benchmark, not on our honeypot.
- **NSL-KDD is widely criticised as less realistic than modern traffic.** Many of its attacks are floods with very distinctive byte counts and flags, which makes near-perfect scores possible. Real attackers are more varied.
- **SSH has no normal examples**, so SSH false alarms cannot be measured.
- **One split.** The held-out set is a single 20% split; the cross-validation spread (± 0.0007 for the forest) suggests the result is stable.
- **No attack-type labels**, so the dataset cannot say which kinds of attack are missed beyond what the TCP flag suggests.

## 7. What this means for HoneyBadger

Both objectives lose the most when the model only has features HoneyBadger can compute today (service, login outcome, connection counts). The single most useful change to the honeypot would be to **record bytes exchanged and how each connection ended** for every session. Anomaly detection (objective 2) is the method that fits a honeypot, because it needs a clean baseline period rather than labeled attacks.

## 8. Reproduce

```bash
pip install -r requirements-analysis.txt
python scripts/run_analysis.py          # about 2 minutes on a laptop CPU
```
