# ATT&CK Detection Tuning Lab

An offline, reproducible Python teaching experiment by Sam Hong: tune authentication-log detections and compare false positives, missed attacks, and detection delay. Python 3.10+; no third-party packages, credentials, or network access required.

## Run

```sh
python lab.py
python -m unittest -v
```

Open `results/REPORT.md`. The command also saves input CSVs, ground truth, alert JSON, metrics, and a development threshold sweep. Change random seeds with `python lab.py --train-seed 17 --test-seed 29 --output results-other`.

## ATT&CK mapping

| Observable behavior | Mapping | Lab implementation |
|---|---|---|
| Repeated failures for one account and source | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Sliding-window failure count |
| Failures against many accounts from one source | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | Sliding-window distinct-account count |

These are educational behavior proxies, not proof of attacker intent. Authentication logs do not expose guessed passwords; the second rule cannot establish reuse of one password and may detect other multi-account activity. ATT&CK mapping is not MITRE certification or a claim of complete coverage. Official references checked October 9, 2026.

## Experiment design

Five synthetic scenarios: normal use, forgotten password, rapid guessing, multi-account spraying, and slow guessing. All IP addresses are reserved documentation addresses. No authentication requests or attacks are sent anywhere.

Baseline: 5 failures per source/account in 300 seconds. Tune the failure threshold and optional distinct-account rule on seed 42 only, requiring development recall >= 0.6 and minimizing false positives. Freeze the selected configuration, then evaluate seed 2026. Ground-truth labels and scenario IDs are excluded from detector input CSVs. Detection uses timestamps, IPs, usernames, and outcomes only.

Metrics count each isolated scenario once: TP/FP/TN/FN, precision, recall, false-positive rate, total alerts, and mean delay among detected malicious cases. Undefined ratios are null. Alert duplication cannot inflate true positives. Synthetic cases are separated in time; evaluation associates alerts with their source IP and case interval. This evaluation does not support overlapping cases sharing an IP without a stronger matching policy.

Separate seeds are drawn from the same simplified generator; they do not establish generalization to real traffic. The examples intentionally create a distinction between benign repeated failures and rapid attacks. Slow, distributed attacks, shared NAT addresses, username-only distributed correlation, production ingestion, and account compromise confirmation need additional work. Fewer alerts alone does not mean better security. Do not tune on the held-out set and still call it held-out.

## Classroom activities

1. Run the baseline and explain why forgotten passwords can cause false alarms.
2. Inspect the selected threshold and why adding a multi-account rule catches another pattern.
3. Find missed slow attacks and explain the cost of raising thresholds.
4. Modify a copy of the generator to include benign shared-IP traffic, slow spraying, or compromised familiar devices. Select on development data again and use a fresh test seed.
5. Add a new detection and tests, document its ATT&CK mapping, and discuss evidence limitations.

## 한국어 설명

ATT&CK는 공격자의 행동 도감, 탐지 규칙은 경보기, 튜닝은 경보기 조정입니다. 이 프로젝트에서는 가상 로그인 기록만 사용합니다. `python lab.py` 실행 후 `results/REPORT.md`를 보면 조정 전후에 정상 사용을 공격으로 착각한 횟수와 놓친 공격을 비교할 수 있습니다. 결과는 교육용 합성 데이터 실험이며 실제 기업 환경의 탐지 성능을 보장하지 않습니다.

## License

MIT; see LICENSE. ATT&CK names and referenced MITRE content belong to their respective owners.
