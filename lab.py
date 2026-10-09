"""Offline ATT&CK-inspired detection experiment; Python standard library only."""
import argparse
import csv
import json
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate(seed=42, count=80):
    rng = random.Random(seed)
    events, truth = [], []
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    kinds = ['normal', 'forgot_password', 'guessing', 'spraying', 'slow_guessing']
    for i in range(count):
        kind = kinds[i % len(kinds)]
        sid = f'case-{i:03d}'
        origin = start + timedelta(hours=i)
        ip = f'192.0.2.{i % 250 + 1}'  # RFC 5737 documentation range
        attempts = {'normal': rng.randint(0, 2), 'forgot_password': rng.randint(5, 7),
                    'guessing': rng.randint(9, 15), 'spraying': rng.randint(6, 10),
                    'slow_guessing': 10}[kind]
        for j in range(attempts):
            gap = 90 if kind == 'slow_guessing' else 12
            events.append({'timestamp': (origin + timedelta(seconds=j * gap)).isoformat(),
                           'source_ip': ip, 'username': f'user-{j}' if kind == 'spraying' else 'student',
                           'outcome': 'failure', 'scenario_id': sid})
        end = origin + timedelta(seconds=max(1, attempts) * (90 if kind == 'slow_guessing' else 12))
        if kind in ('normal', 'forgot_password'):
            events.append({'timestamp': end.isoformat(), 'source_ip': ip,
                           'username': 'student', 'outcome': 'success', 'scenario_id': sid})
        truth.append({'scenario_id': sid, 'start': origin.isoformat(), 'end': end.isoformat(),
                      'source_ip': ip, 'kind': kind, 'malicious': kind in ('guessing', 'spraying', 'slow_guessing')})
    return events, truth


def detect(events, threshold=5, window=300, spray_threshold=None):
    """Consume only observable fields; never use scenario_id or labels."""
    if threshold < 1 or window < 1 or (spray_threshold is not None and spray_threshold < 1):
        raise ValueError('Thresholds and window must be positive')
    account, sources = defaultdict(deque), defaultdict(deque)
    last = {}
    alerts = []
    ordered = sorted(events, key=lambda e: datetime.fromisoformat(e['timestamp']))
    for e in ordered:
        now = datetime.fromisoformat(e['timestamp'])
        if now.tzinfo is None:
            raise ValueError('Timezone-aware timestamps required')
        if e['outcome'] not in ('failure', 'success'):
            raise ValueError('Unknown outcome')
        if e['outcome'] != 'failure':
            continue
        key = (e['source_ip'], e['username'])
        a, src = account[key], sources[e['source_ip']]
        a.append(now)
        src.append((now, e['username']))
        cutoff = now - timedelta(seconds=window)
        while a and a[0] < cutoff:
            a.popleft()
        while src and src[0][0] < cutoff:
            src.popleft()
        matches = []
        if len(a) >= threshold:
            matches.append(('T1110.001', key, len(a)))
        if spray_threshold is not None and len({u for _, u in src}) >= spray_threshold:
            matches.append(('T1110.003', (e['source_ip'],), len({u for _, u in src})))
        for technique, entity, evidence in matches:
            dedup = (technique, entity)
            if dedup not in last or (now - last[dedup]).total_seconds() > window:
                alerts.append({'timestamp': now.isoformat(), 'source_ip': e['source_ip'],
                               'username': e['username'], 'technique': technique, 'evidence_count': evidence})
                last[dedup] = now
    return alerts


def evaluate(alerts, truth):
    """Scenario-level confusion matrix; each case counted once, not each event."""
    result = dict(TP=0, FP=0, TN=0, FN=0)
    delays, missed = [], []
    for case in truth:
        hits = [a for a in alerts if a['source_ip'] == case['source_ip'] and
                case['start'] <= a['timestamp'] <= case['end']]
        predicted = bool(hits)
        result[('TP' if predicted else 'FN') if case['malicious'] else ('FP' if predicted else 'TN')] += 1
        if case['malicious'] and hits:
            delays.append((datetime.fromisoformat(min(a['timestamp'] for a in hits)) -
                           datetime.fromisoformat(case['start'])).total_seconds())
        if case['malicious'] and not hits:
            missed.append(case['scenario_id'])
    tp, fp, tn, fn = (result[k] for k in ('TP', 'FP', 'TN', 'FN'))
    ratio = lambda n, d: round(n / d, 4) if d else None
    result.update(precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                  false_positive_rate=ratio(fp, fp + tn), alerts=len(alerts),
                  mean_detected_delay_seconds=round(sum(delays) / len(delays), 2) if delays else None,
                  missed_scenarios=missed)
    return result


def experiment(output, train_seed=42, test_seed=2026):
    if train_seed == test_seed:
        raise ValueError('Use different development and held-out seeds')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    train, train_truth = generate(train_seed)
    test, test_truth = generate(test_seed)
    # Select on development data only. Recall floor deliberately admits slow misses.
    sweep = []
    for threshold in range(3, 13):
        for spray in (None, 5, 8):
            config = dict(threshold=threshold, window=300, spray_threshold=spray)
            metrics = evaluate(detect(train, **config), train_truth)
            sweep.append({'config': config, 'development': metrics})
    eligible = [r for r in sweep if r['development']['recall'] >= 0.6]
    best = min(eligible, key=lambda r: (r['development']['FP'], -r['development']['recall'],
                                      r['config']['threshold'], r['config']['spray_threshold'] or 999))
    baseline = dict(threshold=5, window=300, spray_threshold=None)
    results = {}
    for name, config in [('baseline', baseline), ('tuned', best['config'])]:
        alerts = detect(test, **config)
        results[name] = {'config': config, 'held_out': evaluate(alerts, test_truth)}
        (output / f'{name}_alerts.json').write_text(json.dumps(alerts, indent=2), encoding='utf-8')
    for name, data in [('development', train), ('held_out', test)]:
        # scenario_id is intentionally omitted from detector inputs.
        with (output / f'{name}_events.csv').open('w', newline='', encoding='utf-8') as f:
            fields = ['timestamp', 'source_ip', 'username', 'outcome']
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(data)
    report = {'train_seed': train_seed, 'test_seed': test_seed, 'unit': 'scenario',
              'selection': 'development recall >= 0.6; minimize FP, then maximize recall',
              'results': results}
    for name, data in [('metrics', report), ('threshold_sweep', sweep), ('held_out_truth', test_truth)]:
        (output / f'{name}.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
    lines = ['# Experiment results', '', 'Synthetic scenario-level evaluation; not real-world efficacy.', '',
             '| Rule | TP | FP | TN | FN | Precision | Recall | FPR |',
             '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name, r in results.items():
        m = r['held_out']
        lines.append('| ' + ' | '.join(str(x) for x in [name] + [m[k] for k in ['TP', 'FP', 'TN', 'FN', 'precision', 'recall', 'false_positive_rate']]) + ' |')
    lines += ['', 'Selected configuration: `' + json.dumps(best['config']) + '`.', '',
              'Slow guessing remains a deliberate blind spot. Separate seeds use the same generator, so this is not external validation.']
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='results')
    parser.add_argument('--train-seed', type=int, default=42)
    parser.add_argument('--test-seed', type=int, default=2026)
    args = parser.parse_args()
    print(json.dumps(experiment(args.output, args.train_seed, args.test_seed), indent=2))
