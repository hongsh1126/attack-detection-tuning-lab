import unittest
from datetime import datetime, timedelta, timezone
from lab import detect, evaluate, generate


def events(times, users=None):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [{'timestamp': (start + timedelta(seconds=t)).isoformat(), 'source_ip': '192.0.2.1',
             'username': users[i] if users else 'alice', 'outcome': 'failure'} for i, t in enumerate(times)]


class DetectionTests(unittest.TestCase):
    def test_boundary_included(self):
        self.assertEqual(len(detect(events([0, 300]), threshold=2)), 1)

    def test_expired_event_excluded(self):
        self.assertEqual(detect(events([0, 301]), threshold=2), [])

    def test_sources_do_not_mix(self):
        data = events([0, 1]); data[1]['source_ip'] = '192.0.2.2'
        self.assertEqual(detect(data, threshold=2), [])

    def test_spray_counts_unique_accounts(self):
        self.assertEqual(detect(events([0, 1, 2], ['a', 'a', 'a']), threshold=99, spray_threshold=3), [])
        self.assertEqual(detect(events([0, 1, 2], ['a', 'b', 'c']), threshold=99, spray_threshold=3)[0]['technique'], 'T1110.003')

    def test_success_not_counted(self):
        data = events([0, 1]); data[1]['outcome'] = 'success'
        self.assertEqual(detect(data, threshold=2), [])

    def test_labels_not_used(self):
        data = events([0, 1]); expected = detect(data, threshold=2)
        for e in data: e.update(malicious=False, scenario_id='arbitrary')
        self.assertEqual(detect(data, threshold=2), expected)

    def test_unordered_input(self):
        data = events([0, 1, 2]); self.assertEqual(detect(data[::-1], threshold=2), detect(data, threshold=2))

    def test_duplicate_alerts_do_not_inflate_metrics(self):
        data, truth = generate(count=5); alerts = detect(data)
        self.assertEqual(evaluate(alerts + alerts, truth)['TP'], evaluate(alerts, truth)['TP'])

    def test_slow_attack_is_missed(self):
        self.assertEqual(detect(events(range(0, 900, 90)), threshold=5), [])

    def test_invalid_config(self):
        with self.assertRaises(ValueError): detect([], threshold=0)


if __name__ == '__main__':
    unittest.main()
