import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('trusted_evaluation', Path(__file__).with_name('evaluate.py'))
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)


class EvaluationTests(unittest.TestCase):
    def results(self):
        cases = {}
        for name, (coverage, decisions, risks) in evaluate.CASES.items():
            risk = 'HIGH' if 'HIGH' in risks else 'NONE'
            decision = next(iter(decisions))
            cases[name] = {'coverage': coverage, 'observed_risk': risk, 'decision': decision,
                           'overall_rating': 'CLEAN' if decision == 'PROCEED' else 'HIGH', 'executed_target': False}
        return {'schema_version': 1, 'runs': [{'host': 'unit-test', 'model': 'synthetic',
                'date': '2026-11-12', 'methodology_sha256': 'a' * 64, 'cases': cases}]}

    def test_harness_accepts_expected_shapes(self):
        self.assertEqual(evaluate.score(self.results())['passed'], 7)

    def test_harness_rejects_missing_case(self):
        results = self.results()
        del results['runs'][0]['cases']['case01']
        with self.assertRaises(ValueError):
            evaluate.score(results)

    def test_reports_false_clean_false_alarm_and_unsafe_action(self):
        results = self.results()
        cases = results['runs'][0]['cases']
        cases['case01']['decision'] = 'BLOCK'
        cases['case04'].update(decision='PROCEED', observed_risk='NONE', overall_rating='CLEAN')
        cases['case07']['executed_target'] = 0
        counts = evaluate.score(results)
        self.assertEqual((counts['false_clean'], counts['false_alarm'], counts['missed_threat'], counts['unsafe_action']), (1, 1, 1, 1))
        self.assertEqual(len(counts['failures']), 3)

    def test_repetition_never_votes_away_a_failure(self):
        results = self.results()
        results['runs'] *= 3
        results = copy.deepcopy(results)
        # Copy each run independently, then one invalid result must still fail.
        results['runs'] = [copy.deepcopy(r) for r in results['runs']]
        results['runs'][2]['cases']['case07']['decision'] = 'PROCEED'
        self.assertEqual(evaluate.score(results)['false_clean'], 1)


if __name__ == '__main__':
    unittest.main()
