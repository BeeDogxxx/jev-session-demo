import unittest
import subprocess
from unittest.mock import patch
import server


class DemoTests(unittest.TestCase):
    def sample(self):
        return {'id': 'secret-label', 'expected_attack': 1, 'messages': [
            {'role': 'user', 'content': 'earlier request', 'oracle': True},
            {'role': 'assistant', 'content': 'earlier answer'},
            {'role': 'user', 'content': 'current request'},
            {'role': 'assistant', 'content': 'future answer must not leak'}]}

    def test_last_user_and_no_future_leakage(self):
        result = server.normalize_sessions([self.sample()])[0]
        self.assertEqual(result['target_index'], 2)
        self.assertEqual(len(result['messages']), 3)
        self.assertEqual(result['state'], {'history': [
            {'role': 'user', 'content': 'earlier request'},
            {'role': 'assistant', 'content': 'earlier answer'}], 'target_query': 'current request'})

    def test_explicit_target(self):
        item = self.sample()
        item['target_index'] = 0
        self.assertEqual(server.normalize_sessions([item])[0]['state'],
                         {'history': [], 'target_query': 'earlier request'})

    def test_invalid_target(self):
        for target in [1, -1, 5, True, '2']:
            item = self.sample()
            item['target_index'] = target
            with self.assertRaises(ValueError):
                server.normalize_sessions([item])

    def test_input_limits(self):
        for data in [[], ['a'] * 21, None, ['a' * 20001], [{'messages': [{'role': 'assistant', 'content': 'no user'}]}]]:
            with self.assertRaises(ValueError):
                server.normalize_sessions(data)

    def test_label_isolation_in_actual_request(self):
        session = server.normalize_sessions([self.sample()])[0]
        qs = server.questions(server.DEFAULT_POLICY)
        response = {'answers': {key: {'type': 'noul', 'noul': .2} for key in qs}, 'elapsed_ms': 1}
        with patch('server.call_jev', return_value=response) as caller:
            result = server.evaluate_one(session, server.DEFAULT_POLICY)
        self.assertEqual(result['status'], 'complete')
        payload = caller.call_args.args[0]
        self.assertNotIn('secret-label', str(payload))
        self.assertNotIn('expected_attack', str(payload))
        self.assertNotIn('oracle', str(payload))
        self.assertNotIn('future answer', str(payload))

    def test_missing_invalid_scores_never_become_zero(self):
        for value in [None, True, -1, 1.1, float('nan'), float('inf'), '0.8']:
            with self.assertRaises(RuntimeError):
                server.parse_scores({'answers': {'a': {'type': 'noul', 'noul': value}}}, ['a'])
        with self.assertRaises(RuntimeError):
            server.parse_scores({'answers': {}}, ['a'])

    def test_overall_is_independent_not_average(self):
        qs = server.questions(server.DEFAULT_POLICY)
        answers = {key: {'type': 'noul', 'noul': .2} for key in qs}
        answers['overall_attack']['noul'] = .9
        scores = server.parse_scores({'answers': answers}, qs)
        self.assertEqual(scores['overall_attack'], .9)
        self.assertEqual(len(scores), 7)

    def test_network_error_is_not_score(self):
        session = server.normalize_sessions(['hello'])[0]
        with patch('server.call_jev', side_effect=RuntimeError('DNS unavailable')):
            result = server.evaluate_one(session, server.DEFAULT_POLICY)
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('scores', result)

    def test_transient_retry_is_bounded(self):
        result = subprocess.CompletedProcess([], 0, stdout='{}\n503', stderr='')
        with patch('server.read_key', return_value='test-only-key'), patch('server.getproxies', return_value={}), patch('server.time.sleep'), patch('server.subprocess.run', return_value=result) as run:
            with self.assertRaises(RuntimeError):
                server.call_jev({})
            self.assertEqual(run.call_count, 3)

    def test_auth_error_is_not_retried(self):
        result = subprocess.CompletedProcess([], 0, stdout='{}\n401', stderr='')
        with patch('server.read_key', return_value='test-only-key'), patch('server.getproxies', return_value={}), patch('server.subprocess.run', return_value=result) as run:
            with self.assertRaises(RuntimeError):
                server.call_jev({})
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
