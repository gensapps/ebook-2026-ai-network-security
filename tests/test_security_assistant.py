from notebook_layout import notebook_path
"""저장한 sklearn 모델을 다시 읽어 통합 경로와 승인 실패를 검사한다."""
import json
from pathlib import Path
import pickle
import tempfile
from types import SimpleNamespace
import unittest

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from security_assistant import SecurityAssistant


class KnowledgeBase:
    def count(self):
        return 1

    def query(self, **kwargs):
        return {'ids': [['ref-1']], 'documents': [['교육용 참고 문서']], 'metadatas': [[{}]]}


class FakeLLM:
    def __init__(self, result, stop_reason='end_turn'):
        self.result = result
        self.stop_reason = stop_reason
        self.messages = self

    def create(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type='text', text=self.result)])


class AssistantTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'model.pickle'
        X = pd.DataFrame({'count': [0, 1, 2, 3]})
        pre = ColumnTransformer([('num', StandardScaler(), ['count'])])
        # 분할하지 않는 모델로 0.5 점수의 회색지대를 만든다.
        model = DecisionTreeClassifier(min_samples_split=10).fit(pre.fit_transform(X), [0, 0, 1, 1])
        with self.path.open('wb') as f:
            pickle.dump({'model': model, 'preprocessor': pre,
                         'feature_columns': ['count'], 'positive_label': 1}, f)
        self.log = {'src': '192.0.2.20', 'features': {'count': 2},
                    'redacted_summary': '비식별 로그 요약', 'password': 'DO_NOT_SEND'}

    def tearDown(self):
        self.tmp.cleanup()

    def assistant(self, text, **kwargs):
        return SecurityAssistant(self.path, kb=KnowledgeBase(), llm=FakeLLM(text), **kwargs)

    def test_saved_model_rag_ids_and_valid_llm(self):
        a = self.assistant(json.dumps({'verdict': 'ATTACK', 'severity': 4,
                                     'summary': '근거 검토', 'citations': ['ref-1']}))
        result = a.analyze(self.log)
        self.assertEqual(result['route'], 'llm_agent')
        self.assertEqual(result['actions'][0]['status'], 'simulated')
        self.assertNotIn('DO_NOT_SEND', str(a.llm.request))

    def test_invalid_json_and_missing_features_stay_unknown(self):
        a = self.assistant('not JSON')
        self.assertEqual(a.analyze(self.log)['verdict'], 'UNKNOWN')
        self.assertEqual(a.analyze({'src': '192.0.2.20'})['route'], 'review')

    def test_complete_json_fence_and_truncated_response(self):
        payload = json.dumps({'verdict': 'ATTACK', 'severity': 4,
                              'summary': '근거 검토', 'citations': ['ref-1']})
        a = self.assistant('```json\n' + payload + '\n```')
        self.assertEqual(a.analyze(self.log)['route'], 'llm_agent')
        for text in [payload, '```json\n' + payload + '\n```']:
            a = self.assistant(text)
            a.llm.stop_reason = 'max_tokens'
            self.assertEqual(a.analyze(self.log)['route'], 'review')
            self.assertFalse(a.audit_log)
        for text in ['설명\n```json\n' + payload + '\n```', payload + '\n' + payload,
                     '```json\n' + payload]:
            a = self.assistant(text)
            self.assertEqual(a.analyze(self.log)['route'], 'review')
            self.assertFalse(a.audit_log)

    def test_fabricated_citation_stays_unknown(self):
        a = self.assistant(json.dumps({'verdict': 'ATTACK', 'severity': 4,
                                     'summary': '근거 검토', 'citations': ['not-retrieved']}))
        self.assertEqual(a.analyze(self.log)['route'], 'review')

    def test_valid_json_with_invalid_schema_never_acts(self):
        valid = {'verdict': 'ATTACK', 'severity': 4, 'summary': '근거', 'citations': ['ref-1']}
        cases = [[], None, 4, {**valid, 'severity': None}, {**valid, 'severity': '4'},
                 {**valid, 'severity': True}, {**valid, 'severity': 6},
                 {**valid, 'verdict': []}, {**valid, 'citations': []},
                 {**valid, 'citations': ['fake-id']}]
        for payload in cases:
            with self.subTest(payload=payload):
                a = self.assistant(json.dumps(payload))
                result = a.analyze(self.log)
                self.assertEqual((result['route'], result['verdict']), ('review', 'UNKNOWN'))
                self.assertIn('ml', result)
                self.assertFalse(a.audit_log)

    def test_unknown_with_null_severity_never_acts(self):
        a = self.assistant(json.dumps({'verdict': 'UNKNOWN', 'severity': None,
                                     'summary': '근거 부족', 'citations': []}))
        result = a.analyze(self.log)
        self.assertNotIn('error', result)
        self.assertEqual(result['actions'], [])

    def test_notebook_demo_uses_same_failure_boundary(self):
        # 20장 셀 자체가 가져오는 클래스를 실행해 배포 경로도 검사한다.
        root = Path(__file__).resolve().parents[1]
        notebook = json.loads((root / 'notebooks/solutions/part4/ch20_security_assistant_capstone.ipynb').read_text())
        source = next(''.join(c['source']) for c in notebook['cells']
                      if c['cell_type'] == 'code' and 'from security_assistant import SecurityAssistant' in ''.join(c['source']))
        ns = {}
        exec(compile(source, 'ch20 import cell', 'exec'), ns)
        for text in ['[]', '{"severity": null}', '{"severity": "4"}',
                     '{"verdict":"ATTACK","severity":4,"summary":"fake","citations":["fake-id"]}']:
            a = ns['SecurityAssistant'](None, kb=KnowledgeBase(), llm=FakeLLM(text),
                                       score_fn=lambda _: 0.55)
            self.assertEqual(a.analyze(self.log)['route'], 'review')
            self.assertFalse(a.audit_log)

    def test_demo_score_boundaries_and_nonfinite_values(self):
        for score, route in [(0.29, 'pass'), (0.3, 'review'), (0.9, 'review'),
                             (0.91, 'playbook'), (float('nan'), 'review'),
                             (float('inf'), 'review'), (-1, 'review'), (2, 'review')]:
            with self.subTest(score=score):
                a = SecurityAssistant(None, kb=KnowledgeBase(), llm=FakeLLM('[]'),
                                      score_fn=lambda _, value=score: value)
                self.assertEqual(a.analyze(self.log)['route'], route)

    def test_approval_and_protected_ip(self):
        a = self.assistant('{}', dry_run=False)
        self.assertEqual(a._tool('block_ip', ip='192.0.2.20')['status'], 'denied')
        a.approve = lambda *_: True
        self.assertEqual(a._tool('block_ip', ip='192.0.2.20')['status'], 'mock_approved')
        a.protected_ips.add('192.0.2.20')
        self.assertEqual(a._tool('block_ip', ip='192.0.2.20')['status'], 'denied')
        self.assertEqual(a._tool('unknown')['status'], 'denied')
        self.assertEqual(len(a.audit_log), 4)


if __name__ == '__main__':
    unittest.main()
