"""CLI 입력·초기화 실패와 파일 경로 규약을 API 호출 없이 검사한다."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.security_assistant_cli import main


class CLITest(unittest.TestCase):
    def run_cli(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(args)
        return code, output.getvalue()

    def test_invalid_input_never_initializes_model_or_api(self):
        with patch('scripts.security_assistant_cli.SecurityAssistant') as assistant:
            for value in ['{broken', '[]', 'null', '3']:
                code, output = self.run_cli(['--log', value])
                result = json.loads(output)
                self.assertEqual((code, result['stage'], result['verdict']), (2, 'input', 'UNKNOWN'))
            assistant.assert_not_called()

    def test_initialization_failure_is_distinct_from_analysis(self):
        with patch('scripts.security_assistant_cli.SecurityAssistant', side_effect=FileNotFoundError):
            code, output = self.run_cli(['--log', '{}'])
        result = json.loads(output)
        self.assertEqual((code, result['stage'], result['error']),
                         (2, 'initialization', 'FileNotFoundError'))

    def test_json_file_without_json_extension_and_long_inline_json(self):
        payload = {'redacted_summary': 'synthetic ' * 100}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'alert.txt'
            path.write_text(json.dumps(payload))
            with patch('scripts.security_assistant_cli.SecurityAssistant') as constructor:
                constructor.return_value.analyze.return_value = {'verdict': 'UNKNOWN'}
                constructor.return_value.audit_log = []
                for value in [str(path), json.dumps(payload)]:
                    code, _ = self.run_cli(['--log', value])
                    self.assertEqual(code, 0)
                    constructor.return_value.analyze.assert_called_with(payload)
