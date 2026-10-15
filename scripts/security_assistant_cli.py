"""20장 CLI. 승인된 대응도 모의 실행하며 실제 네트워크를 변경하지 않는다."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_assistant import SecurityAssistant


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', required=True, help='JSON 문자열 또는 UTF-8 JSON 파일')
    parser.add_argument('--ml-model', default='models/nsl_kdd_rf.pickle')
    parser.add_argument('--chroma', default='data/chroma')
    parser.add_argument('--approve-mock', action='store_true', help='모의 차단에 대화형 승인 적용')
    args = parser.parse_args(argv)
    try:
        # JSON 문자열은 먼저 해석한다. 파일은 확장자에 의존하지 않는다.
        try:
            log = json.loads(args.log)
        except json.JSONDecodeError:
            if args.log.lstrip().startswith(('{', '[')):
                raise
            log = json.loads(Path(args.log).read_text(encoding='utf-8'))
        if not isinstance(log, dict):
            raise ValueError('로그는 JSON 객체여야 한다.')
    except (ValueError, OSError) as exc:
        print(json.dumps({'route': 'review', 'ml': None, 'verdict': 'UNKNOWN',
                          'stage': 'input', 'error': type(exc).__name__}, ensure_ascii=False))
        return 2

    def approve(name, params):
        return input(f'모의 작업 {name} {params} 승인? (yes/no): ').strip().lower() == 'yes'

    try:
        assistant = SecurityAssistant(args.ml_model, args.chroma,
                                      os.environ.get('ANTHROPIC_API_KEY'),
                                      dry_run=not args.approve_mock, approve=approve)
    except Exception as exc:
        print(json.dumps({'route': 'review', 'ml': None, 'verdict': 'UNKNOWN',
                          'stage': 'initialization', 'error': type(exc).__name__}, ensure_ascii=False))
        return 2
    print(json.dumps(assistant.analyze(log), ensure_ascii=False, indent=2))
    print(json.dumps({'audit_log': assistant.audit_log}, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
