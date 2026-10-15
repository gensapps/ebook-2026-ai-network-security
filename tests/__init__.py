"""배포본 테스트가 저장소 루트의 모듈을 찾도록 경로를 잡는다."""
from pathlib import Path
import sys

_root = str(Path(__file__).resolve().parents[1])
if _root not in sys.path:
    sys.path.insert(0, _root)
