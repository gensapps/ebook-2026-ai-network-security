"""현행 20장 구성의 원고·노트북 위치와 공통 작업 경로의 단일 출처.

경로를 쓰는 쪽(빌드·동기화·배포·검증·테스트)은 여기서 가져다 쓴다.
구성이 바뀌면 이 파일만 고친다.
"""
from pathlib import Path
import re

PARTS = {'part1': (1, 6), 'part2': (7, 11), 'part3': (12, 16), 'part4': (17, 20)}

# 서문은 Part I 폴더 안에 둔다. 루트에는 원고를 두지 않는다.
PREFACE_REL = 'part1_네트워크_구조와_위협_이해/00_서문.md'


def manuscripts(root):
    """서문 + 20개 장을 읽는 순서대로 돌려준다."""
    return [Path(root) / PREFACE_REL, *sorted(Path(root).glob('part*/ch*.md'))]
BOOTSTRAP_ID = 'book-shared-workdir'
BOOTSTRAP = '''# 파트별 노트북은 같은 종류의 공통 데이터·모델 작업 폴더를 사용합니다.
from pathlib import Path as _BookPath
import os as _book_os
_book_cwd = _BookPath.cwd()
if (_book_cwd.name in {"part1", "part2", "part3", "part4"}
        and _book_cwd.parent.name in {"instructor", "exercises", "solutions"}):
    _book_os.chdir(_book_cwd.parent)
'''


def notebook_relative(name):
    name = Path(name).name
    if not name.endswith('.ipynb'):
        name += '.ipynb'
    if name == 'capstone_through_line.ipynb':
        return Path('part4') / name
    match = re.match(r'ch(\d{2})[a-z]?_', name)
    if not match:
        raise ValueError(f'알 수 없는 노트북: {name}')
    number = int(match[1])
    for part, (start, end) in PARTS.items():
        if start <= number <= end:
            return Path(part) / name
    raise ValueError(f'장 번호 범위 밖: {name}')


def notebook_path(root, kind, name):
    if kind not in {'instructor', 'exercises', 'solutions'}:
        raise ValueError(kind)
    return Path(root) / 'notebooks' / kind / notebook_relative(name)


def ensure_bootstrap(nb):
    if any(c.get('id') == BOOTSTRAP_ID for c in nb['cells']):
        return
    index = next((i for i,c in enumerate(nb['cells']) if c['cell_type'] == 'code'), len(nb['cells']))
    nb['cells'].insert(index, {'cell_type':'code', 'id':BOOTSTRAP_ID,
        'metadata':{'tags':['book-workdir']}, 'source':BOOTSTRAP.splitlines(keepends=True),
        'execution_count':None, 'outputs':[]})
