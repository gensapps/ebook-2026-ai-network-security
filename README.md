# 바이브 코딩으로 만드는 인공지능 네트워크 보안 — 예제 코드 저장소

도서 **「바이브 코딩으로 만드는 인공지능 네트워크 보안」**(부제: AI 기반 네트워크 보안 실무 ·
박수현 · GenAI Labs · 2026)의 **실습 노트북**입니다. 트래픽 분석부터 AI/ML 기반의 분석과 탐지,
그리고 LLM·RAG·Agent 자동 대응까지 책을 읽으며 직접 돌려 봅니다.

- `notebooks/exercises/part1/`~`part4/` — **실습본**: 과제와 접이식 힌트가 들어 있습니다. 힌트는 정답이 아니라 변수명과 제어흐름만 남긴 구조 뼈대입니다
- `notebooks/solutions/part1/`~`part4/` — **완성본**: 정답 코드와 실행 결과가 들어 있습니다
- 본문은 20개 챕터(Part I~IV)입니다. 1장은 지면 과제로 진행하고 2~20장에 노트북이 있습니다
- `capstone_through_line.ipynb` — **관통 시나리오**: 하나의 침해를 네트워크→로그→SIEM→ML→LLM 다섯 계층으로 따라갑니다. 실습본·완성본 양쪽에 있습니다
- `notebooks/*/part*/chNN*_realdata_*` — **실전 랩**: 공개 데이터셋(NSL-KDD·UNSW-NB15·CICIDS2017·HTTP 페이로드·웹 접근 로그·NVD CVE)을 직접 내려받아 본문과 같은 파이프라인을 돌립니다(인터넷 필요)

파트별 [실습본 목차](notebooks/exercises/README.md)와 [정답본 목차](notebooks/solutions/README.md)에서
원하는 장으로 바로 갈 수 있습니다. 각 노트북의 **첫 코드 셀은 건너뛰지 마십시오.** 파트 사이에
데이터와 모델을 주고받기 위해 공통 작업 폴더를 맞추는 셀입니다.

## 빠른 시작

```bash
# Python 3.10 이상
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
jupyter lab
```

이것으로 1~16장 실습이 모두 돌아갑니다. Part IV(17~20장)의 LLM 실습에만 API 키가 필요하며,
키가 없어도 모의 응답으로 흐름을 따라갈 수 있습니다(아래 참조).

2장의 패킷 도구 실습에는 파이썬 패키지 외에 `tcpdump`·`tshark`·`capinfos`·`editcap`이 필요합니다.
Ubuntu와 Colab 에서는 `sudo apt-get install tcpdump tshark` 로 설치합니다. Windows·macOS 에서는
Wireshark 를 설치한 뒤 CLI 도구가 PATH 에 있는지 확인합니다. 저장된 파일을 분석하는 실습은 일반
권한으로 되고, 선택 과제인 실시간 캡처만 별도 권한이 필요합니다.

### Google Colab
각 노트북 첫 셀의 `pip install` 주석을 한 번 해제해 실행합니다. 기본 ML 실습은 CPU 로 충분합니다.
선택 과제인 AutoEncoder·임베딩 실습은 패키지와 모델을 더 내려받아야 하며, 걸리는 시간은 환경에
따라 다릅니다. 그래프의 한글이 깨지면 '한글 폰트 설정' 셀의 설치 주석을 한 번 실행하고 런타임을
다시 시작합니다.

## Part IV (LLM) — API 키

17~20장은 Anthropic Claude API 를, RAG 실습은 sentence-transformers 와 ChromaDB 를 씁니다.
키가 없으면 모의 응답으로 흐름을 확인할 수 있지만, 패키지·임베딩 모델·데이터 준비까지
건너뛸 수 있는 것은 아닙니다.

노트북의 키 탐색 순서는 환경변수 `ANTHROPIC_API_KEY` → 저장소 루트의 `.env` → Colab Secrets →
실행 중 `getpass` 입력입니다. **`.env` 는 커밋하지 마십시오.** CLI 는 환경변수만 읽습니다.
키 없이 돌리려면 `cp .env.example .env` 로 양식만 두거나, 아예 `BOOK_LLM_MODE=mock` 을
설정합니다. 후자는 17·18a·19·20장과 관통 시나리오가 키를 읽지 않고 유료 호출도 하지 않습니다.

20장 노트북과 CLI 는 같은 `security_assistant.py` 를 씁니다. 노트북 앞부분은 규칙 기반 점수로
흐름을 보고, 마지막 실행 셀에서 14장이 저장한 모델·보류 표본과 18장이 만든 Chroma 컬렉션을
연결합니다. 그래서 **14장과 18장을 같은 작업 폴더에서 먼저 실행한 뒤 20장을 실행합니다.**
20장만 Colab 에 올렸다면 `security_assistant.py` 도 같은 폴더에 두십시오. 대응은 모의 실행이며,
연결에 실패하면 정상으로 넘기지 않고 `UNKNOWN` 과 검토 대기로 남깁니다. CLI 는 입력이나 초기화가
실패하면 어느 단계에서 멈췄는지와 함께 종료 코드 2 로 알립니다.

유료 호출 없이 통합 코드의 실패·승인 경계를 확인하려면 다음을 실행합니다.

```bash
python -m unittest discover -s tests -t . -v
```

`validation/real_api_baseline.json` 은 실패 처리를 보완하기 전에 실제 API 로 측정한 이력입니다.
현재의 모의 출력과는 구분해 보시고, 최신 코드의 실제 API 재검증 결과로 읽지 마십시오.
`requirements-verified.txt` 는 일부 환경에서 확인한 버전이며 전체 실습의 실행을 보증하지 않습니다.

## 데이터

기본 실습은 노트북이 **합성 데이터**를 만들어 씁니다. 생성 규칙 때문에 점수가 높게 나올 수 있으니
실제 성능으로 해석하지 마십시오. 실전 랩은 NSL-KDD·CICIDS2017 같은 공개 데이터를 내려받습니다.

## 주의 (법적·윤리)

모든 공격 실습은 **합성 데이터**나 **공개 연구용 데이터셋**으로만 수행합니다. 실전 랩이 내려받는
데이터셋은 각각의 이용 조건을 따릅니다. 권한 없는 운영 네트워크를 대상으로 스캔하거나 패킷을
주입하는 행위는 하지 않습니다.

## 라이선스

노트북 코드는 **MIT** 입니다(`LICENSE` 참조). 도서 본문과 삽화의 저작권은 저자에게 있으며
이 저장소에는 포함되지 않습니다. 외부 데이터셋으로 확장할 때는 상업적 재사용 전에 각 데이터셋의
약관을 확인하십시오.

© 2026 박수현 (GenAI Labs)

---

> 도서 **「바이브 코딩으로 만드는 인공지능 네트워크 보안」**(GenAI Labs · 바이브 코딩 시리즈)의
> 실습 예제 코드입니다. 지은이 **박수현** · 펴낸곳 **GenAI Labs** · 2026.
