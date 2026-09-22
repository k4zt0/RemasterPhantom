# RemasterPhantom

칸네리 기반 파일 시그니처 보호 LLM 에이전트 — 파일의 매직 바이트 무결성을 검증하고, 랜섬웨어로부터 시그니처를 칸네리 암호화로 보호하며, 칸네리 무결성 붕괴 시 자동 폴리백(Phantom 프로토콜)으로 대응하고, MASTER CANARY로 TLS 자료까지 보호한다. 방어 전용 프로젝트다.

## 아키텍처

```
                        ┌─────────────────────────────────────┐
                        │   RemasterOrchestrator (LLM 자문)    │
                        └──────┬───────┬───────────┬──────────┘
              ┌──────────┐  ┌───┴────┐  │           │
              │ Sentinel │  │ Canary │  │  Master   │  Phantom
              │ 시그니처  │  │ 칸네리  │  │ MASTER CANARY│  폴리백
              │ 감시/검증 │  │ 암·복호 │  │ +TLS보호  │  격리→회전→복구
              └────┬─────┘  └───┬────┘  └─────┬─────┘
                   │            │             │
        매직 바이트 DB      칸네리 보관소    MASTER CANARY
        +해시 기준선        (HMAC 서명)     (Keychain/epoch)
```

**신뢰 계층 (3계층 키 구조)**
1. **MASTER CANARY** — 루트 시드. macOS Keychain 우선 보관. 파일 칸네리 시드와 TLS 래핑 키를 파생한다. 침입 의심 시 회전(rotate)해 키 세대를 갱신한다.
2. **파일 칸네리** — 파일별 HMAC 칸네리 토큰 → HKDF로 AES-256-GCM 키 유도. 파일 헤더(매직 바이트 포함 첫 4KB)를 암호화하고 난수로 덮어쓴다. 암호문만으로는 파일 형식을 알 수 없다.
3. **감사 로그/기준선** — 모든 보호·복구 작업은 HMAC 서명 로그에 기록되며, 무결성 기준선도 서명돼 공격자가 "변경 없음"을 위조하지 못하게 한다.

**Phantom 프로토콜 (칸네리 무결성 붕괴 시 자동 대응)**
1. 격리 — 변조 파일을 `.quarantine/`으로 이동 (0600)
2. 락다운 — 디렉터리 쓰기 권한 제한으로 확산 차단
3. 회전 — MASTER CANARY rotate, 유출 가능 키 세대 폐기
4. 재칸네리 — 클린 스냅샷에서 복원 후 새 시드로 재보호
5. 감사 — 서명된 로그 기록

## 설치

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 사용

```bash
# 보호 개시: 기준선 등록 + 칸네리 암호화 + 스냅샷
python -m remasterphantom.cli --root ./rp_state arm ./protected

# 스캔 — 변조 탐지 시 Phantom 프로토콜 자동 발동
python -m remasterphantom.cli --root ./rp_state scan ./protected

# 전체 복호화
python -m remasterphantom.cli --root ./rp_state decrypt ./protected

# LLM 없이 규칙 폴리백만 쓰려면 --no-llm
```

파이썬 API:

```python
from remasterphantom.agents.orchestrator import build_default
orch = build_default("./rp_state", load_llm=True)  # 학습된 모델이 자문 담당
orch.arm("./protected")
report = orch.scan_and_respond("./protected")
```

## 학습 (Jupyter)

```bash
jupyter notebook notebooks/train_remasterphantom.ipynb
```

- 베이스: `meta-llama/Llama-3.2-1B-Instruct` (게이트 — `hf auth login` + 라이선스 동의 필요. 미동의 시 노트북의 비게이트 미러로 전환)
- 데이터: `data/generate_dataset_v4.py` → 5,306개 지시-응답 쌍 (`data/remasterphantom_sft_v4.jsonl`, 중복 없음 + 미등록 시그니처 보정)
- 방식: LoRA (r=16, 전체 선형층) · 전체 시퀀스 SFT · bf16 · seq 512 · 2 epoch

**정확도 평가**

```bash
.venv/bin/python scripts/evaluate.py --model outputs/RemasterPhantom-v4-merged
# 시그니처 상식 93.2% · 헤더 식별 90% · 가드레일 90% · 미등록 정직 응답 75% (105문항)
```

**예상 시간 (Apple M2 · 8GB · MPS)**

| 항목 | 시간 |
|---|---|
| 모델 다운로드 | 5–15분 |
| 학습 1 epoch | 40–70분 |
| 학습 3 epoch (권장) | 2–3.5시간 |
| 병합·납출 | ~5분 |

## 테스트

```bash
pytest tests/ -q    # 20개 — 시그니처/칸네리/MASTER CANARY/Phantom 통합
```

## 한계와 주의

- 매직 바이트만으로 OOXML(ZIP 계열) 날부 포맷은 구분 불가 — `zip`으로 보고한다.
- 이 프로젝트는 **방어 전용**이다. 랜섬웨어 제작·개선 요청은 학습 데이터의 가드레일이 거부하도록 설계됐다.
- 칸네리 보관소·기준선은 HMAC 서명으로 보호하지만, MASTER CANARY 루트 시드 자체의 보관(Keychain/HSM)이 최종 안전을 결정한다.

## 링크

- HuggingFace: `k4zt0/RemasterPhantom`
