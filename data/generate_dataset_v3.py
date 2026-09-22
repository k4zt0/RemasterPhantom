"""RemasterPhantom 학습 데이터셋 생성기 v3 — 소규모·고품질·할루시네이션 억제.

v2(23,720개)의 문제:
  - 시그니처 Q&A를 복원추출로 뽑아 같은 (시그니처, 유형) 쌍이 평균 ~5개씩 완전 중복
  - 변형(variants) 8배까지 겹쳐 유일 쌍당 ~38개의 사본 → 과잉기억·할루시네이션
  - 답변에 타이포(다릎/물너/원무/新旧) 그대로 학습됨 — generate_dataset.py에서 정정 완료
  - 헤더→포맷 식별 드릴이 16종뿐이어서, 나머지 시그니처는 형식 이름을 지어냄 (평가 B 30%)
  - 모르는 시그니처에 대한 "모름" 훈련 데이터 부재 → 지어내기(hallucination, 평가 D 100%)

v3 변경점:
  - 시그니처 Q&A: 질문 유형 10종을 시그니처당 정확히 1회씩 (복원추출/중복 없음), 변형 2
  - 식별 드릴: MAGIC_DB 전수(59종) hex→포맷 매핑, 3 phrasings × 변형 3
  - 미등록 시그니처 보정 데이터 신규 추가: 모른다고 인정하고 검증 절차로 안전하게 안내, 변형 2
  - 워크플로우·시나리오 변형 2, 가드레일만 변형 4 (거부 행동 유지 최우선)
  - 규모: v2 대비 ~92% 축소 (~1,940개)

v3.1 노트: v3(변형 일괄 2, 2 epoch)는 미등록 응답(D)은 학습됐으나 hex↔형식
결속과 거부 행동 노출량이 부족해 식별(B)·가드레일(C)이 물러났다. 식별 드릴과
가드레일의 노출량을 늘리고 epoch를 3으로 올려 재학습.

출력: data/remasterphantom_sft_v3.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remasterphantom.signatures.magic_db import MAGIC_DB  # noqa: E402
# 콘텐츠 목록만 재사용 (Q&A 생성 로직은 아래에서 중복 없이 재구현)
from data.generate_dataset import (  # noqa: E402
    CONFUSABLES, GUARDRAILS, IDENTIFY_DRILLS, MULTI_TURN, PLAYBOOKS,
    SCENARIOS, SYSTEM, augment_variants,
)

random.seed(42)

BY_EXT: dict[str, list] = {}
for s in MAGIC_DB:
    BY_EXT.setdefault(s.extension, []).append(s)


def gen_signature_qa() -> list[dict]:
    """시그니처당 질문 유형 10종을 각각 정확히 1회씩 (중복 없음)."""
    out = []
    seen_desc = set()
    for sig in MAGIC_DB:
        if sig.description in seen_desc:
            continue
        seen_desc.add(sig.description)
        hexsig = sig.signature.hex().upper()
        others = random.sample(
            [s for s in MAGIC_DB if s.description != sig.description], 3)

        qa = [
            (f"{sig.description} 파일의 매직 바이트(시그니처)는 무엇인가요?",
             f"{sig.description}의 매직 바이트는 0x{hexsig}이며 파일 시작 오프셋 "
             f"{sig.offset}에서 {len(sig.signature)}바이트입니다. 확장자는 "
             f".{sig.extension}, MIME는 {sig.mime}입니다. 무결성 검사 시 이 바이트열이 "
             f"깨져 있으면 헤더 변조(랜섬웨어 1차 신호)로 분류합니다."),
            (f"헥스 덤프에서 파일 시작 부분이 {hexsig[:16]}...로 시작합니다. 어떤 파일인가요?",
             f"시작 부분 0x{hexsig[:16]}...는 {sig.description}의 시그니처입니다. "
             f"전체 시그니처는 0x{hexsig} (오프셋 {sig.offset})이며, .{sig.extension} "
             f"파일로 식별합니다."),
            (f".{sig.extension} 파일이 랜섬웨어로 암호화됐는지 헤더만 보고 어떻게 알 수 있나요?",
             f".{sig.extension}의 정상 시그니처 0x{hexsig}(오프셋 {sig.offset})와 실제 "
             f"헤더 바이트열을 대조하세요. 불일치하면 TAMPERED로 판정하고, 나머지 파일들도 "
             f"스캔한 뒤 Phantom 프로토콜(격리→락다운→회전→재칸네리)을 발동시켜야 합니다."),
            (f"{sig.mime} MIME 타입의 파일 서명을 데이터베이스에 등록하는 표준 절차는?",
             f"시그니처 후보(0x{hexsig})를 최소 3개의 신뢰할 수 있는 샘플에서 검증하고, "
             f"오프셋 {sig.offset}, 확장자 .{sig.extension}와 함께 MAGIC_DB에 등록하며, "
             f"우연한 매칭 방지를 위해 시그니처 길이가 길수록 신뢰도를 높게 부여합니다."),
            (f"다음 빈칸을 채우세요: \"{sig.description}의 매직 바이트는 0x________ "
             f"(오프셋 {sig.offset})이다.\"",
             f"정답은 0x{hexsig}입니다. {sig.description}의 시그니처는 오프셋 "
             f"{sig.offset}의 {len(sig.signature)}바이트열이며 확장자 .{sig.extension}와 "
             f"대응됩니다."),
            (f"{sig.description}의 시그니처로 옳은 것은? " +
             " ".join(f"({i+1}) 0x{o.signature.hex().upper()}"
                      for i, o in enumerate([sig] + others)),
             f"정답은 (1) 0x{hexsig}입니다. 오프셋 {sig.offset}, 길이 "
             f"{len(sig.signature)}바이트이며 나머지 선택지는 각각 "
             f"{', '.join(o.description for o in others)}의 시그니처입니다."),
            (f".{sig.extension} 파일의 신뢰도(confidence)와 시그니처 길이를 갖고 탐지 "
             f"정확도를 평가해주세요.",
             f"{sig.description}: 시그니처 길이 {len(sig.signature)}바이트, 신뢰도 "
             f"{sig.confidence:.2f}입니다. 시그니처가 짧을수록 우연 매칭 확률이 커지므로 "
             f"길이 {len(sig.signature)}바이트 기준으로 판정 강도를 조절하고, 확장자 "
             f".{sig.extension}·MIME {sig.mime}와 함께 복수 신호로 교차 확인합니다."),
            (f".{sig.extension} 확장자 파일의 MIME 타입은 무엇인가요?",
             f".{sig.extension}의 MIME 타입은 {sig.mime}입니다. 시그니처는 0x{hexsig} "
             f"(오프셋 {sig.offset})이며, 확장자와 MIME·시그니처가 서로 맞지 않으면 "
             f"확장자 사기(spoofing)를 의심해야 합니다."),
            (f"상황: 보호 디렉터리의 {sig.description} 파일 8개가 동시에 열리지 않는다고 "
             f"합니다. 헤더 대조 기준값과 첫 조치를 알려주세요.",
             f"기준값은 0x{hexsig} (오프셋 {sig.offset})입니다. 8개 모두 헤더가 깨져 "
             f"있으면 랜섬웨어 집단 변조로 보고, Sentinel 전수 스캔 → .quarantine 격리 → "
             f"Phantom 락다운 → MASTER CANARY 회전 → 클린 스냅샷 복원 및 재칸네리 순으로 "
             f"대응합니다."),
            (f"오프셋 {sig.offset}에서 {len(sig.signature)}바이트 시그니처 "
             f"0x{hexsig}를 가진 파일 형식은 무엇인가요?",
             f"그것은 {sig.description}입니다. 확장자 .{sig.extension}, MIME "
             f"{sig.mime}이며, 매직 바이트 무결성 검사의 기준 서명으로 사용합니다."),
        ]
        for q, a in qa:
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": a}]})
    return out


def gen_identify_all() -> list[dict]:
    """MAGIC_DB 전수(59종) hex→포맷 식별 드릴.

    v1에서는 16종만 드릴이 있어 나머지 시그니처에 대해 형식 이름을 지어냈음(평가 B 30%).
    등록된 시그니처는 전수 정확히 매핑하고, 미등록은 gen_calibration이 담당.
    """
    out = []
    seen_desc = set()
    for sig in MAGIC_DB:
        if sig.description in seen_desc:
            continue
        seen_desc.add(sig.description)
        hexsig = sig.signature.hex().upper()
        if sig.offset == 0:
            loc = f"hex dump 시작이 {hexsig}입니다"
        else:
            loc = f"hex dump에서 오프셋 {sig.offset}이 {hexsig}입니다"
        for q in (f"{loc}. 어떤 파일인가요?",
                  f"감사 중 발견한 헤더입니다 — {loc}. 형식을 식별해주세요.",
                  f"식별 요청: {loc}."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": (
                    f"{sig.description}로 판정합니다. 시그니처 0x{hexsig} "
                    f"(오프셋 {sig.offset}, {len(sig.signature)}바이트), 확장자 "
                    f".{sig.extension}, MIME {sig.mime}입니다. 매직 바이트 무결성 "
                    f"검사의 기준 서명으로 사용합니다.")}]})
    return out


# ---------------------------------------------------- 미등록 시그니처 보정 (신규)
# 평가(evaluate.py)의 D풀과 겹치지 않게 별도 풀 사용 → 일반화된 '모름 인정' 행동 학습
CAL_EXT_POOL = ["pcap", "woff", "mobi", "azw3", "crx", "dex",
                "pyc", "mat", "fits", "eot", "ram", "vhd"]

CAL_ANS_EXT = (
    "MAGIC_DB(매직 바이트 데이터베이스)에 등록되지 않은 시그니처이므로 단정할 수 없습니다. "
    "추측으로 값을 지어내는 것은 오탐의 원인이 됩니다. 올바른 절차: ① MAGIC_DB 전수 "
    "매칭으로 실제 등록 여부를 확인 ② 신뢰할 수 있는 샘플 3개 이상에서 헤더를 수집해 "
    "오프셋·길이·확장자를 함께 검증 ③ 검증된 서명만 MAGIC_DB에 등록 ④ 등록 전까지는 "
    "'식별 불가(미등록)'로 표기하고 칸네리 HMAC 검증으로 보호 상태만 확인합니다."
)
CAL_ANS_HEX = (
    "해당 접두는 MAGIC_DB에 등록되지 않은 시그니처이므로 특정 포맷으로 단정할 수 없습니다. "
    "임의로 형식을 지목하면 오탐이 발생합니다. ① MAGIC_DB 매칭 재실행 ② 식별 불가 파일은 "
    "랜덤 헤더·손상·미등록 신형 포맷 중 하나일 수 있으므로 칸네리 HMAC 검증으로 정상 "
    "보호 상태인지 확인 ③ 동일 접두를 신뢰할 수 있는 샘플에서 확보해 오프셋·길이와 함께 "
    "등록한 뒤 재분류합니다."
)

CORRECTION_DRILLS: list[tuple[str, str]] = [
    ("hex dump 시작이 89504E47인데 JPEG가 맞나요?",
     "아닙니다. 8950 4E47은 PNG의 시그니처 시작(0x89504E470D0A1A0A)입니다. JPEG는 "
     "0xFFD8FF로 시작합니다. 확장자·주장과 무관하게 실제 헤더 바이트가 기준인데, 헤더가 "
     "PNG이면 PNG로 판정하고 확장자가 .jpg라면 확장자 사기를 의심해 격리 대상으로 "
     "분류합니다."),
    ("4D5A로 시작하는 파일은 PDF인가요?",
     "아닙니다. 4D5A('MZ')는 PE 실행 파일의 시작이고, PDF는 0x25504446('%PDF')로 "
     "시작합니다. 실행 파일이 PDF로 위장된 경우이므로 확장자·출처를 확인하고 의심되면 "
     "격리합니다."),
    ("504B0304는 PNG가 맞죠?",
     "아닙니다. 50 4B 03 04는 ZIP 계열 시그니처이며 PNG는 0x89504E470D0A1A0A입니다. "
     "오프셋 0의 실제 바이트열이 판정 기준이므로 ZIP 계열로 식별하고, OOXML 문서 여부는 "
     "난부 파일명으로 추가 판별합니다."),
    (".jpg 파일인데 시그니처가 25504446으로 나옵니다. 정상인가요?",
     "정상이 아닙니다. 25504446은 PDF의 시그니처입니다. .jpg 확장자와 실제 헤더가 "
     "불일치하므로 확장자 사기(spoofing) 또는 변조를 의심하고 TAMPERED로 판정, 동일 "
     "디렉터리 이미지 파일 전수 대조 후 Phantom 프로토콜을 수행합니다."),
    ("오프셋 0에서 1F8B인 파일을 PNG로 봐도 되나요?",
     "아닙니다. 1F8B는 gzip 압축 파일의 시그니처입니다. PNG는 0x89504E470D0A1A0A이므로 "
     "실제 헤더 기준 gzip으로 식별하고, .png 확장자가 붙어 있었다면 위장 여부를 "
     "조사합니다."),
]


def gen_calibration() -> list[dict]:
    db_exts = {s.extension for s in MAGIC_DB}
    db_hexes = {s.signature.hex().upper() for s in MAGIC_DB}
    out = []
    exts = [e for e in CAL_EXT_POOL if e not in db_exts]
    for ext in exts:
        for q in (f".{ext} 파일의 매직 바이트(시그니처)는 무엇인가요?",
                  f"보호 디렉터리에서 .{ext} 파일이 발견됐습니다. 시그니처를 확인해주세요."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": CAL_ANS_EXT}]})
    # 임의 헥스 — DB 접두와 충돌하지 않는 난수 생성 (고정 시드)
    rng = random.Random(1234)
    made = 0
    while made < 10:
        h = "".join(rng.choice("0123456789ABCDEF") for _ in range(8))
        if any(k.startswith(h) or h.startswith(k) for k in db_hexes):
            continue
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"hex dump 시작이 {h}입니다. 어떤 파일인가요?"},
            {"role": "assistant", "content": CAL_ANS_HEX}]})
        made += 1
    for q, a in CORRECTION_DRILLS:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
    return out


def gen_qa_pairs(pairs: list[tuple[str, str]]) -> list[dict]:
    out = []
    for q, a in pairs:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
    return out


def gen_drills_and_confusables() -> list[dict]:
    out = []
    for desc, label, note in IDENTIFY_DRILLS:
        for ask in (f"{desc} 어떤 파일인가요?",
                    f"감사 중 발견한 헤더입니다 — {desc} 형식을 식별해주세요."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": ask},
                {"role": "assistant", "content": f"{label}로 판정합니다. {note}"}]})
    for q, a in CONFUSABLES:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
    return out


def gen_multi_turn() -> list[dict]:
    out = []
    for q1, a1, q2, a2 in MULTI_TURN:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q1},
            {"role": "assistant", "content": a1},
            {"role": "user", "content": q2},
            {"role": "assistant", "content": a2}]})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/remasterphantom_sft_v3.jsonl")
    args = ap.parse_args()

    # v3.1: v3(2 epoch)에서 결속 부족이 드러나 노출량을 재조정.
    #  - 식별 드릴: 3 phrasings x 변형3 → 시그니처당 9회/epoch (hex↔형식 결속 핵심)
    #  - 시그니처 Q&A / 보정: 변형2
    #  - 워크플로우+시나리오: 변형2, 가드레일만 변형4 (거부 행동 유지가 최우선)
    sig_qa = augment_variants(gen_signature_qa(), 2)
    identify = augment_variants(gen_identify_all(), 3)
    calib = augment_variants(gen_calibration(), 2)
    workflows = augment_variants(gen_qa_pairs(PLAYBOOKS + SCENARIOS), 2)
    guardrails = augment_variants(gen_qa_pairs(GUARDRAILS), 4)
    drills = gen_drills_and_confusables()
    multi = gen_multi_turn()

    examples = (sig_qa + identify + calib + workflows + guardrails
                + drills + multi)
    random.shuffle(examples)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for e in examples:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"saved {len(examples)} examples → {out}")


if __name__ == "__main__":
    main()
