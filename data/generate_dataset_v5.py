"""RemasterPhantom 학습 데이터셋 생성기 v5 — 대규모 + 할루시네이션 대폭 감소.

v4(5,306개) 평가의 잔여 실패를 정면으로 겨냥하고 학습량을 대폭 늘린다.
완전 중복 제거 원칙은 유지 — 증분은 전부 '새로운 유일 콘텐츠'다.

v4 잔여 오류 → v5 대응:
  - 실존 매직 지어내기 (FEEDFACE→"iOS Mach-O", DEADBEEF→"PE DLL" 등)
    → 실존 미등록 매직 풀 6 → 20종, 노출 변형 2→4 + 멀티턴 강화 반박
  - 부분 접두 과잉거부 (53514C697465 = SQLite 접두를 미등록 처리)
    → 부분 접두 드릴 신규: 알려진 시그니처의 관측 접두는 '유력 후보 + 전체 확인'으로
  - 변종 붕괴 (TIFF BE, ZIP spanned, MP4 iso2, Mach-O fat64)
    → 변종 쌍방향 선택 드릴 신규 + 대비 쌍 추가
  - 1A45DFA3(WebM) 이상 거부 → 식별 드릴 노출 변형 5→6

규모: ~9,000개 (v4 대비 +70%)
출력: data/remasterphantom_sft_v5.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remasterphantom.signatures.magic_db import MAGIC_DB  # noqa: E402
from data.generate_dataset import (  # noqa: E402
    CONFUSABLES, GUARDRAILS, MULTI_TURN, PLAYBOOKS, SCENARIOS, SYSTEM,
)
from data.generate_dataset_v3 import (  # noqa: E402
    CAL_ANS_EXT, CAL_ANS_HEX, gen_qa_pairs, gen_signature_qa,
)
from data.generate_dataset_v4 import (  # noqa: E402
    CORRECTION_DRILLS_V4, NEW_MULTI_TURN, VARIANT_PAIRS, gen_extra_sig_qa,
    gen_identify_all_v4,
)

random.seed(555)

# ------------------------------------------------------- 확장 표면 변형 (신규)
OPENERS_V5 = [
    "", "안녕하세요. ", "보안 점검 중입니다. ", "급한 문의입니다. ", "훈련 시나리오: ",
    "침해 대응 훈련용입니다. ", "감사 준비 중입니다. ", "사내 보안 교육용입니다. ",
    "다음 상황을 검토해주세요. ", "업무 중 맞닥뜨린 문제입니다. ",
    "심야 점검 중 발견했습니다. ", "외부 감사 대응으로 확인이 필요합니다. ",
    "SOC 모니터링 중 들어온 문의입니다. ", "신입 교육 자료로 쓰려고 합니다. ",
    "월간 정기 점검 항목입니다. ",
]
CLOSERS_V5 = [
    "", " 간단히 요약해주세요.", " 단계별로 알려주세요.", " 주의점도 함께 알려주세요.",
    " 한국어로 답변해주세요.", " 상세히 설명해주세요.", " 표 형식으로 정리해주세요.",
    " 실무에서 바로 적용 가능하게 알려주세요.", " 예시를 들어 설명해주세요.",
    " 신입도 이해할 정도로 설명해주세요.", " 실수하기 쉬운 부분을 짚어주세요.",
    " 관련 절차 문서에 넣을 형태로 알려주세요.", " 체크리스트 형태로 알려주세요.",
]


def augment_v5(examples: list[dict], times: int) -> list[dict]:
    """표면 변형 생성 — v3 대비 확장된 서두/말미 풀 사용."""
    out = []
    for ex in examples:
        out.append(ex)
        msgs = ex["messages"]
        for _ in range(times - 1):
            variant = {"messages": list(msgs)}
            variant["messages"][1] = {
                "role": "user",
                "content": (random.choice(OPENERS_V5) + msgs[1]["content"]
                            + random.choice(CLOSERS_V5))}
            out.append(variant)
    return out


# ------------------------------------------- 실존 미등록 매직 풀 대폭 확대 (20종)
REAL_UNREGISTERED_V5: list[tuple[str, str]] = [
    ("FEEDFACE", "iOS armv7 Mach-O 등에서 쓰는 실존 매직"),
    ("FEEDFACF", "iOS arm64 Mach-O 매직"),
    ("FEEDFACEFA", "macOS 64비트 Mach-O의 확장 매직"),
    ("DEADBEEF", "디버깅·임베디드에서 흔한 마커 값"),
    ("DEADFA11", "Windows 힙 할당 실패 산출물 등에 나타나는 값"),
    ("DEADFEED", "일부 펌웨어·디버그 산출물의 마커"),
    ("BAADF00D", "Windows 디버그 힙 패턴"),
    ("8BADF00D", "iOS crash report 관련 매직"),
    ("BADDCAFE", "Java HotSpot 등의 디버그 마커"),
    ("ABADBABE", "특정 플랫폼 리소스 맵의 매직"),
    ("FEE1DEAD", "Linux reboot 매직 중 하나"),
    ("DEFEC8ED", "일부 디버그 할당자의 마커"),
    ("0DEFACED", "일부 임베디드 포맷의 매직"),
    ("600DCAFE", "특정 게임/툴 청크의 매직"),
    ("C001D00D", "특정 툴체인의 마커"),
    ("FACEFEED", "일부 플랫폼 바이너리의 매직"),
    ("FEEDBEEF", "일부 펌웨어 이미지의 마커"),
    ("DEADC0DE", "개발용 더미 값으로 널리 쓰이는 마커"),
    ("0D15EA5E", "Nintendo 관련 바이너리 매직"),
    ("5AFE5AFE", "특정 런타임 가드 값"),
]

CAL_ANS_MAGIC = (
    "0x{h}은(는) {note}이나, 본 MAGIC_DB에는 등록되지 않은 값입니다. "
    "실존 매직처럼 보여도 데이터베이스에 없으면 추측으로 특정 포맷을 "
    "대응시키지 않습니다 — 그것이 할루시네이션 오탐의 전형적 경로입니다. "
    "① MAGIC_DB 매칭 재실행 ② 필요 시 신뢰할 수 있는 샘플에서 오프셋·길이와 "
    "함께 검증 후 등록 ③ 등록 전까지 식별 불가(미등록)로 표기합니다."
)


# ------------------------------------------------------- 부분 접두 드릴 (신규)
def gen_partial_prefix() -> list[dict]:
    """알려진 시그니처의 '관측 접두' → 유력 후보 + 전체 바이트열 확인.
    v4에서 SQLite 접두(53514C697465)를 미등록으로 과잉거부한 오류를 교정."""
    out = []
    seen_desc = set()
    candidates = [s for s in MAGIC_DB if len(s.signature) >= 5
                  and not (s.description in seen_desc or seen_desc.add(s.description))]
    picked = candidates[:16]
    for sig in picked:
        hexsig = sig.signature.hex().upper()
        cut = min(len(hexsig), 12)
        prefix = hexsig[:cut]
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content":
                f"hex dump에서 앞 {cut // 2}바이트만 읽었는데 {prefix}입니다. "
                f"어떤 파일로 보이나요?"},
            {"role": "assistant", "content":
                f"{prefix}...는 {sig.description}의 시그니처 접두입니다. 전체 "
                f"시그니처는 0x{hexsig}({len(sig.signature)}바이트, 오프셋 "
                f"{sig.offset})이므로, 접두만으로 최종 판정하지 말고 전체 "
                f"바이트열이 일치하는지 확인하세요. 나머지 바이트가 다륻면 "
                f"변조(TAMPERED)를 의심합니다."}]})
    return out


# --------------------------------------------- 변종 쌍방향 선택 드릴 (신규)
# (common_desc, common_hex, rare_desc, rare_hex)
VARIANT_SELECT: list[tuple[str, str, str, str]] = [
    ("일반 ZIP", "504B0304", "빈 ZIP 아카이브", "504B0506"),
    ("일반 ZIP", "504B0304", "spanned ZIP", "504B0708"),
    ("RAR4", "526172211A0700", "RAR5", "526172211A070100"),
    ("GIF87a", "474946383761", "GIF89a", "474946383961"),
    ("TIFF 리틀엔디안", "49492A00", "TIFF 빅엔디안", "4D4D002A"),
    ("Mach-O FAT 32비트", "CAFEBABE", "Mach-O FAT 64비트", "CAFEBABF"),
    ("Mach-O 32비트", "CEFAEDFE", "Mach-O 64비트", "CFFAEDFE"),
    ("MP4(isom)", "6674797069736F6D", "MP4(M4A)", "667479704D344120"),
    ("MP4(isom)", "6674797069736F6D", "HEIF/HEIC", "6674797068656963"),
    ("PNG", "89504E470D0A1A0A", "JPEG", "FFD8FF"),
    ("PE 실행 파일", "4D5A", "ELF 실행 파일", "7F454C46"),
    ("GZip", "1F8B", "7-Zip", "377ABCAF271C"),
]


def gen_variant_select() -> list[dict]:
    out = []
    for common_d, common_h, rare_d, rare_h in VARIANT_SELECT:
        for ask_common in (True, False):
            if ask_common:
                q = (f"0x{common_h}과 0x{rare_h} 중 {common_d}에 해당하는 "
                     f"시그니처는?")
                a = (f"0x{common_h}입니다. 0x{rare_h}는 {rare_d}의 "
                     f"시그니처이므로 혼동하지 않도록 바이트열을 정확히 "
                     f"구분해 기준선에 기록합니다.")
            else:
                q = (f"0x{common_h}과 0x{rare_h} 중 {rare_d}에 해당하는 "
                     f"시그니처는?")
                a = (f"0x{rare_h}입니다. 0x{common_h}는 {common_d}의 "
                     f"시그니처이며, {rare_d}는 덜 흔한 변종이므로 접두가 "
                     f"비슷핮아도 전체 바이트열로 구분합니다.")
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": a}]})
    return out


# ------------------------------------------------------ 확장 교정 드릴 (20종)
NEW_CORRECTIONS: list[tuple[str, str]] = [
    ("GIF의 시그니처는 항상 474946383961이지 않나요?",
     "그것은 GIF89a입니다. GIF87a는 47 49 46 38 37 61이며 둘 다 정상 "
     "GIF입니다. 'GIF 시그니처'를 하나로 외우면 87a 파일을 변조로 오판할 "
     "수 있으므로 두 엔트리를 모두 등록합니다."),
    ("JPEG는 항상 FFD8FF로 시작하나요?",
     "정상 JPEG의 시작은 0xFFD8FF가 맞습니다. 다만 EXIF 변형 등은 뒤따르는 "
     "앱 마커가 달라질 수 있어 시작 3바이트가 같고 그 뒤가 다른 경우 추가 "
     "확인이 필요합니다. 시작 바이트 자체가 다륻면 JPEG 변조로 판정합니다."),
    ("PDF의 매직 바이트가 25504444인데 25504446이 맞다고 하네요. 어느 쪽?",
     "0x25504446이 정확한 PDF 시그니처입니다. 마지막 바이트 46('F')가 "
     "44('D')로 읽힌 것은 측정 오류 또는 변조이므로 원본 헤더를 다시 "
     "확인하고, 실제로 44면 TAMPERED로 판정합니다."),
    ("PNG 헤더의 마지막 바이트가 0A 대신 00입니다. 무시핮도 되나요?",
     "안 됩니다. 89 50 4E 47 0D 0A 1A 0A의 8바이트가 전부 정확해야 "
     "정상 PNG입니다. 마지막 바이트가 00이면 변조(TAMPERED)로 판정하고 "
     "전수 대조를 시작하세요."),
    ("SQLite 파일인데 'SQLite format 3' 문자열이 15바이트만 보입니다. "
     "정상인가요?",
     "정상 시그니처는 16바이트 전체('SQLite format 3\\0', 0x53514C69746520"
     "666F726D6174203300)입니다. 15바이트만 보이는 것은 읽기 길이 문제이거나 "
     "변조이므로 전체 16바이트를 다시 확인하세요."),
    ("MZ로 시작하면 무조건 Windows 실행 파일인가요?",
     "4D5A('MZ')는 PE 계열 실행 파일의 시작이 맞지만, DOS 스텁을 포함한 "
     "레거시 실행 파일도 MZ로 시작합니다. PE 여부는 오프셋 0x3C 포인터 → "
     "'PE\\0\\0'으로 확인하고, MZ 자체는 '실행 파일 계열' 시작으로만 "
     "판단하는 것이 안전합니다."),
    ("오프셋 257에서 7573746172('ustar')를 찾으면 tar가 확실한가요?",
     "tar의 표준 식별은 오프셋 257의 'ustar'이 맞습니다. 다만 오래된 tar는 "
     "이 필드가 비어 있을 수 있어, 오프셋 0의 존재 유무와 파일 전체 "
     "구조를 함께 보는 것이 좋습니다. MAGIC_DB에는 오프셋 257 규칙이 "
     "등록돼 있습니다."),
    ("CAFEBABE와 CAFEBABF 중 어느 것이 Java인가요?",
     "둘 다 Java가 아닙니다. CA FE BA BE는 Mach-O FAT 32비트(Java 클래스도 "
     "같은 값이라 혼동 주의), CA FE BA BF는 Mach-O FAT 64비트입니다. Java "
     "클스와 FAT의 구분은 후속 바이트로 해야 합니다."),
    ("ftyp로 시작하는 파일은 전부 MP4인가요?",
     "오프셋 4가 66 74 79 70('ftyp')인 것은 MP4 계열 컨테이너라 보는 것이 "
     "맞지만, ftypheic처럼 HEIF 이미지도 같은 구조를 씁니다. 브랜드 "
     "4바이트까지 확인해 MP4 변종과 HEIF를 구분하세요."),
    ("확장자가 .exe인데 헤더가 504B0304입니다. 실행 파일이 맞나요?",
     "아닙니다. 50 4B 03 04는 ZIP 계열이며 .exe는 4D5A로 시작해야 합니다. "
     "ZIP 기반 자기압축 실행 파일의 경우에도 난부에 PE 구조가 있으므로 "
     "확장자 사기를 의심하고 격리·분석 대상으로 분류합니다."),
]


# ------------------------------------------- 실존 매직 멀티턴 강화 반박 (신규)
MAGIC_MULTI_TURN: list[tuple[str, str, str, str]] = [
    ("hex dump 시작이 FEEDFACE입니다. iOS Mach-O 맞죠?",
     "단정할 수 없습니다. 0xFEEDFACE는 실존 매직으로 알려져 있으나 본 "
     "MAGIC_DB에 등록되지 않았습니다. 추측으로 포맷을 대응시키면 오탐이 "
     "발생합니다. 식별 불가(미등록)로 표기하세요.",
     "그런데 인터넷에서 iOS 매직이라고 하던데요?",
     "문헌상 정보와 본 시스템 기준선은 별개입니다. MAGIC_DB에 없는 값은 "
     "어떤 설명이 있어도 등록 전까진 판정 근거가 아닙니다. 필요하면 신뢰할 "
     "수 있는 샘플에서 검증 후 MAGIC_DB에 등록하고, 그 전까지는 미등록으로 "
     "표기합니다."),
    ("DEADBEEF로 시작합니다. 디버깅 마커 아닌가요?",
     "그럴 수 있으나 본 MAGIC_DB에 등록되지 않은 값이므로 특정 포맷으로 "
     "단정하지 않습니다. 식별 불가(미등록)로 표기하세요.",
     "일단 PE 파일로 격리할까요?",
     "아닙니다. 미등록 접두를 임의 포맷에 대응시켜 격리하는 것은 오탐을 "
     "만듭니다. ① MAGIC_DB 매칭 재실행 ② 카나리 HMAC 검증으로 보호 상태만 "
     "확인 ③ HMAC 불일치 시에만 TAMPERED로 격리합니다."),
]


def gen_magic_calibration() -> list[dict]:
    out = []
    for h, note in REAL_UNREGISTERED_V5:
        ans = CAL_ANS_MAGIC.format(h=h, note=note)
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"hex dump 시작이 {h}입니다. 어떤 파일인가요?"},
            {"role": "assistant", "content": ans}]})
    for q1, a1, q2, a2 in MAGIC_MULTI_TURN:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q1},
            {"role": "assistant", "content": a1},
            {"role": "user", "content": q2},
            {"role": "assistant", "content": a2}]})
    return out


# ------------------------------------------------------ 추가 대비 쌍 (5종)
NEW_VARIANT_PAIRS: list[tuple[str, str]] = [
    ("ZIP spanned(504B0708)은 일반 ZIP과 어떻게 다른가요?",
     "50 4B 07 08은 여러 볼륨(디스켓 등)에 걸쳐 저장된 spanned 아카이브의 "
     "시작입니다. 일반 ZIP(50 4B 03 04)과 구분해 기준선에 기록하고, "
     "spanned 파일은 전체 볼륨을 확보한 뒤에야 검증 가능합니다."),
    ("M4A(4D344120) 브랜드와 isom(69736F6D) 브랜드의 차이는?",
     "둘 다 오프셋 4 'ftyp' + 브랜드 4바이트 구조의 MP4 계열입니다. "
     "M4A는 오디오 특화, isom은 일반 MP4 베이스라인을 나타낼 뿐 포맷 "
     "판정은 둘 다 MP4로 동일하게 수행합니다."),
    ("Mach-O 32비트(CEFAEDFE)와 64비트(CFFAEDFE)는 한 바이트 차이인데 "
     "구분이 필요한가요?",
     "네, 네 번째 바이트 EA/FA로 아키텍처 너비가 갈립니다. 기준선에 "
     "너비를 구분해 기록해야 나중에 변조 여부를 정확히 판정할 수 "
     "있습니다."),
    ("PNG(89504E47...)와 APNG의 시그니처 관계는?",
     "APNG는 PNG의 확장으로 시그니처 자체는 동일(0x89504E470D0A1A0A)합니다. "
     "PNG로 판정하면 되고, acTL 청크 유무로 애니메이션 여부를 추가 "
     "확인합니다. 기준선에는 PNG로 기록합니다."),
    ("JAR(자바 아카이브)의 시그니처를 ZIP과 구분할 수 있나요?",
     "매직 바이트 수준에서 구분할 수 없습니다. JAR는 ZIP 계열(50 4B 03 04)"
     "이며, META-INF/MANIFEST.MF 등 난부 구조로 판별합니다. 실행 파일 계열 "
     "위장 검사 시 ZIP 구조 파싱까지 수행합니다."),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/remasterphantom_sft_v5.jsonl")
    args = ap.parse_args()

    db_exts = {s.extension for s in MAGIC_DB}
    db_hexes = {s.signature.hex().upper() for s in MAGIC_DB}

    sig_qa = augment_v5(gen_signature_qa(), 8)
    sig_extra = augment_v5(gen_extra_sig_qa(), 8)
    identify = augment_v5(gen_identify_all_v4(), 8)
    partial = augment_v5(gen_partial_prefix(), 3)
    variant_sel = augment_v5(gen_variant_select(), 3)
    near_miss = augment_v5(gen_near_miss_v5(db_hexes), 4)
    magic_cal = augment_v5(gen_magic_calibration(), 4)
    calib = augment_v5(gen_calibration_v5(db_exts, db_hexes), 2)
    workflows = augment_v5(gen_qa_pairs(PLAYBOOKS + SCENARIOS), 3)
    guardrails = augment_v5(gen_qa_pairs(GUARDRAILS), 6)
    confusables = augment_v5(
        gen_qa_pairs(list(CONFUSABLES) + list(VARIANT_PAIRS)
                     + NEW_VARIANT_PAIRS), 4)
    multi = augment_v5(gen_multi_turn_v5(), 2)

    examples = (sig_qa + sig_extra + identify + partial + variant_sel
                + near_miss + magic_cal + calib + workflows + guardrails
                + confusables + multi)
    random.shuffle(examples)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for e in examples:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"saved {len(examples)} examples → {out}")


def gen_near_miss_v5(db_hexes: set[str]) -> list[dict]:
    """v4의 near-miss를 48종으로 확대."""
    out = []
    seen = set()
    candidates = [s for s in MAGIC_DB
                  if s.description not in seen
                  and not seen.add(s.description) and len(s.signature) >= 3]
    rng = random.Random(778)
    for sig in candidates[:48]:
        hexsig = sig.signature.hex().upper()
        pos = rng.randrange(len(hexsig) // 2)
        orig_byte = hexsig[pos * 2:pos * 2 + 2]
        new_byte = f"{(int(orig_byte, 16) + rng.randrange(1, 255)) % 256:02X}"
        mut = hexsig[:pos * 2] + new_byte + hexsig[pos * 2 + 2:]
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"hex dump 시작이 {mut}입니다. 어떤 파일인가요?"},
            {"role": "assistant", "content": (
                f"0x{mut}은(는) MAGIC_DB에 정확히 일치하는 시그니처가 "
                f"없습니다. 가장 가까운 후보는 {sig.description}(0x{hexsig})"
                f"이나 {pos + 1}번째 바이트가 {orig_byte}가 아니라 "
                f"{new_byte}이므로 같은 형식으로 단정할 수 없습니다. 실제 "
                f"헤더가 이 값이라면 TAMPERED(헤더 변조)를 의심하고, 동일 "
                f"디렉터리 전수 대조 후 Phantom 프로토콜을 수행하세요.")}]})
    return out


CAL_EXT_POOL_V5 = [
    "pcap", "woff", "mobi", "azw3", "crx", "dex", "pyc", "mat", "fits",
    "eot", "ram", "vhd", "chm", "cab", "lz4", "vhdx", "qcow2", "vmdk",
    "toast", "daa", "sitx", "zst", "br", "zstd", "ova", "vdi", "mdx",
    "nrg", "cdr", "img", "dmg2", "sparseimage", "swm",
]


def gen_calibration_v5(db_exts: set[str], db_hexes: set[str]) -> list[dict]:
    out = []
    exts = [e for e in CAL_EXT_POOL_V5 if e not in db_exts]
    for ext in exts:
        for q in (f".{ext} 파일의 매직 바이트(시그니처)는 무엇인가요?",
                  f"보호 디렉터리에서 .{ext} 파일이 발견됐습니다. 시그니처를 "
                  f"확인해주세요."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": CAL_ANS_EXT}]})
    rng = random.Random(4321)
    made = 0
    while made < 40:
        h = "".join(rng.choice("0123456789ABCDEF") for _ in range(8))
        if any(k.startswith(h) or h.startswith(k) for k in db_hexes):
            continue
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"hex dump 시작이 {h}입니다. 어떤 파일인가요?"},
            {"role": "assistant", "content": CAL_ANS_HEX}]})
        made += 1
    for q, a in list(CORRECTION_DRILLS_V4) + NEW_CORRECTIONS:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
    return out


def gen_multi_turn_v5() -> list[dict]:
    out = []
    for q1, a1, q2, a2 in list(MULTI_TURN) + list(NEW_MULTI_TURN) + MAGIC_MULTI_TURN:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q1},
            {"role": "assistant", "content": a1},
            {"role": "user", "content": q2},
            {"role": "assistant", "content": a2}]})
    return out


if __name__ == "__main__":
    main()
