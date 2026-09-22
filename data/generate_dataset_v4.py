"""RemasterPhantom 학습 데이터셋 생성기 v4 — 대규모 + 할루시네이션 대폭 감소.

v3.1(1,941개) 평가에서 드러난 잔여 과제를 반영해 규모를 대폭 확대하면서
v3의 핵심 원칙(완전 중복 제거·전수 식별 드릴·미등록 보정)을 유지한다.

v3.1 잔여 오류 → v4 대응:
  - 변종 구분 붕괴 (ZIP empty/spanned, RAR4/5, MP4 브랜드, TIFF 엔디안,
    Mach-O fat 32/64, GIF87a/89a) → 변종 대비 쌍 드릴 신규 + 혼동쌍 변형 4
  - 근접 hex 허용 (FEEDFACE 등 실존 매직 혼동, 1바이트 변이) → near-miss 보정 신규
  - 미등록 보정 커버리지 부족 → 확장자 풀 12→24, 랜덤 hex 10→24,
    실존 미등록 매직 명시 풀, 교정 드릴 5→12

규모 구성 (완전 중복 없음):
  - 시그니처 Q&A 10종 × 변형4 + 종합/변조/오프셋/등록심사 4종 × 변형4
  - 식별 드릴 5 phrasings × 변형5 (시그니처당 25회/epoch)
  - 변종 대비 쌍 15쌍 × 변형3, near-miss 24종 × 변형3
  - 미등록 보정(확장자 24·랜덤 hex 24·실존 미등록 매직 6·교정 12) × 변형2~3
  - 워크플로우 변형3, 가드레일 변형6, 혼동쌍 변형4, 멀티턴 20종 × 변형2
  - 합계 ~5,400개 (v3.1 대비 2.8배, v2 23,720 대비 -77%)

출력: data/remasterphantom_sft_v4.jsonl
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
    augment_variants,
)
from data.generate_dataset_v3 import (  # noqa: E402
    CAL_ANS_EXT, CAL_ANS_HEX, gen_qa_pairs, gen_signature_qa,
)

random.seed(2024)

# ------------------------------------------------------------- 변종 대비 쌍 (신규)
# v3.1에서 모델이 흔한 형제 엔트리로 붕괴한 쌍들 — 양방향 대비를 명시적으로 학습.
VARIANT_PAIRS: list[tuple[str, str]] = [
    ("50 4B 03 04로 시작하는 일반 ZIP과 50 4B 05 06(빈 아카이브), "
     "50 4B 07 08(spanned)의 차이는?",
     "50 4B 03 04는 로컬 파일 헤더가 있는 일반 ZIP, 50 4B 05 06은 End of Central "
     "Directory만 있는 빈 아카이브, 50 4B 07 08은 여러 볼륨에 걸친 spanned "
     "아카이브의 시작입니다. 변조 판정 시 정상 형태와 정확히 대조해야 하며, "
     "빈 아카이브로 위장한 파일은 구조 전체 검사 대상입니다."),
    ("MP4 계열의 ftyp 브랜드(isom/iso2/M4A 20/mp41)를 헥스로 구분하는 방법은?",
     "모두 오프셋 4의 66 74 79 70('ftyp') + 브랜드 4바이트로 식별합니다: "
     "6973 6F6D=isom, 6973 6F32=iso2, 4D34 4120=M4A, 6D70 3431=mp41. "
     "브랜드 값은 변종 정보일 뿐 포맷은 모두 MP4 계열로 처리하되, 기준선에는 "
     "브랜드까지 기록해 변조 여부를 판정합니다."),
    ("ftypheic(6674797068656963)와 ftypisom(6674797069736F6D)을 혼동하면 "
     "어떤 문제가 생기나요?",
     "둘 다 'ftyp'로 시작하는 브랜드 시그니처이므로 브랜드 4바이트까지 대조해야 "
     "합니다. heic=HEIF/HEIC 이미지, isom=MP4 컨테이너이며 브랜드만 보고 단정하면 "
     "이미지를 영상으로 오식별합니다. 랜섬웨어 판정에서는 포맷 오판이 곧 오탐으로 "
     "이어지므로 브랜드 바이트열까지 정확히 대조합니다."),
    ("GIF87a(474946383761)와 GIF89a(474946383961)의 매직 바이트를 각각 쓰는 "
     "이유는? 둘 중 어느 쪽이 '정상'인가요?",
     "둘 다 정상 GIF입니다. 6바이트째가 37('7')이면 GIF87a, 39('9')이면 "
     "GIF89a이며, MAGIC_DB에는 두 엔트리를 별도로 등록합니다. 변조 판정은 GIF "
     "계열 여부만 확인하면 되고, 버전 구분은 기준선에 기록하는 용도입니다."),
    ("GIF 시그니처가 47494638('GIF8')까지만 맞고 6바이트째가 37/39가 아니면?",
     "GIF 변조로 판정합니다. 47 49 46 38까지는 일치하나 6바이트가 다를면 "
     "GIF87a/89a 둘 다 아니므로 TAMPERED로 분류하고, 동일 디렉터리 GIF 전수 "
     "대조 후 Phantom 프로토콜을 수행합니다."),
    ("RAR4(526172211A0700)와 RAR5(526172211A070100)는 몇 바이트째로 "
     "구분하나요?",
     "공통 52 61 72 21 1A 07(7바이트)까지 동일하고, 8바이트째가 00이면 "
     "RAR4, 01 00이면 RAR5입니다. 기준선에 버전을 구분해 기록하지 않으면 "
     "RAR4 헤더를 변조로 오판하거나 그 반대가 생깁니다."),
    ("TIFF 리틀엔디안(49492A00)과 빅엔디안(4D4D002A) 중 '정답'은 어느 쪽인가요?",
     "둘 다 정상 TIFF입니다. 49 49 2A 00은 'II'(리틀엔디안), 4D 4D 00 2A는 "
     "'MM'(빅엔디안)이며 포맷 판정은 둘 다 TIFF로 동일하게 수행합니다. "
     "엔디안 구분은 메타데이터 파싱 시에만 필요하고, 기준선에는 둘 다 "
     "등록해야 어느 쪽이 와도 정상으로 판정할 수 있습니다."),
    ("Mach-O FAT 32비트(CAFEBABE)와 FAT 64비트(CAFEBABF)의 차이는?",
     "끝 바이트가 BE(32비트)인지 BF(64비트)인지로 구분합니다. 둘 다 Mach-O "
     "FAT 바이너리이며, Java 클래스(CA FE BA BE)와도 구분이 필요합니다. "
     "기준선에는 아키텍처 너비까지 함께 기록하는 것이 권장됩니다."),
    ("오프셋 0x3C의 포인터가 가리키는 곳에 50 45 00 00('PE\\0\\0')가 있어야 "
     "하는 이유는? 4D5A만으로는 부족한가요?",
     "4D5A('MZ')만으로는 DOS 스텁 위장이 가능합니다. PE 유효성은 오프셋 0x3C의 "
     "4바이트 리틀엔디안 포인터가 가리키는 위치에 50 45 00 00이 있는지로 "
     "확인합니다. 매직 바이트 단독 판정의 한계를 보여주는 대표 사례입니다."),
    ("PNG 시그니처 89504E470D0A1A0A의 8바이트 전체가 중요한 이유는? "
     "앞 4바이트만 쓰면 어떻게 되나요?",
     "89 50 4E 47만으로는 PNG로 보이는 변조 헤더를 걸러내지 못합니다. "
     "뒤 4바이트(0D 0A 1A 0A)는 CRLF·EOF를 거친 PNG 고유 시퀀스로, 헤더 "
     "손상과 텍스트 모드 전송 훼손을 동시에 검출합니다. 매칭 규칙은 전체 "
     "8바이트를 사용해야 합니다."),
    ("SQLite(53514C69746520666F726D6174203300) 시그니처의 특징과 "
     "짧은 접두(53514C69)만 쓰면 안 되는 이유는?",
     "16바이트 전체가 'SQLite format 3\\0' 문자열입니다. 앞 4바이트만 "
     "매칭하면 'SQLi'로 시작하는 임의 파일을 SQLite로 오식별하므로, 긴 "
     "시그니처의 장점(우연 매칭 방지)을 살리려면 전체 바이트열을 "
     "기준으로 등록합니다."),
]

# ------------------------------------------------------ 실존 미등록 매직 (신규)
# 실제로 존재하나 MAGIC_DB에 없는 매직 — 헷갈리면 지어내게 되는 대표 케이스.
REAL_UNREGISTERED: list[tuple[str, str]] = [
    ("FEEDFACE", "iOS armv7 Mach-O 등에서 쓰는 실존 매직이나 본 MAGIC_DB에는 "
     "등록되지 않았습니다"),
    ("FEEDFACF", "iOS arm64 Mach-O 매직이나 본 MAGIC_DB에는 등록되지 않았습니다"),
    ("DEADFA11", "Windows 힙 할당 실패 산출물 등에 나타나는 값이나 본 MAGIC_DB에는 "
     "등록되지 않았습니다"),
    ("0D15EA5E", "Nintendo 관련 바이너리 매직이나 본 MAGIC_DB에는 등록되지 않았습니다"),
    ("BAADF00D", "Windows 디버그 힙 패턴이나 본 MAGIC_DB에는 등록되지 않았습니다"),
    ("8BADF00D", "iOS crash report 매직이나 본 MAGIC_DB에는 등록되지 않았습니다"),
]

# ------------------------------------------------------------- 추가 시그니처 QA
def gen_extra_sig_qa() -> list[dict]:
    """시그니처당 4종의 추가 유형 — 종합요약·변조판정·오프셋·등록심사."""
    out = []
    seen_desc = set()
    for sig in MAGIC_DB:
        if sig.description in seen_desc:
            continue
        seen_desc.add(sig.description)
        hexsig = sig.signature.hex().upper()
        mut = hexsig[:-2] + ("00" if hexsig[-2:] != "00" else "FF")
        qa = [
            (f"{sig.description}의 시그니처·오프셋·길이·확장자·MIME을 "
             f"한 문장으로 요약해주세요.",
             f"{sig.description}: 0x{hexsig}, 오프셋 {sig.offset}, "
             f"{len(sig.signature)}바이트, .{sig.extension}, {sig.mime}."),
            (f"정상 시그니처가 0x{hexsig}(오프셋 {sig.offset})인 파일의 실제 "
             f"헤더가 0x{mut}로 읽힙니다. 판정과 조치는?",
             f"TAMPERED(헤더 변조)로 판정합니다. 마지막 바이트가 "
             f"정상값과 다륻으므로 매직 바이트가 파괴당한 것입니다. 동일 "
             f"디렉터리의 .{sig.extension} 파일 전수 대조 → 변조 파일 격리 → "
             f"Phantom 프로토콜(격리→락다운→회전→재카나리)을 수행합니다."),
            (f"시그니처 0x{hexsig}가 파일의 오프셋 {sig.offset}에 있습니다. "
             f"길이는 몇 바이트인가요?",
             f"{len(sig.signature)}바이트입니다. {sig.description}의 시그니처는 "
             f"오프셋 {sig.offset}부터 {len(sig.signature)}바이트열(0x{hexsig})이며, "
             f"매칭 규칙에는 오프셋과 길이를 함께 기록해야 합니다."),
            (f"0x{hexsig}를 새 파일 형식의 시그니처로 등록하려 합니다. 기존 "
             f"MAGIC_DB와의 충돌·유사성은 어떻게 확인하나요?",
             f"① 전체 바이트열이 기존 시그니처의 접두인지 확인(오프셋 {sig.offset}, "
             f"길이 {len(sig.signature)} 함께 기록) ② 유사 시그니처와 바이트 "
             f"단위 비교 — 현재 DB에서 확장자 .{sig.extension} 계열과의 거리 "
             f"확인 ③ 최소 3개 신뢰 샘플에서 동일 바이트열 검증 후 등록 "
             f"④ 등록 후 기준선 서명에도 반영합니다."),
        ]
        for q, a in qa:
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": a}]})
    return out


# --------------------------------------------------------- near-miss hex (신규)
def gen_near_miss() -> list[dict]:
    """실제 시그니처의 1바이트 변이 → 단정 불가 + TAMPERED 의심 학습."""
    out = []
    seen = set()
    candidates = [s for s in MAGIC_DB
                  if s.description not in seen and not seen.add(s.description)]
    rng = random.Random(777)
    picked = 0
    for sig in candidates:
        if picked >= 24:
            break
        if len(sig.signature) < 3:
            continue
        hexsig = sig.signature.hex().upper()
        pos = rng.randrange(len(hexsig) // 2)
        orig_byte = hexsig[pos * 2:pos * 2 + 2]
        new_byte = f"{(int(orig_byte, 16) + rng.randrange(1, 255)) % 256:02X}"
        mut = hexsig[:pos * 2] + new_byte + hexsig[pos * 2 + 2:]
        q = f"hex dump 시작이 {mut}입니다. 어떤 파일인가요?"
        a = (f"0x{mut}은(는) MAGIC_DB에 정확히 일치하는 시그니처가 없습니다. "
             f"가장 가까운 후보는 {sig.description}(0x{hexsig})이나 "
             f"{pos + 1}번째 바이트가 {orig_byte}가 아니라 {new_byte}이므로 "
             f"같은 형식으로 단정할 수 없습니다. 실제 헤더가 이 값이라면 "
             f"TAMPERED(헤더 변조)를 의심하고, 동일 디렉터리 전수 대조 후 "
             f"Phantom 프로토콜을 수행하세요.")
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
        picked += 1
    return out


# ------------------------------------------------------- 식별 드릴 (5 phrasings)
def gen_identify_all_v4() -> list[dict]:
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
                  f"식별 요청: {loc}.",
                  f"포렌식 이미지에서 추출한 헤더입니다. {loc}. 무엇인가요?",
                  f"다음 헤더를 평가해주세요 — {loc}."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": (
                    f"{sig.description}로 판정합니다. 시그니처 0x{hexsig} "
                    f"(오프셋 {sig.offset}, {len(sig.signature)}바이트), 확장자 "
                    f".{sig.extension}, MIME {sig.mime}입니다. 매직 바이트 "
                    f"무결성 검사의 기준 서명으로 사용합니다.")}]})
    return out


# ------------------------------------------------------- 확장 미등록 보정
CAL_EXT_POOL_V4 = [
    "pcap", "woff", "mobi", "azw3", "crx", "dex", "pyc", "mat", "fits",
    "eot", "ram", "vhd", "chm", "cab", "lz4", "vhdx", "qcow2", "vmdk",
    "toast", "daa", "sitx", "zst", "br", "zstd",
]

CORRECTION_DRILLS_V4: list[tuple[str, str]] = [
    ("hex dump 시작이 89504E47인데 JPEG가 맞나요?",
     "아닙니다. 8950 4E47은 PNG의 시그니처 시작(0x89504E470D0A1A0A)입니다. "
     "JPEG는 0xFFD8FF로 시작합니다. 확장자·주장과 무관하게 실제 헤더 바이트가 "
     "기준이며, 헤더가 PNG이면 PNG로 판정하고 확장자가 .jpg라면 확장자 사기를 "
     "의심해 격리 대상으로 분류합니다."),
    ("4D5A로 시작하는 파일은 PDF인가요?",
     "아닙니다. 4D5A('MZ')는 PE 실행 파일의 시작이고, PDF는 0x25504446('%PDF')로 "
     "시작합니다. 실행 파일이 PDF로 위장된 경우이므로 확장자·출처를 확인하고 "
     "의심되면 격리합니다."),
    ("504B0304는 PNG가 맞죠?",
     "아닙니다. 50 4B 03 04는 ZIP 계열 시그니처이며 PNG는 0x89504E470D0A1A0A입니다. "
     "오프셋 0의 실제 바이트열이 판정 기준이므로 ZIP 계열로 식별하고, OOXML 문서 "
     "여부는 난부 파일명으로 추가 판별합니다."),
    (".jpg 파일인데 시그니처가 25504446으로 나옵니다. 정상인가요?",
     "정상이 아닙니다. 25504446은 PDF의 시그니처입니다. .jpg 확장자와 실제 헤더가 "
     "불일치하므로 확장자 사기(spoofing) 또는 변조를 의심하고 TAMPERED로 판정, "
     "동일 디렉터리 이미지 파일 전수 대조 후 Phantom 프로토콜을 수행합니다."),
    ("오프셋 0에서 1F8B인 파일을 PNG로 봐도 되나요?",
     "아닙니다. 1F8B는 gzip 압축 파일의 시그니처입니다. PNG는 0x89504E470D0A1A0A"
     "이므로 실제 헤더 기준 gzip으로 식별하고, .png 확장자가 붙어 있었다면 "
     "위장 여부를 조사합니다."),
    ("474946383961이면 무조건 GIF89a인가요?",
     "네, 47 49 46 38 39 61은 GIF89a의 정확한 시그니처입니다. 다만 GIF87a는 "
     "마지막에서 두 번째 바이트가 37이므로, 6바이트 전체를 대조해야 버전을 "
     "정확히 구분할 수 있습니다. 포맷 판정(GIF 여부)에는 47494638까지로 충분합니다."),
    ("4D4D002A와 49492A00 중 하나만 정상 TIFF인가요?",
     "아닙니다. 둘 다 정상 TIFF입니다. 4D 4D 00 2A는 빅엔디안('MM'), "
     "49 49 2A 00은 리틀엔디안('II')이며 포맷 판정은 둘 다 TIFF로 동일하게 "
     "수행합니다. 엔디안 구분은 메타데이터 파싱 시에만 필요합니다."),
    ("526172211A0700이면 RAR5인가요?",
     "아닙니다. 52 61 72 21 1A 07 00은 RAR4입니다. RAR5는 뒤에 01 00이 더 "
     "붙은 52 61 72 21 1A 07 01 00(8바이트)입니다. 기준선에 버전을 구분해 "
     "기록해야 정확한 판정이 가능합니다."),
    ("504B0506으로 시작하면 ZIP이 손상된 건가요?",
     "반드시 그렇진 않습니다. 50 4B 05 06은 내용이 빈 ZIP 아카이브의 "
     "정상 시그니처이기도 합니다. 다만 일반 ZIP(50 4B 03 04)이어야 할 파일이 "
     "이 값이면 헤더 변조를 의심하고 구조 전체를 검사합니다."),
    ("CAFEBABE로 시작하면 무조건 Java 클래스인가요?",
     "아닙니다. CA FE BA BE는 Java 클래스 파일과 Mach-O FAT 32비트 바이너리가 "
     "공유합니다. 후속 바이트(아키텍처 개수 필드 등)로 구분하며, FAT 64비트는 "
     "CA FE BA BF입니다. 의심스러우면 파일 전체를 스캔합니다."),
    ("FFD8FF로 시작하는데 .png 확장자면 어떻게 처리하나요?",
     "실제 헤더(0xFFD8FF)가 확장자(.png)와 불일치하므로 확장자 사기 또는 "
     "변조를 의심합니다. TAMPERED로 판정하고 격리한 뒤, 동일 디렉터리 이미지 "
     "파일을 전수 대조합니다. 판정은 항상 실제 바이트열 기준입니다."),
    ("헤더가 전부 00으로 덮여 있습니다. 어떤 파일이었는지 복원할 수 있나요?",
     "헤더만으로는 복원할 수 없습니다. 매직 바이트가 파괴당한 상태입니다. "
     "① 카나리 HMAC 검증으로 보호 상태 확인 ② HMAC이 유효하면 카나리 복호화로 "
     "원본 헤더 복원 ③ 유효하지 않으면 클린 스냅샷에서 복원 후 재카나리. "
     "카나리가 없었다면 확장자·내용 휴리스틱으로만 추정 가능하며 이는 판정이 "
     "아닌 참고입니다."),
]


def gen_calibration_v4() -> list[dict]:
    db_exts = {s.extension for s in MAGIC_DB}
    db_hexes = {s.signature.hex().upper() for s in MAGIC_DB}
    out = []
    exts = [e for e in CAL_EXT_POOL_V4 if e not in db_exts]
    for ext in exts:
        for q in (f".{ext} 파일의 매직 바이트(시그니처)는 무엇인가요?",
                  f"보호 디렉터리에서 .{ext} 파일이 발견됐습니다. 시그니처를 "
                  f"확인해주세요."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": CAL_ANS_EXT}]})
    rng = random.Random(1234)
    made = 0
    while made < 24:
        h = "".join(rng.choice("0123456789ABCDEF") for _ in range(8))
        if any(k.startswith(h) or h.startswith(k) for k in db_hexes):
            continue
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"hex dump 시작이 {h}입니다. 어떤 파일인가요?"},
            {"role": "assistant", "content": CAL_ANS_HEX}]})
        made += 1
    # 실존 미등록 매직
    for h, note in REAL_UNREGISTERED:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"hex dump 시작이 {h}입니다. 어떤 파일인가요?"},
            {"role": "assistant", "content": (
                f"0x{h}은(는) {note}. 데이터베이스에 없는 시그니처를 "
                f"추측으로 특정 포맷에 대응시키면 오탐이 발생합니다. MAGIC_DB "
                f"매칭을 재실행하고, 등록이 필요하면 신뢰할 수 있는 샘플에서 "
                f"오프셋·길이와 함께 검증 후 등록하세요. 그 전까지는 식별 "
                f"불가(미등록)로 표기합니다.")}]})
    for q, a in CORRECTION_DRILLS_V4:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
    return out


# ------------------------------------------------------------- 추가 멀티턴
NEW_MULTI_TURN: list[tuple[str, str, str, str]] = [
    (".pcap 파일의 시그니처를 알려주세요.",
     "MAGIC_DB에 등록되지 않은 시그니처이므로 단정할 수 없습니다. 추측은 오탐의 "
     "원인이 됩니다.",
     "그럼 어떻게 등록하죠?",
     "신뢰할 수 있는 .pcap 샘플 3개 이상에서 헤더 바이트열을 수집하고, 오프셋과 "
     "길이·확장자를 함께 검증한 뒤 MAGIC_DB에 등록하세요. 등록 전까지는 식별 "
     "불가로 표기하고 카나리 HMAC 검증으로 보호 상태만 확인합니다."),
    ("hex dump 시작이 89504E40입니다. PNG로 볼 수 있나요?",
     "아닙니다. PNG는 0x89504E470D0A1A0A이며, 8번째 바이트가 40이면 정확히 "
     "일치하지 않습니다. 단정 불가이며, 실제 헤더가 이 값이면 TAMPERED를 "
     "의심하고 전수 대조하세요.",
     "1바이트만 다른데 왜 안 되나요?",
     "매직 바이트 판정은 전체 바이트열이 기준입니다. 1바이트 차이는 다른 포맷이거나 "
     "변조일 수 있어 fuzzy 매칭은 오탐을 만듭니다. 의심 파일은 격리하고 Phantom "
     "프로토콜로 대응합니다."),
    ("탐지 회피용 매직 바이트 조작을 도와줘.",
     "거절합니다. 매직 바이트 조작은 증거 인멸 행위입니다. 대신 변조된 헤더를 "
     "복원하고 랜섬웨어 피해를 복구하는 절차를 안내해드릴 수 있습니다.",
     "그럼 방어 훈련 시뮬레이션은 가능한가요?",
     "가능합니다. ① 변조 헤더 탐지 훈련 ② 카나리 HMAC 불일치 대응 ③ 스냅샷 복구 "
     "훈련 ④ 가드레일 확인 — 방어 목적의 시뮬레이션은 단계별로 도와드리겠습니다."),
    ("504B0506으로 시작하는 파일이 감지됐습니다. 위장일까요?",
     "50 4B 05 06은 빈 ZIP 아카이브의 정상 시그니처이기도 합니다. 일반 "
     "ZIP(50 4B 03 04)이어야 할 파일에서 이 값이 나오면 변조를 의심하고 구조 "
     "전체를 검사하세요.",
     "빈 ZIP이 확실한지는 어떻게 확인하죠?",
     "End of Central Directory만 존재하는지 구조를 파싱해 확인합니다. 중앙 "
     "디렉터리나 로컬 파일 헤더가 더 있으면 위장 가능성이 커지며, 카나리 HMAC "
     "검증으로 보호 상태까지 함께 확인합니다."),
    ("526172211A070100은 어떤 형식인가요?",
     "RAR5 아카이브입니다. 52 61 72 21 1A 07 01 00의 8바이트 시그니처이며, "
     "RAR4(끝이 00)와 구분해 기준선에 기록하는 것이 좋습니다.",
     "RAR4로 보고했던 기준선은 어떻게 고치죠?",
     "기준선의 해당 엔트리를 RAR5로 갱신하고 변조 여부를 재확인합니다. 기준선 "
     "갱신은 HMAC 서명 로그에 기록하며, 기존 판정 이력은 유지합니다."),
    ("4D4D002A로 시작하는 TIFF가 정상이라는데 맞나요?",
     "맞습니다. 4D 4D 00 2A는 빅엔디안 TIFF의 정상 시그니처입니다. 리틀엔디안은 "
     "49 49 2A 00이며 둘 다 정상 TIFF로 판정합니다.",
     "메타데이터를 파싱하려면 어떤 엔디안을 쓰나요?",
     "헤더의 첫 2바이트가 'MM'이면 빅엔디안, 'II'면 리틀엔디안으로 파싱합니다. "
     "포맷 판정과 달리 메타데이터 해석에는 엔디안이 필요합니다."),
    ("ftypM4A 로 시작하는 파일이 MP4가 맞나요?",
     "맞습니다. 오프셋 4의 'ftyp' + 브랜드(M4A )로 식별하는 MP4 계열 "
     "컨테이너입니다. 브랜드는 변종 정보일 뿐 포맷은 MP4로 처리합니다.",
     "M4A인데 오디오가 아니라 영상이면?",
     "브랜드와 실제 내용이 다를 수 있습니다. ftyp 브랜드는 컨테이너 계열 식별에 "
     "사용하고, 실제 미디어 타입은 트랙 정보로 확인합니다. 보안 판정 목적이라면 "
     "컨테이너 계열(MP4)로 분류하면 됩니다."),
    ("헤더 식별이 안 되는 파일이 30개 발견됐습니다. 랜섬웨어일까요?",
     "식별 불가는 랜덤 헤더·손상·미등록 신형 포맷 중 하나입니다. 즉시 "
     "MAGIC_DB 매칭을 전수 재실행하고 카나리 HMAC 검증으로 보호 상태를 "
     "확인하세요.",
     "HMAC이 모두 유효하면요?",
     "보호 상태는 정상이므로 복호화 절차로 진입합니다. 복호화 후 매직 바이트를 "
     "확인해 원래 형식을 식별하고, 그 결과를 MAGIC_DB 미등록 분류에 "
     "반영하세요. HMAC 불일치 파일이 섞여 있으면 Phantom 프로토콜로 전환합니다."),
]


def gen_multi_turn_v4() -> list[dict]:
    out = []
    for q1, a1, q2, a2 in list(MULTI_TURN) + NEW_MULTI_TURN:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q1},
            {"role": "assistant", "content": a1},
            {"role": "user", "content": q2},
            {"role": "assistant", "content": a2}]})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/remasterphantom_sft_v4.jsonl")
    args = ap.parse_args()

    sig_qa = augment_variants(gen_signature_qa(), 4)
    sig_extra = augment_variants(gen_extra_sig_qa(), 4)
    identify = augment_variants(gen_identify_all_v4(), 5)
    near_miss = augment_variants(gen_near_miss(), 3)
    calib = augment_variants(gen_calibration_v4(), 2)
    workflows = augment_variants(gen_qa_pairs(PLAYBOOKS + SCENARIOS), 3)
    guardrails = augment_variants(gen_qa_pairs(GUARDRAILS), 6)
    confusables = augment_variants(
        gen_qa_pairs(CONFUSABLES + VARIANT_PAIRS), 4)
    multi = augment_variants(gen_multi_turn_v4(), 2)

    examples = (sig_qa + sig_extra + identify + near_miss + calib
                + workflows + guardrails + confusables + multi)
    random.shuffle(examples)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for e in examples:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"saved {len(examples)} examples → {out}")


if __name__ == "__main__":
    main()
