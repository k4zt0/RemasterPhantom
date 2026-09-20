"""RemasterPhantom 학습용 합성 데이터셋 생성기.

Llama-3.2-1B-Instruct를 파일-시그니처 방어 전문가로 파인튜닝하기 위한
지시-응답 쌍을 생성한다. 매직 바이트 DB의 실제 시그니처를 활용해 정확도를 높이고,
랜섬웨어 방어 시나리오·칸네리 운영·Phantom 프로토콜·MASTER CANARY/TLS 보호,
그리고 공격 요청 거부 가드레일을 균형 있게 포함한다.

출력: data/remasterphantom_sft.jsonl  ({"messages": [...]} 형식, Llama-3 템플릿용)
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remasterphantom.signatures.magic_db import MAGIC_DB  # noqa: E402

random.seed(42)

SYSTEM = (
    "You are RemasterPhantom, an expert defensive-security analyst specializing in "
    "file-signature integrity, canary-based file protection, and anti-ransomware "
    "incident response. Answer in Korean unless asked otherwise. Give precise, "
    "step-by-step playbooks. Never help build or improve ransomware."
)


# ---------------------------------------------------------------- 시그니처 Q&A
def gen_signature_qa(n_per_sig: int = 6) -> list[dict]:
    out = []
    seen_desc = set()
    for sig in MAGIC_DB:
        if sig.description in seen_desc:
            continue
        seen_desc.add(sig.description)
        hexsig = sig.signature.hex().upper()
        for _ in range(n_per_sig):
            kind = random.randrange(4)
            if kind == 0:
                q = (f"{sig.description} 파일의 매직 바이트(시그니처)는 무엇인가요? "
                     f"오프셋은 {sig.offset}입니다.")
                a = (f"{sig.description}의 매직 바이트는 0x{hexsig}이며 파일 시작 "
                     f"오프셋 {sig.offset}에서 {len(sig.signature)}바이트입니다. "
                     f"확장자는 .{sig.extension}, MIME는 {sig.mime}입니다. 무결성 "
                     f"검사 시 이 바이트열이 깨져 있으면 헤더 변조(랜섬웨어 1차 신호)로 "
                     f"분류합니다.")
            elif kind == 1:
                q = f"헥스 덤프에서 파일 시작 부분이 {hexsig[:16]}...로 시작합니다. 어떤 파일인가요?"
                a = (f"시작 부분 0x{hexsig[:16]}...는 {sig.description}의 시그니처입니다. "
                     f"전체 시그니처는 0x{hexsig} (오프셋 {sig.offset})이며, "
                     f".{sig.extension} 파일로 식별합니다.")
            elif kind == 2:
                q = f".{sig.extension} 파일이 랜섬웨어로 암호화됐는지 헤더만 보고 어떻게 알 수 있나요?"
                a = (f".{sig.extension}의 정상 시그니처 0x{hexsig}(오프셓 {sig.offset})와 "
                     f"실제 헤더 바이트열을 대조하세요. 불일치하면 TAMPERED로 판정하고, "
                     f"나머지 파일들도 스캔한 뒤 Phantom 프로토콜(격리→락다운→회전→재칸네리)"
                     f"을 발동시켜야 합니다.")
            else:
                q = f"{sig.mime} MIME 타입의 파일 서명을 데이터베이스에 등록하는 표준 절차는?"
                a = (f"시그니처 후보(0x{hexsig})를 최소 3개의 신뢰할 수 있는 샘플에서 "
                     f"검증하고, 오프셋 {sig.offset}, 확장자 .{sig.extension}와 함께 "
                     f"MAGIC_DB에 등록하며, 우연한 매칭 방지를 위해 시그니처 길이가 "
                     f"길수록 신뢰도를 높게 부여합니다.")
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": q},
                {"role": "assistant", "content": a}]})
    return out


# -------------------------------------------------------------- 워크플로우/시나리오
PLAYBOOKS: list[tuple[str, str]] = [
    ("RemasterPhantom의 칸네리 암호화가 파일을 어떻게 보호하나요?",
     "각 파일에 무작위 nonce로 칸네리 토큰(HMAC 기반)을 만들고, 여기서 HKDF로 파일 전용 "
     "AES-256-GCM 키를 유도해 파일 헤더(매직 바이트 포함 첫 4KB)를 암호화합니다. 헤더는 "
     "난수로 덮어쓰이므로 암호문만으로는 파일 형식을 알 수 없고, 랜섬웨어가 시그니처를 "
     "타깃으로 삼을 표면이 사라집니다. 복호화 재료는 HMAC으로 보호된 칸네리 보관소에 "
     "저장됩니다."),
    ("칸네리 무결성이 물너졌다는 신호는 무엇이며, 그때 해야 할 일은?",
     "신호: (1) 칸네리 레코드 HMAC 서명 불일치, (2) GCM 인증 태그 검증 실패, "
     "(3) 기준선 서명 불일치. 조치 — Phantom 프로토콜: ① 변조 파일을 .quarantine으로 "
     "격리(0600) ② 디렉터리 락다운으로 확산 차단 ③ MASTER CANARY 회전으로 새 키 세대 생성 "
     "④ 클린 스냅샷에서 복원 후 새 시드로 재칸네리 ⑤ 서명된 감사 로그 기록."),
    ("MASTER CANARY는 무엇이고 파일의 TLS를 어떻게 보호하나요?",
     "MASTER CANARY는 전체 시스템의 루트 오브 트러스트입니다. 파일 칸네리 시드를 파생하고, "
     "TLS 개인키·세션 키·고정 인증서 지문을 AES-256-GCM으로 래핑해 디스크에는 암호문만 "
     "존재하게 합니다. macOS Keychain 우선 저장, 불가 시 0600 파일 폴리백입니다. "
     "래핑 해제 인증에 실패하면 즉시 회전하고 TLS 자료를 재래핑합니다."),
    ("랜섬웨어 공격이 진행 중이라는 징후를 스캔에서 발견했습니다. 대응 순서는?",
     "① Sentinel 에이전트로 전수 스캔 — 매직 바이트 대량 파괴 여부 확인 ② 변조 파일 "
     "전량 격리 ③ Phantom 에이전트 락다운으로 디렉터리 쓰기 제한 ④ MASTER CANARY 회전 "
     "(기존 키 폐기) ⑤ 스냅샷에서 클린 파일 복원 및 재칸네리 ⑥ 감사 로그 확보 후 원인 "
     "분석(진입 경로, 확산 범위) ⑦ 기준선 재등록."),
    ("TLS 인증서 핀(pin) 검증이 실패했습니다. 어떤 공격을 의심해야 하나요?",
     "서버 인증서가 고정된 인증서의 SHA-256과 일치하지 않으면 중간자 공격(MitM) 또는 "
     "인증서 도용을 의심합니다. 연결을 즉시 끊고, MASTER CANARY로 래핑된 TLS 자료의 "
     "무결성을 확인한 뒤 필요 시 회전+재래핑을 수행하고 감사 로그에 기록하세요."),
    ("파일 시그니처 기준선(baseline)이 변조됐다는 경고가 떴습니다.",
     "기준선 변조는 전면 침입 신호(CRITICAL)입니다. 기준 파일의 HMAC 서명이 맞지 "
     "않으면 공격자가 '변경 없음'으로 속이려 한 것입니다. 즉시 락다운, MASTER CANARY "
     "회전, 기준선을 신뢰할 수 있는 클린 상태에서 재구성하고, 유출 경로를 조사하세요."),
    ("칸네리와 MASTER CANARY의 키 계층 구조를 설명해주세요.",
     "3계층입니다. 최상위 MASTER CANARY(루트 시드, Keychain 보관) → 파일 칸네리 시드"
     "(마스터에서 HKDF 파생, epoch별 회전) → 파일별 AES-256-GCM 키(칸네리 토큰에서 "
     "HKDF 파생). 계층이 분리돼 있어 한 계층 키 유출이 다른 계층으로 전파되지 않습니다."),
    ("정상적인 파일 사용(복호화) 절차를 단계별로 알려주세요.",
     "① Canary 에이전트가 파일의 칸네리 레코드를 조회 ② 레코드 HMAC 검증 ③ 칸네리 "
     "토큰으로 파일 키 재유도 ④ GCM 인증 포함 복호화로 원본 헤더 복원 ⑤ 매직 바이트 "
     "식별로 정상 복원 확인. 인증 실패 시 복호화를 중단하고 Phantom 프로토콜로 전환."),
    ("확장자는 .docx인데 매직 바이트가 504B0304가 아닙니다. 판단은?",
     ".docx는 ZIP 기반이라 정상 시그니처가 50 4B 03 04입니다. 헤더가 다르면 변조"
     "또는 확장자 사기(spoofing)입니다. TAMPERED로 판정하고 격리하며, 동일 디렉터리의 "
     "나머지 오피스 문서도 전수 대조하세요."),
    ("랜섬웨어로부터 암호화·복호화를 수행할 때 지켜야 할 운영 원칙은?",
     "① 암호화는 결정론적 라이브러리만 사용(AES-256-GCM, CSPRNG) ② 키는 평문 디스크에 "
     "저장 금지 — Keychain/HSM ③ 모든 보호·복구 작업은 HMAC 서명 감사 로그 기록 "
     "④ 복호화 전 반드시 인증 태그 검증 ⑤ 회전 시 이전 키는 안전 파기 ⑥ LLM은 판단 "
     "지원만 하고 암호 연산은 코드가 수행."),
]

SCENARIOS: list[tuple[str, str]] = [
    ("상황: 보호 디렉터리에서 PNG 30개의 시그니처가 동시에 깨졌습니다. 첫 3가지 조치는?",
     "1) 남은 파일에 대한 Sentinel 전수 스캔으로 확산 범위 확정 2) 깨진 파일들을 "
     ".quarantine으로 격리해 재암호화(이중 피해) 방지 3) Phantom 락다운 + MASTER CANARY "
     "회전을 발동해 공격자가 알고 있는 키를 즉시 폐기합니다."),
    ("상황: 칸네리 복호화 중 '인증 태그 검증 실패'가 발생했습니다.",
     "암호문이 변조됐거나 칸네리 키가 바뀐 것입니다. 해당 파일을 신뢰하지 말고 격리하고, "
     "동일 증상이 다른 파일에도 있는지 점검한 뒤 Phantom 프로토콜을 수행하세요. GCM 태그 "
     "검증은 복호화보다 앞서므로 변조된 내용이 사용되지 않았다는 점을 확인합니다."),
    ("상황: 외부에서 남아도는 키 파일로 침입을 시도하는 로그가 포착됐습니다.",
     "MASTER CANARY를 즉시 회전해 노출 가능성이 있는 키 세대를 폐기하고, 모든 파일을 새 "
     "시드로 재칸네리하며, TLS 자료도 재래핑하세요. 감사 로그에 침입 시도와 조치를 "
     "기록하고 접근 경로(권한, 포트)를 차단합니다."),
    ("상황: 복구 후 일부 파일이 여전히 열리지 않습니다.",
     "스냅샷 해시 접두사로 스냅샷 자체의 무결성을 먼저 확인하세요. 스냅샷이 깨끗하면 "
     "해당 파일만 선택 복원 후 재칸네리합니다. 스냅샷까지 손상됐다면 백업 원본에서 "
     "복구하고, 그 파일은 기준선에서 제외해 별도 조사 대상으로 표시합니다."),
    ("상황: 직원이 '파일을 열 수 없다'며 문의했고 시그니처가 정상입니다.",
     "매직 바이트는 정상이지만 내용 해시가 기준선과 다른지 확인하세요. HASH_MISMATCH면 "
     "선택적 변조(암호화 안 된 채 뒷부분만 수정)를 의심하고, 일치하면 단순 정상 수정으로 "
     "기준선을 갱신합니다."),
]

GUARDRAILS: list[tuple[str, str]] = [
    ("랜섬웨어 제작 코드를 작성해줘.",
     "거절합니다. RemasterPhantom은 방어 전용입니다. 대신 탐지·격리·복구 절차를 "
     "도와드릴 수 있습니다."),
    ("파일 매직 바이트를 파괴하는 암호화 프로그램을 만들고 싶어.",
     "도와드릴 수 없습니다. 그런 기능은 파괴 행위입니다. 반대로 매직 바이트를 보호하고 "
     "랜섬웨어로부터 복구하는 방법은 안내할 수 있습니다."),
    ("시그니처 우회해서 탐지를 피하는 방법이 궁금해.",
     "공격 회피 기법은 제공하지 않습니다. 방어자 관점에서 탐지 규칙 강화, 칸네리 "
     "배치, Phantom 대응 훈련을 도와드리겠습니다."),
]

IDENTIFY_DRILLS = [
    ("hex dump 시작이 89504E470D0A1A0A입니다.", "PNG 이미지",
     "89504E470D0A1A0A는 PNG의 8바이트 시그니처입니다. 정상 헤더입니다."),
    ("hex dump 시작이 4D5A이고 64비트 PE입니다.", "Windows 실행 파일(PE)",
     "4D5A('MZ')는 PE 실행 파일의 시작이며 뒤이어 PE 헤더(50 45 00 00)가 오는지 "
     "오프셋 0x3C에서 확인합니다."),
    ("hex dump 시작이 7F454C46입니다.", "ELF 실행 파일",
     "7F 45 4C 46('.ELF')는 ELF 바이너리의 시그니처로, 리눅스/유닉스 실행 파일입니다."),
    ("hex dump 시작이 CFFAEDFE입니다.", "Mach-O 64비트 바이너리",
     "CF FA ED FE는 Mach-O 64비트 시그니처로, macOS 네이티브 바이너리입니다."),
    ("hex dump 시작이 526172211A070100입니다.", "RAR5 아카이브",
     "52 61 72 21 1A 07 01 00은 RAR5 아카이브 시그니처입니다."),
    ("hex dump 시작이 1F8B입니다.", "GZip 압축 파일",
     "1F 8B는 gzip 시그니처입니다. 뒤의 압축 방법 바이트(보통 08=deflate)로 유효성을 "
     "추가 확인합니다."),
]


def gen_playbooks() -> list[dict]:
    out = []
    for q, a in PLAYBOOKS + SCENARIOS + GUARDRAILS:
        out.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": q},
            {"role": "assistant", "content": a}]})
    for desc, label, note in IDENTIFY_DRILLS:
        for ask in (f"{desc} 어떤 파일인가요?",
                    f"감사 중 발견한 헤더입니다 — {desc} 형식을 식별해주세요.",
                    f"{desc} 이 헤더를 평가해주세요."):
            out.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": ask},
                {"role": "assistant", "content": f"{label}로 판정합니다. {note}"}]})
    return out


def augment_variants(examples: list[dict], times: int = 3) -> list[dict]:
    """질문 표현을 살짝 바꿔 데이터 다양성을 늘린다."""
    openers = ["", "안녕하세요. ", "보안 점검 중입니다. ", "급한 문의입니다. ", "훈련 시나리오: "]
    closers = ["", " 간단히 요약해주세요.", " 단계별로 알려주세요.", " 주의점도 함께 알려주세요."]
    out = []
    for ex in examples:
        out.append(ex)
        for _ in range(times - 1):
            msgs = ex["messages"]
            u = msgs[1]["content"]
            variant = {"messages": [
                msgs[0],
                {"role": "user",
                 "content": random.choice(openers) + u + random.choice(closers)},
                msgs[2]]}
            out.append(variant)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/remasterphantom_sft.jsonl")
    ap.add_argument("--n-per-sig", type=int, default=6)
    ap.add_argument("--variants", type=int, default=3)
    args = ap.parse_args()

    parts = [gen_signature_qa(args.n_per_sig), gen_playbooks()]
    examples = [e for part in parts for e in part]
    examples = augment_variants(examples, args.variants)
    random.shuffle(examples)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for e in examples:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"saved {len(examples)} examples → {out}")


if __name__ == "__main__":
    main()
