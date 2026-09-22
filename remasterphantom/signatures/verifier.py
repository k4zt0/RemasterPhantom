"""파일 무결성 검증기.

매직 바이트 일치 여부 + 해시 기준선(baseline) 비교로 파일의 건전성을 판정한다.
랜섬웨어가 파일 헤더를 암호화/변조하면 매직 바이트가 깨지므로 이를 1차 탐지
신호로 사용한다. 해시 기준선은 "아직 깨끗했던 시점"의 지문을 저장해 두고,
이후 변경 여부를 감지하는 2차 신호로 사용한다.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .magic_db import SignatureInfo, identify_file, expected_signature

# 읽어 들일 파일 헤더 크기 (매직 바이트 최대 오프셋 257 + 시그니처 여유분)
_HEADER_BYTES = 4096

# 무결성 상태 코드
STATUS_CLEAN = "CLEAN"
STATUS_TAMPERED = "TAMPERED"          # 매직 바이트/헤더 변조 탐지
STATUS_HASH_MISMATCH = "HASH_MISMATCH"  # 내용 해시가 기준선과 불일치
STATUS_UNKNOWN = "UNKNOWN"            # 시그니처를 알 수 없는 파일
STATUS_MISSING = "MISSING"            # 파일 자체가 사라짐


@dataclass
class VerificationResult:
    path: str
    status: str
    detected: SignatureInfo | None = None
    expected: SignatureInfo | None = None
    sha256: str = ""
    baseline_sha256: str | None = None
    detail: str = ""
    checked_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_CLEAN

    def to_dict(self) -> dict:
        d = asdict(self)
        d["detected"] = asdict(self.detected) if self.detected else None
        d["expected"] = asdict(self.expected) if self.expected else None
        return d


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class IntegrityVerifier:
    """디렉터리 단위 파일 무결성 검증 및 기준선 관리.

    기준선은 HMAC으로 서명해 저장한다. 공격자가 기준선 파일을 조작해
    "변경 없음"으로 속이는 것을 방지한다.
    """

    def __init__(self, baseline_path: str | Path, hmac_key: bytes):
        self.baseline_path = Path(baseline_path)
        self.hmac_key = hmac_key
        self._baseline: dict[str, dict] = {}
        self._load()

    # ---- 기준선 관리 ----
    def _load(self) -> None:
        if not self.baseline_path.exists():
            self._baseline = {}
            return
        raw = json.loads(self.baseline_path.read_text())
        mac = raw.pop("_mac", "")
        payload = json.dumps(raw, sort_keys=True).encode()
        expected_mac = hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            # 기준선이 변조됨 — 카나리 무결성과 동일한 급의 사고다.
            raise BaselineTamperedError("무결성 기준선 서명이 일치하지 않습니다. 변조 가능성.")
        self._baseline = raw

    def _save(self) -> None:
        payload = json.dumps(self._baseline, sort_keys=True, indent=2).encode()
        mac = hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        raw = json.loads(payload)
        raw["_mac"] = mac
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False))
        try:
            self.baseline_path.chmod(0o600)
        except OSError:
            pass

    # ---- 검증 ----
    def verify_file(self, path: str | Path, strict_hash: bool = True) -> VerificationResult:
        p = Path(path)
        if not p.exists():
            return VerificationResult(path=str(p), status=STATUS_MISSING,
                                      detail="파일이 존재하지 않습니다")

        detected = identify_file(p, _HEADER_BYTES)
        expected = expected_signature(p)
        digest = sha256_file(p) if strict_hash else ""
        record = self._baseline.get(str(p.resolve()))

        # 1차: 매직 바이트 변조 여부
        if detected is None and expected is not None:
            return VerificationResult(
                path=str(p), status=STATUS_TAMPERED, detected=None, expected=expected,
                sha256=digest, baseline_sha256=record["sha256"] if record else None,
                detail=f"기대 시그니처({expected.description})가 깨져 있음 — "
                       f"헤더 암호화/변조 의심 (랜섬웨어 1차 신호)",
            )
        if detected is None:
            status = STATUS_UNKNOWN
            detail = "알려진 시그니처 없음 — 모니터링 대상으로 분류"
        else:
            status = STATUS_CLEAN
            detail = f"{detected.description} 시그니처 정상"

        # 2차: 해시 기준선과의 불일치 (매직 바이트는 살아 있으나 내용이 바뀐 경우)
        if record and strict_hash and record["sha256"] != digest:
            return VerificationResult(
                path=str(p), status=STATUS_HASH_MISMATCH, detected=detected,
                expected=expected, sha256=digest, baseline_sha256=record["sha256"],
                detail="매직 바이트는 정상이나 내용 해시가 기준선과 불일치 — "
                       "선택적 암호화/삽입 공격 의심",
            )
        return VerificationResult(
            path=str(p), status=status, detected=detected, expected=expected,
            sha256=digest, baseline_sha256=record["sha256"] if record else None,
            detail=detail,
        )

    def verify_directory(self, root: str | Path, strict_hash: bool = True) -> list[VerificationResult]:
        results = []
        for p in sorted(Path(root).rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                results.append(self.verify_file(p, strict_hash=strict_hash))
        return results

    # ---- 기준선 갱신 (보호 개시 또는 클린 복구 후) ----
    def register(self, path: str | Path) -> None:
        p = Path(path)
        self._baseline[str(p.resolve())] = {"sha256": sha256_file(p)}
        self._save()

    def register_directory(self, root: str | Path) -> None:
        for p in sorted(Path(root).rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                self._baseline[str(p.resolve())] = {"sha256": sha256_file(p)}
        self._save()

    def drop(self, path: str | Path) -> None:
        self._baseline.pop(str(Path(path).resolve()), None)
        self._save()


class BaselineTamperedError(Exception):
    """무결성 기준선 자체가 변조됨 — Phantom 프로토콜 발동 조건."""
