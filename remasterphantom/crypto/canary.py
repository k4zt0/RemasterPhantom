"""카나리 기반 파일 시그니처 암호화/복호화.

원리:
1. 각 파일에 대해 "카나리 토큰"을 생성한다 — HMAC(마스터 시드, file_id || nonce).
2. 카나리에서 HKDF로 파일 전용 AES-256-GCM 키를 유도한다.
3. 파일 헤더(매직 바이트 영역 포함)를 암호화한다. 암호문만으로는 원본 형식을
   알 수 없으므로 랜섬웨어가 시그니처를 타깃으로 삼을 표면이 사라진다.
4. 파일과 함께 저장되는 카나리 레코드는 자체 HMAC으로 보호된다.

카나리 레코드 HMAC이 어긋나는 순간 = 카나리 무결성 붕괴 → defense.fallback의
Phantom 프로토콜이 발동한다.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# 보호 헤더 마커: "RPC1" (RemasterPhantom Canary v1)
_MARKER = b"RPC1"
# 암호화 대상 헤더 크기: 매직 바이트(최대 오프셋 257 + 여유) 포함
_PROTECT_HEADER_BYTES = 4096

# 카나리 상태
CANARY_OK = "OK"
CANARY_TAMPERED = "TAMPERED"
CANARY_UNKNOWN = "UNKNOWN"


class CanaryError(Exception):
    """카나리 복호화 일반 실패."""


class CanaryTamperedError(Exception):
    """카나리 레코드 무결성 붕괴 — Phantom 프로토콜 발동 조건."""


@dataclass
class CanaryRecord:
    file_id: str
    nonce: str                # hex — 카나리 토큰 재생성에 필요
    header_ciphertext: str    # hex — 암호화된 파일 헤더
    gcm_tag_ok: bool = True
    created_at: float = field(default_factory=time.time)
    rotated_at: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class CanaryVault:
    """파일별 카나리 레코드 보관소. 레코드 저장 시 HMAC 서명."""

    def __init__(self, vault_path: str | Path, hmac_key: bytes):
        self.vault_path = Path(vault_path)
        self.hmac_key = hmac_key
        self._records: dict[str, CanaryRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.vault_path.exists():
            self._records = {}
            return
        raw = json.loads(self.vault_path.read_text())
        mac = raw.pop("_mac", "")
        payload = json.dumps(raw, sort_keys=True).encode()
        expected = hmac_mod.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(mac, expected):
            raise CanaryTamperedError("카나리 보관소 서명 불일치 — 카나리 무결성 붕괴")
        self._records = {k: CanaryRecord(**v) for k, v in raw.items()}

    def _save(self) -> None:
        raw = {k: v.to_dict() for k, v in self._records.items()}
        payload = json.dumps(raw, sort_keys=True).encode()
        mac = hmac_mod.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        raw["_mac"] = mac
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.vault_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(raw, indent=2, ensure_ascii=False))
        os.replace(tmp, self.vault_path)
        try:
            self.vault_path.chmod(0o600)
        except OSError:
            pass

    def put(self, rec: CanaryRecord) -> None:
        self._records[rec.file_id] = rec
        self._save()

    def get(self, file_id: str) -> CanaryRecord | None:
        return self._records.get(file_id)

    def remove(self, file_id: str) -> None:
        self._records.pop(file_id, None)
        self._save()

    def all(self) -> dict[str, CanaryRecord]:
        return dict(self._records)


class CanaryCipher:
    """카나리 기반 파일 헤더 암호화/복호화 엔진."""

    def __init__(self, master_seed: bytes, vault: CanaryVault):
        if len(master_seed) < 32:
            raise ValueError("마스터 시드는 32바이트 이상이어야 합니다")
        self.master_seed = master_seed
        self.vault = vault

    # ---- 키 유도 ----
    def _derive_canary_token(self, file_id: str, nonce: bytes) -> bytes:
        msg = file_id.encode() + b"||" + nonce
        return hmac_mod.new(self.master_seed, msg, hashlib.sha256).digest()

    def _derive_aes_key(self, canary_token: bytes) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=b"remasterphantom-canary-v1", info=b"file-header-key")
        return hkdf.derive(canary_token)

    # ---- 암호화 ----
    def encrypt_header(self, path: str | Path, file_id: str | None = None) -> CanaryRecord:
        """파일 헤더(매직 바이트 포함 첫 4KB)를 AES-256-GCM으로 암호화한다.

        원본 헤더는 안전한 난수로 덮어쓴 뒤, 복호화에 필요한 모든 재료는
        HMAC 보호 카나리 레코드에 보관한다.
        """
        p = Path(path)
        fid = file_id or str(p.resolve())
        nonce = secrets.token_bytes(16)
        canary = self._derive_canary_token(fid, nonce)
        key = self._derive_aes_key(canary)

        data = p.read_bytes()
        header, body = data[:_PROTECT_HEADER_BYTES], data[_PROTECT_HEADER_BYTES:]
        aes = AESGCM(key)
        aad = fid.encode()  # 연관 데이터: 다른 파일의 암호문 재사용 방지
        ct = aes.encrypt(nonce, header, aad)

        # 헤더를 난수로 덮어써 시그니처 표면을 제거
        masked = os.urandom(_PROTECT_HEADER_BYTES) + body
        p.write_bytes(masked)

        rec = CanaryRecord(file_id=fid, nonce=nonce.hex(),
                           header_ciphertext=ct.hex())
        self.vault.put(rec)
        return rec

    # ---- 복호화 ----
    def decrypt_header(self, path: str | Path, file_id: str | None = None) -> CanaryRecord:
        """카나리 레코드를 검증한 뒤 파일 헤더를 복원한다.

        서명/HMAC 검증이 실패하면 CanaryTamperedError를 던져 상위에서
        Phantom 폴리백을 발동시킨다.
        """
        p = Path(path)
        fid = file_id or str(p.resolve())
        rec = self.vault.get(fid)
        if rec is None:
            raise CanaryError(f"카나리 레코드 없음: {fid}")

        # 1) 레코드 재무결성 확인: 저장된 nonce+ct로 토큰을 재유도해 복호화 가능한지 확인
        nonce = bytes.fromhex(rec.nonce)
        stored_ct = bytes.fromhex(rec.header_ciphertext)
        canary = self._derive_canary_token(fid, nonce)
        key = self._derive_aes_key(canary)

        # 2) GCM 복호화 (인증 태그 검증 포함 — 헤더가 변조됐으면 여기서 실패)
        aes = AESGCM(key)
        try:
            header = aes.decrypt(nonce, stored_ct, fid.encode())
        except Exception as e:
            raise CanaryTamperedError(
                f"카나리 복호화 인증 실패 ({fid}) — 헤더 암호문이 변조됐거나 "
                f"카나리 키가 유출/변경됨: {e}"
            ) from e

        # 3) 원본 헤더로 복원 (헤더는 항상 _PROTECT_HEADER_BYTES 바이트로 암호화됨)
        if len(header) != _PROTECT_HEADER_BYTES:
            raise CanaryTamperedError(f"복원 헤더 길이 이상: {fid}")
        data = p.read_bytes()
        body = data[_PROTECT_HEADER_BYTES:]
        p.write_bytes(header + body)
        rec.rotated_at = time.time()
        self.vault.put(rec)
        return rec

    # ---- 상태 점검 (복호화 없이) ----
    def check_integrity(self, path: str | Path, file_id: str | None = None) -> str:
        """현재 파일의 카나리 상태를 돌려준다."""
        p = Path(path)
        fid = file_id or str(p.resolve())
        rec = self.vault.get(fid)
        if rec is None:
            return CANARY_UNKNOWN
        try:
            nonce = bytes.fromhex(rec.nonce)
            key = self._derive_aes_key(self._derive_canary_token(fid, nonce))
            AESGCM(key).decrypt(nonce, bytes.fromhex(rec.header_ciphertext), fid.encode())
            return CANARY_OK
        except Exception:
            return CANARY_TAMPERED


def generate_master_seed() -> bytes:
    """새 마스터 시드 생성 (256비트 CSPRNG)."""
    return secrets.token_bytes(32)
