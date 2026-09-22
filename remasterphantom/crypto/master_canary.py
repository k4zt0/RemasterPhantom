"""MASTER CANARY — 루트 오브 트러스트 + TLS 자료 보호.

MASTER CANARY는 시스템 전체의 신뢰 뿌리다.
1. 모든 파일 카나리 시드(master_seed)를 MASTER CANARY로 감싼다.
2. TLS 개인키·세션 자료·인증서 고정(pin) 정보를 MASTER CANARY 키로 암호화해
   저장한다. 외부 침입자가 디스크의 TLS 자료를 훔쳐가도 쓸모없게 만든다.
3. 카나리 회전(rotate) 시 새 시드를 파생하고 이전 시드는 즉시 파기한다.

저장은 macOS Keychain을 우선하고, 불가 시 0600 권한 파일로 폴리백한다.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

_KEYCHAIN_SERVICE = "remasterphantom-master-canary"
_KEYCHAIN_ACCOUNT = "root"


class MasterCanaryError(Exception):
    pass


class MasterCanaryTamperedError(Exception):
    """MASTER CANARY 무결성 붕괴 — 최고 단계 사고."""


@dataclass
class TLSProtectionBundle:
    """TLS 자료 보호 번들. 디스크에는 항상 암호문으로만 존재한다."""
    wrapped_private_key: bytes
    wrapped_session_keys: bytes
    pinned_cert_sha256: str = ""
    created_at: float = field(default_factory=time.time)
    version: int = 1


class MasterCanary:
    """루트 시드 보관·회전·TLS 자료 래핑을 담당."""

    def __init__(self, root_dir: str | Path, passphrase: bytes | None = None):
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._passphrase = passphrase
        self._root_seed: bytes | None = None

    # ---- 루트 시드 확보 ----
    def _load_or_create_root(self) -> bytes:
        if self._root_seed is not None:
            return self._root_seed
        seed = self._keychain_read()
        if seed is None:
            seed = self._file_read() if (self.root_dir / "master.key").exists() else None
        if seed is None:
            seed = secrets.token_bytes(32)
            self._keychain_write(seed) or self._file_write(seed)
        if len(seed) < 32:
            raise MasterCanaryError("루트 시드가 32바이트 미만입니다")
        self._root_seed = seed
        return seed

    # ---- macOS Keychain 어댑터 (실패 시 파일 폴리백) ----
    def _keychain_read(self) -> bytes | None:
        try:
            out = subprocess.run(
                ["security", "find-generic-password", "-s", _KEYCHAIN_SERVICE,
                 "-a", _KEYCHAIN_ACCOUNT, "-w"],
                capture_output=True, timeout=5)
            if out.returncode == 0:
                return bytes.fromhex(out.stdout.decode().strip())
        except Exception:
            pass
        return None

    def _keychain_write(self, seed: bytes) -> bool:
        try:
            # 이미 있으면 갱신
            subprocess.run(
                ["security", "delete-generic-password", "-s", _KEYCHAIN_SERVICE,
                 "-a", _KEYCHAIN_ACCOUNT],
                capture_output=True, timeout=5)
            out = subprocess.run(
                ["security", "add-generic-password", "-U", "-s", _KEYCHAIN_SERVICE,
                 "-a", _KEYCHAIN_ACCOUNT, "-w", seed.hex()],
                capture_output=True, timeout=5)
            return out.returncode == 0
        except Exception:
            return False

    def _file_read(self) -> bytes | None:
        kp = self.root_dir / "master.key"
        try:
            return bytes.fromhex(kp.read_text().strip())
        except Exception:
            return None

    def _file_write(self, seed: bytes) -> bool:
        kp = self.root_dir / "master.key"
        kp.write_text(seed.hex())
        kp.chmod(0o600)
        return True

    # ---- 키 파생 ----
    def _derive(self, info: bytes, length: int = 32) -> bytes:
        root = self._load_or_create_root()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length,
                    salt=b"remasterphantom-master-v1", info=info)
        return hkdf.derive(root)

    def derive_file_canary_seed(self, epoch: int = 0) -> bytes:
        """파일 카나리 계층용 시드. epoch로 회전 세대를 구분한다."""
        return self._derive(b"file-canary-seed" + epoch.to_bytes(8, "big"))

    def derive_tls_key(self, epoch: int = 0) -> bytes:
        return self._derive(b"tls-wrap-key" + epoch.to_bytes(8, "big"))

    def rotation_epoch(self) -> int:
        st = self.root_dir / "epoch"
        if st.exists():
            try:
                return int(st.read_text().strip())
            except ValueError:
                pass
        return 0

    def _set_epoch(self, epoch: int) -> None:
        (self.root_dir / "epoch").write_text(str(epoch))

    # ---- TLS 자료 보호 ----
    def wrap_tls_material(self, private_key_pem: bytes, session_keys: bytes,
                          pinned_cert_der: bytes | None = None) -> TLSProtectionBundle:
        """TLS 개인키·세션키·고정 인증서 지문을 MASTER CANARY 키로 래핑한다."""
        epoch = self.rotation_epoch()
        key = self.derive_tls_key(epoch)
        aes = AESGCM(key)
        n1, n2 = secrets.token_bytes(12), secrets.token_bytes(12)
        wrapped_pk = aes.encrypt(n1, private_key_pem, b"tls-private-key")
        wrapped_sk = aes.encrypt(n2, session_keys, b"tls-session-keys")
        pin = hashlib.sha256(pinned_cert_der).hexdigest() if pinned_cert_der else ""
        return TLSProtectionBundle(wrapped_private_key=n1 + wrapped_pk,
                                   wrapped_session_keys=n2 + wrapped_sk,
                                   pinned_cert_sha256=pin)

    def unwrap_tls_material(self, bundle: TLSProtectionBundle) -> tuple[bytes, bytes]:
        """래핑 해제. 태그 검증 실패 시 침입/변조로 간주."""
        epoch = self.rotation_epoch()
        key = self.derive_tls_key(epoch)
        aes = AESGCM(key)
        try:
            pk = aes.decrypt(bundle.wrapped_private_key[:12],
                             bundle.wrapped_private_key[12:], b"tls-private-key")
            sk = aes.decrypt(bundle.wrapped_session_keys[:12],
                             bundle.wrapped_session_keys[12:], b"tls-session-keys")
            return pk, sk
        except Exception as e:
            raise MasterCanaryTamperedError(
                f"TLS 자료 래핑 해제 실패 — MASTER CANARY 불일치 또는 침입 의심: {e}"
            ) from e

    def verify_pinned_cert(self, cert_der: bytes, bundle: TLSProtectionBundle) -> bool:
        """현재 서버 인증서가 고정(pin)된 인증서와 일치하는지 확인 (TLS 핀 검증)."""
        if not bundle.pinned_cert_sha256:
            return False
        return hmac_mod.compare_digest(hashlib.sha256(cert_der).hexdigest(),
                                       bundle.pinned_cert_sha256)

    # ---- 카나리 회전 (Phantom 프로토콜의 재구성 단계에서 사용) ----
    def rotate(self) -> int:
        """루트 시드를 재생성하고 epoch를 올린다. 이전 키는 메모리에서 즉시 파기.

        주의: rotate() 후에는 이전 epoch으로 래핑된 자료를 열 수 없다.
        상위(Phantom 폴리백)가 먼저 모든 파일을 새 시드로 재카나리해야 한다.
        """
        old_epoch = self.rotation_epoch()
        new_root = secrets.token_bytes(32)
        self._root_seed = None
        if not self._keychain_write(new_root):
            self._file_write(new_root)
        self._root_seed = new_root
        new_epoch = old_epoch + 1
        self._set_epoch(new_epoch)
        # 휴지통이 아닌 난수 덮어쓰기로 흔적 제거
        self._secure_shred_residuals()
        return new_epoch

    def _secure_shred_residuals(self) -> None:
        kp = self.root_dir / "master.key"
        if kp.exists():
            kp.write_bytes(os.urandom(64))
            kp.write_text(self._root_seed.hex() if self._root_seed else "")
            kp.chmod(0o600)

    def public_fingerprint(self) -> str:
        """루트 시드의 지문(공개 가능). 무결성 대조·감사 로그용."""
        root = self._load_or_create_root()
        return hmac_mod.new(b"fingerprint", root, hashlib.sha256).hexdigest()
