"""Master 에이전트 — MASTER CANARY와 TLS 자료 보호 담당."""

from __future__ import annotations

from pathlib import Path

from ..crypto.master_canary import (MasterCanary, TLSProtectionBundle,
                                    MasterCanaryTamperedError)
from .base import LLMAdvisor


class MasterAgent:
    name = "master"

    def __init__(self, master: MasterCanary, advisor: LLMAdvisor | None = None):
        self.master = master
        self.advisor = advisor or LLMAdvisor(load_model=False)

    def protect_tls(self, private_key_pem: bytes, session_keys: bytes,
                    pinned_cert_der: bytes | None = None) -> TLSProtectionBundle:
        """TLS 개인키/세션키/고정 인증서를 MASTER CANARY로 래핑한다."""
        bundle = self.master.wrap_tls_material(private_key_pem, session_keys,
                                               pinned_cert_der)
        self.master.root_dir.mkdir(parents=True, exist_ok=True)
        (self.master.root_dir / "tls_bundle.json").write_text(
            __import__("json").dumps({
                "wrapped_private_key": bundle.wrapped_private_key.hex(),
                "wrapped_session_keys": bundle.wrapped_session_keys.hex(),
                "pinned_cert_sha256": bundle.pinned_cert_sha256,
                "created_at": bundle.created_at,
                "version": bundle.version,
            }, indent=2))
        return bundle

    def open_tls(self, bundle: TLSProtectionBundle) -> tuple[bytes, bytes]:
        """래핑 해제. 실패 시 MasterCanaryTamperedError → Phantom 발동."""
        try:
            return self.master.unwrap_tls_material(bundle)
        except MasterCanaryTamperedError:
            raise

    def verify_peer(self, cert_der: bytes, bundle: TLSProtectionBundle) -> bool:
        """TLS 핀 검증 — 예상 인증서와 다른 인증서로의 중간자 공격 차단."""
        ok = self.master.verify_pinned_cert(cert_der, bundle)
        if not ok:
            self.advisor.advise("tls_breach — 인증서 핀 불일치",
                                context={"pin": bundle.pinned_cert_sha256})
        return ok

    def rotate_with_advice(self) -> int:
        epoch = self.master.rotate()
        self.advisor.advise(f"MASTER CANARY 회전 완료 — epoch {epoch}",
                            context={"epoch": epoch})
        return epoch

    def status(self) -> dict:
        return {
            "fingerprint": self.master.public_fingerprint(),
            "epoch": self.master.rotation_epoch(),
            "model_loaded": self.advisor.ready,
        }
