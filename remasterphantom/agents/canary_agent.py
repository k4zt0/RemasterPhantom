"""Canary 에이전트 — 파일 헤더 카나리 암호화/복호화 담당."""

from __future__ import annotations

from pathlib import Path

from ..crypto.canary import CanaryCipher, CanaryError, CanaryTamperedError
from .base import LLMAdvisor


class CanaryAgent:
    name = "canary"

    def __init__(self, cipher: CanaryCipher, advisor: LLMAdvisor | None = None):
        self.cipher = cipher
        self.advisor = advisor or LLMAdvisor(load_model=False)

    def protect(self, path: str | Path) -> dict:
        """파일 헤더를 카나리로 보호. 이미 보호된 파일은 건드리지 않는다."""
        p = Path(path)
        state = self.cipher.check_integrity(p)
        if state == "OK":
            return {"file": str(p), "action": "skip", "reason": "이미 보호됨"}
        rec = self.cipher.encrypt_header(p)
        return {"file": str(p), "action": "encrypted", "file_id": rec.file_id}

    def release(self, path: str | Path) -> dict:
        """복호화 수행. 카나리 붕괴 시 CanaryTamperedError를 위로 전파한다."""
        p = Path(path)
        try:
            rec = self.cipher.decrypt_header(p)
            return {"file": str(p), "action": "decrypted", "file_id": rec.file_id}
        except CanaryTamperedError:
            raise
        except CanaryError as e:
            return {"file": str(p), "action": "error", "reason": str(e)}

    def status(self, path: str | Path) -> dict:
        p = Path(path)
        state = self.cipher.check_integrity(p)
        advice = self.advisor.advise(f"카나리 상태 {state} — {p}",
                                     context={"state": state, "path": str(p)})
        return {"file": str(p), "canary_state": state, "advice": advice}
