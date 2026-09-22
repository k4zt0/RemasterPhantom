"""Phantom 에이전트 — 카나리 무결성 붕괴 시 폴리백 대응 총괄."""

from __future__ import annotations

from pathlib import Path

from ..crypto.canary import CanaryTamperedError
from ..crypto.master_canary import MasterCanaryTamperedError
from ..defense.fallback import PhantomFallback, PhantomIncident
from .base import LLMAdvisor


class PhantomAgent:
    name = "phantom"

    def __init__(self, fallback: PhantomFallback, advisor: LLMAdvisor | None = None):
        self.fallback = fallback
        self.advisor = advisor or LLMAdvisor(load_model=False)

    def respond_canary_breach(self, err: CanaryTamperedError,
                              suspect_files: list[str | Path]) -> PhantomIncident:
        """카나리 붕괴 → LLM에게 사고 해석을 맡기고 폴리백을 수행한다."""
        self.advisor.advise(f"canary tampered: {err}",
                            context={"files": [str(f) for f in suspect_files]})
        return self.fallback.handle_canary_tampered(err, suspect_files)

    def respond_tls_breach(self, err: MasterCanaryTamperedError) -> PhantomIncident:
        self.advisor.advise(f"tls_breach: {err}")
        return self.fallback.handle_baseline_tampered(err)  # 동급 치사 조치

    def respond_baseline_breach(self, err) -> PhantomIncident:
        self.advisor.advise(f"baseline tampered: {err}")
        return self.fallback.handle_baseline_tampered(err)

    def snapshot_clean(self, paths: list[str | Path]) -> None:
        """평시 클린 스냅샷을 찍어 두어 복구 단계의 원본으로 삼는다."""
        self.fallback.take_snapshot(paths)
