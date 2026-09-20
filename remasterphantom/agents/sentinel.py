"""Sentinel 에이전트 — 파일 시그니처 무결성 감시.

주기적으로 보호 대상 디렉터리를 스캔해 매직 바이트/해시 변조를 탐지하고,
LLM 자문을 얻어 사고 심각도를 분류한다. 탐지 결과는 다른 에이전트로 라우팅된다.
"""

from __future__ import annotations

from pathlib import Path

from ..signatures.verifier import IntegrityVerifier, VerificationResult
from ..signatures.magic_db import identify_file
from .base import LLMAdvisor


class SentinelAgent:
    name = "sentinel"

    def __init__(self, verifier: IntegrityVerifier, advisor: LLMAdvisor | None = None):
        self.verifier = verifier
        self.advisor = advisor or LLMAdvisor(load_model=False)

    def scan(self, root: str | Path) -> list[VerificationResult]:
        """디렉터리 전체 스캔. 변조/불일치 결과만 골라낸다."""
        results = self.verifier.verify_directory(root)
        return [r for r in results if not r.ok]

    def inspect(self, path: str | Path) -> dict:
        """단일 파일 식별 + 무결성 판정 + LLM 분석."""
        result = self.verifier.verify_file(path)
        detected = identify_file(path)
        advice = self.advisor.advise(
            f"파일 {path} 상태 {result.status}: {result.detail}",
            context=result.to_dict())
        return {
            "result": result.to_dict(),
            "detected": (detected.description if detected else None),
            "advice": advice,
        }

    def classify_incident(self, results: list[VerificationResult]) -> str:
        """LLM에게 사고를 분류시킨다 (rule 폴리백 포함)."""
        if not results:
            return self.advisor.advise("clean")
        summary = "; ".join(f"{r.path}:{r.status}" for r in results[:10])
        return self.advisor.advise(f"다수 파일 이상 탐지 — {summary}",
                                   context={"count": len(results)})
