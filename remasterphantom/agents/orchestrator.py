"""RemasterPhantom 오케스트레이터 — 네 에이전트를 하나로 묶는 진입점.

흐름:
  Sentinel이 이상을 탐지 → 분류 → Canary/Master/Phantom 중 담당 에이전트로 라우팅.
  모든 결정론적 보안 연산은 각 에이전트의 코어가 수행하고, LLM은 판단 지원.
"""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from ..crypto.canary import CanaryCipher, CanaryVault
from ..crypto.master_canary import MasterCanary
from ..defense.fallback import PhantomFallback, AuditLog
from ..signatures.verifier import IntegrityVerifier
from .base import LLMAdvisor, DEFAULT_MODEL
from .sentinel import SentinelAgent
from .canary_agent import CanaryAgent
from .master_agent import MasterAgent
from .phantom_agent import PhantomAgent


def build_default(root: str | Path, load_llm: bool = True,
                  model_id: str = DEFAULT_MODEL) -> "RemasterOrchestrator":
    """권장 구성으로 오케스트레이터를 한 번에 생성한다."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    keys_dir = root / "keys"
    keys_dir.mkdir(exist_ok=True)

    # 각 저장소의 HMAC 키는 독립적 — 하나가 유출돼도 다른 계층은 유지된다.
    def _key(name: str) -> bytes:
        kp = keys_dir / f"{name}.key"
        if kp.exists():
            return bytes.fromhex(kp.read_text().strip())
        k = secrets.token_bytes(32)
        kp.write_text(k.hex())
        kp.chmod(0o600)
        return k

    master = MasterCanary(keys_dir)
    seed = master.derive_file_canary_seed(master.rotation_epoch())
    vault = CanaryVault(keys_dir / "canary_vault.json", _key("vault"))
    cipher = CanaryCipher(seed, vault)
    verifier = IntegrityVerifier(keys_dir / "baseline.json", _key("baseline"))
    audit = AuditLog(keys_dir / "audit.log", _key("audit"))

    advisor = LLMAdvisor(model_id=model_id, load_model=load_llm)
    fallback = PhantomFallback(root, master, cipher, vault, audit)
    return RemasterOrchestrator(
        root=root,
        sentinel=SentinelAgent(verifier, advisor),
        canary=CanaryAgent(cipher, advisor),
        master_agent=MasterAgent(master, advisor),
        phantom=PhantomAgent(fallback, advisor),
        advisor=advisor,
        keys_dir=keys_dir,
    )


class RemasterOrchestrator:
    def __init__(self, root: Path, sentinel: SentinelAgent, canary: CanaryAgent,
                 master_agent: MasterAgent, phantom: PhantomAgent,
                 advisor: LLMAdvisor, keys_dir: Path):
        self.root = Path(root)
        self.sentinel = sentinel
        self.canary = canary
        self.master = master_agent
        self.phantom = phantom
        self.advisor = advisor
        self.keys_dir = keys_dir

    # ---- 상위 수준 워크플로우 ----
    def arm(self, target_dir: str | Path) -> dict:
        """보호 개시: 스캔 → 기준선 등록 → 칸네리 암호화 → 클린 스냅샷."""
        target = Path(target_dir)
        registered, protected = 0, 0
        for p in sorted(target.rglob("*")):
            if not p.is_file() or p.name.startswith("."):
                continue
            res = self.sentinel.verifier.verify_file(p)
            if res.status in ("CLEAN", "UNKNOWN"):
                self.sentinel.verifier.register(p)
                self.canary.protect(p)
                self.phantom.snapshot_clean([p])
                registered += 1
                protected += 1
        return {"registered": registered, "protected": protected,
                "skipped_tampered": len(list(target.rglob('*'))) - registered}

    def scan_and_respond(self, target_dir: str | Path) -> dict:
        """주기적 스캔 — 탐지 시 자동으로 Phantom 폴리백까지 수행한다."""
        target = Path(target_dir)
        findings = self.sentinel.scan(target)
        incidents = []
        tampered_paths = []
        for r in findings:
            if r.status in ("TAMPERED", "HASH_MISMATCH"):
                tampered_paths.append(r.path)
        if tampered_paths:
            from ..crypto.canary import CanaryTamperedError
            inc = self.phantom.respond_canary_breach(
                CanaryTamperedError(f"스캔 탐지: {len(tampered_paths)}개 파일 변조"),
                tampered_paths)
            incidents.append(inc.to_dict())
        advice = self.sentinel.classify_incident(findings)
        return {"findings": [r.to_dict() for r in findings],
                "incidents": incidents, "advice": advice}

    def decrypt_all(self, target_dir: str | Path) -> dict:
        """관리 목적의 전체 복호화."""
        released, errors = 0, []
        for p in sorted(Path(target_dir).rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                try:
                    out = self.canary.release(p)
                    if out.get("action") == "decrypted":
                        released += 1
                except Exception as e:
                    errors.append({"file": str(p), "error": str(e)})
        return {"released": released, "errors": errors}

    def status(self) -> dict:
        return {
            "root": str(self.root),
            "llm_loaded": self.advisor.ready,
            "master": self.master.status(),
        }
