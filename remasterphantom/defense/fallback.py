"""Phantom 프로토콜 — 카나리 무결성 붕괴 시 폴리백 대응.

발동 조건:
- 파일 카나리 레코드 HMAC/GCM 인증 실패 (CanaryTamperedError)
- 무결성 기준선 서명 불일치 (BaselineTamperedError)
- MASTER CANARY 래핑 해제 실패 (MasterCanaryTamperedError)
- 랜섬웨어 확산 징후 (다수 파일 동시 TAMPERED)

대응 단계 (자동 수행):
  1. 격리 (Quarantine)  — 감염/변조 의심 파일을 .quarantine/ 로 이동, 0600
  2. 봉쇄 (Lockdown)    — 디렉터리 쓰기 권한을 일시 제한(모니터링 모드)
  3. 회전 (Rotate)      — MASTER CANARY rotate → 새 시드 세대
  4. 재카나리 (Re-canary) — 클린 스냅샷에서 파일을 복원하고 새 시드로 재보호
  5. 감사 (Audit)       — 전 과정을 서명된 감사 로그에 기록
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import stat
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from ..crypto.canary import CanaryCipher, CanaryVault, CanaryTamperedError
from ..crypto.master_canary import MasterCanary
from ..signatures.verifier import IntegrityVerifier, BaselineTamperedError

STAGE_QUARANTINE = "QUARANTINE"
STAGE_LOCKDOWN = "LOCKDOWN"
STAGE_ROTATE = "ROTATE"
STAGE_RECOVER = "RECOVER"
STAGE_AUDIT = "AUDIT"

SEVERITY_LOW = "LOW"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


@dataclass
class PhantomIncident:
    trigger: str                    # 어떤 오류로 발동했는지
    severity: str
    files: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    resolved_at: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLog:
    """HMAC 서명 감사 로그 — 공격자가 대응 기록을 지우거나 변조하지 못하게 한다."""

    def __init__(self, log_path: str | Path, hmac_key: bytes):
        self.log_path = Path(log_path)
        self.hmac_key = hmac_key
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, data: dict | None = None) -> None:
        entry = {"ts": time.time(), "event": event, "data": data or {}}
        payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode()
        entry["mac"] = hmac_mod.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class PhantomFallback:
    """카나리 붕괴 사고의 자동 폴리백 오케스트레이터."""

    def __init__(self, root: str | Path, master: MasterCanary, cipher: CanaryCipher,
                 vault: CanaryVault, audit: AuditLog, snapshot_dir: str | Path | None = None):
        self.root = Path(root)
        self.master = master
        self.cipher = cipher
        self.vault = vault
        self.audit = audit
        self.quarantine_dir = self.root / ".quarantine"
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else self.root / ".snapshots"

    # ---- 사고 발동 ----
    def handle_canary_tampered(self, err: CanaryTamperedError,
                               suspect_files: list[str | Path]) -> PhantomIncident:
        """카나리 무결성 붕괴 → 전 단계 폴리백을 순서대로 수행한다."""
        inc = PhantomIncident(trigger=str(err), severity=SEVERITY_CRITICAL,
                              files=[str(f) for f in suspect_files])
        self.audit.record("phantom.incident", {"trigger": inc.trigger,
                                               "files": inc.files})
        self._stage_quarantine(inc, suspect_files)
        self._stage_lockdown(inc)
        new_epoch = self._stage_rotate(inc)
        self._stage_recover(inc, new_epoch)
        inc.resolved_at = time.time()
        self.audit.record("phantom.resolved", inc.to_dict())
        return inc

    def handle_baseline_tampered(self, err: BaselineTamperedError) -> PhantomIncident:
        """기준선 변조는 전면 침입 신호 — 치명 단계로 처리한다."""
        inc = PhantomIncident(trigger=str(err), severity=SEVERITY_CRITICAL, files=[])
        self.audit.record("phantom.baseline_tampered", {"trigger": inc.trigger})
        self._stage_lockdown(inc)
        new_epoch = self._stage_rotate(inc)
        self.audit.record("phantom.baseline_rebuild_epoch", {"epoch": new_epoch})
        inc.resolved_at = time.time()
        return inc

    # ---- 단계별 수행 ----
    def _stage_quarantine(self, inc: PhantomIncident, files: list[str | Path]) -> None:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.quarantine_dir.chmod(0o700)
        except OSError:
            pass
        for f in files:
            src = Path(f)
            if not src.exists():
                continue
            dst = self.quarantine_dir / f"{int(time.time())}_{src.name}"
            shutil.move(str(src), dst)  # 같은 볼륨이면 rename(원자적)
            dst.chmod(0o600)
            inc.actions.append(f"격리: {src} → {dst}")
        inc.stages.append(STAGE_QUARANTINE)

    def _stage_lockdown(self, inc: PhantomIncident) -> None:
        """보호 대상 디렉터리의 그룹/기타 쓰기 권한을 제거해 확산을 늦춘다."""
        try:
            mode = stat.S_IMODE(os.stat(self.root).st_mode)
            os.chmod(self.root, mode & ~0o022)
            inc.actions.append(f"락다운: {self.root} 권한 {oct(mode)} → "
                               f"{oct(mode & ~0o022)}")
        except OSError as e:
            inc.actions.append(f"락다운 실패(권한 부족): {e}")
        inc.stages.append(STAGE_LOCKDOWN)

    def _stage_rotate(self, inc: PhantomIncident) -> int:
        new_epoch = self.master.rotate()
        self.audit.record("phantom.rotate", {"new_epoch": new_epoch,
                                             "fingerprint": self.master.public_fingerprint()})
        inc.actions.append(f"MASTER CANARY 회전 → epoch {new_epoch}")
        inc.stages.append(STAGE_ROTATE)
        return new_epoch

    def _stage_recover(self, inc: PhantomIncident, new_epoch: int) -> None:
        """스냅샷에서 클린 파일을 복원하고 새 시드로 재카나리한다.

        스냅샷이 없으면 클린한 남은 파일만 재카나리한다.
        """
        new_seed_files = 0
        if self.snapshot_dir.exists():
            for snap in sorted(self.snapshot_dir.iterdir()):
                target = self.root / snap.name
                if target.exists():
                    continue  # 격리·존재 파일은 덮지 않음
                shutil.copy2(snap, target)
                inc.actions.append(f"스냅샷 복원: {snap.name}")
        # 남아 있는 파일들을 새 시드로 재보호
        for fid in list(self.vault.all().keys()):
            p = Path(fid)
            if p.exists() and p.is_file():
                try:
                    self.cipher.decrypt_header(p, fid)
                    self.cipher.encrypt_header(p, fid)
                    new_seed_files += 1
                except CanaryTamperedError:
                    inc.actions.append(f"재카나리 불가(파괴): {fid}")
        if new_seed_files:
            inc.actions.append(f"재카나리 완료: {new_seed_files}개 파일 (epoch {new_epoch})")
        inc.stages.append(STAGE_RECOVER)

    # ---- 사후 스냅샷 (평시 백업) ----
    def take_snapshot(self, paths: list[str | Path]) -> None:
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        for f in paths:
            src = Path(f)
            if src.is_file() and src.exists():
                shutil.copy2(src, self.snapshot_dir / src.name)
