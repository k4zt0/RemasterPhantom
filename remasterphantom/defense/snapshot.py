"""스냅샷 관리자.

클린 상태의 파일 사본을 유지해 Phantom 프로토콜의 복구 단계에 쓴다.
사본은 파일명에 해시 접두사를 붙여 변조 시 즉시 알 수 있게 한다.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path


class SnapshotManager:
    def __init__(self, snapshot_dir: str | Path):
        self.dir = Path(snapshot_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _hash_prefix(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read(1 << 20))
        return h.hexdigest()[:16]

    def take(self, path: str | Path) -> Path | None:
        p = Path(path)
        if not p.is_file():
            return None
        dst = self.dir / f"{self._hash_prefix(p)}_{p.name}"
        shutil.copy2(p, dst)
        return dst

    def restore(self, name: str, dest: str | Path) -> Path:
        src = self.dir / name
        shutil.copy2(src, dest)
        return Path(dest)

    def list(self) -> list[Path]:
        return sorted(self.dir.iterdir()) if self.dir.exists() else []

    def verify(self, name: str) -> bool:
        """스냅샷이 저장 당시 해시 접두사와 여전히 일치하는지 확인."""
        p = self.dir / name
        if not p.exists():
            return False
        prefix = name.split("_", 1)[0]
        return self._hash_prefix(p) == prefix
