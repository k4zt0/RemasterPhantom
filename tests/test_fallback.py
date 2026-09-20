import os
import secrets

import pytest

from remasterphantom.agents.orchestrator import build_default
from remasterphantom.crypto.canary import CanaryTamperedError
from remasterphantom.defense.fallback import (PhantomFallback, AuditLog)


def make_png(path):
    path.write_bytes(bytes.fromhex("89504E470D0A1A0A") + os.urandom(5000))


@pytest.fixture()
def orch(tmp_path, monkeypatch):
    monkeypatch.setenv("RP_TEST", "1")
    o = build_default(tmp_path / "state", load_llm=False)
    # 테스트에서 Keychain 대신 파일 폴리백 강제
    o.master.master._keychain_read = lambda: None
    o.master.master._keychain_write = lambda s: False
    return o


def test_arm_protects_files(orch, tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    for i in range(3):
        make_png(d / f"f{i}.png")
    out = orch.arm(d)
    assert out["protected"] == 3
    # 시그니처가 가려져 있고 스캔에서 TAMPERED로 잡힌다 (보호된 상태)
    f0 = (d / "f0.png").read_bytes()[:8]
    assert f0 != bytes.fromhex("89504E470D0A1A0A")


def test_full_cycle_arm_decrypt(orch, tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    originals = {}
    for i in range(2):
        p = d / f"g{i}.png"
        make_png(p)
        originals[p.name] = p.read_bytes()
    orch.arm(d)
    out = orch.decrypt_all(d)
    assert out["released"] == 2 and out["errors"] == []
    for name, blob in originals.items():
        assert (d / name).read_bytes() == blob


def test_ransomware_simulation_triggers_phantom(orch, tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    make_png(d / "victim.png")
    orch.arm(d)
    # 랜섬웨어 시뮬레이션: 공격자가 보호된 파일의 헤더를 파괴
    victim = d / "victim.png"
    data = bytearray(victim.read_bytes())
    data[:64] = os.urandom(64)
    victim.write_bytes(bytes(data))
    result = orch.scan_and_respond(d)
    assert result["findings"], "탐지 결과가 있어야 함"
    statuses = {r["status"] for r in result["findings"]}
    assert "TAMPERED" in statuses
    assert result["incidents"], "Phantom 인시던트가 발동해야 함"
    inc = result["incidents"][0]
    assert "QUARANTINE" in inc["stages"]
    assert "ROTATE" in inc["stages"]
    # 격리 디렉터리에 파일이 이동됐는지 확인
    assert any((tmp_path / "state").rglob("*victim*"))


def test_audit_log_signed(orch, tmp_path):
    audit = AuditLog(tmp_path / "audit.log", secrets.token_bytes(32))
    audit.record("test.event", {"a": 1})
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 1 and '"mac"' in lines[0]
