import os
import secrets

import pytest

from remasterphantom.crypto.master_canary import (
    MasterCanary, MasterCanaryTamperedError,
)


@pytest.fixture()
def master(tmp_path, monkeypatch):
    # Keychain 접근을 막고 파일 폴리백 강제 (CI/테스트 환경)
    m = MasterCanary(tmp_path / "keys")
    m._keychain_read = lambda: None
    m._keychain_write = lambda seed: False
    return m


def test_wrap_unwrap_roundtrip(master):
    pk = b"-----BEGIN PRIVATE KEY-----\n" + os.urandom(64)
    sk = os.urandom(32)
    bundle = master.wrap_tls_material(pk, sk, b"fake-cert-der")
    pk2, sk2 = master.unwrap_tls_material(bundle)
    assert pk2 == pk and sk2 == sk


def test_wrong_key_fails(master):
    pk = b"pk" + os.urandom(32)
    bundle = master.wrap_tls_material(pk, os.urandom(16))
    master.rotate()  # 키 세대 변경
    with pytest.raises(MasterCanaryTamperedError):
        master.unwrap_tls_material(bundle)


def test_pin_verification(master):
    cert = os.urandom(200)
    bundle = master.wrap_tls_material(b"pk", b"sk", cert)
    assert master.verify_pinned_cert(cert, bundle) is True
    assert master.verify_pinned_cert(os.urandom(200), bundle) is False


def test_rotation_bumps_epoch(master):
    e0 = master.rotation_epoch()
    e1 = master.rotate()
    assert e1 == e0 + 1
    assert master.derive_file_canary_seed(e1) != master.derive_file_canary_seed(e0)


def test_deterministic_derivation(master):
    assert master.derive_tls_key(0) == master.derive_tls_key(0)
    assert master.derive_file_canary_seed(0) != master.derive_tls_key(0)
