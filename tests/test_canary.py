import os
import secrets

import pytest

from remasterphantom.crypto.canary import (
    CanaryCipher, CanaryVault, CanaryTamperedError, generate_master_seed,
    CANARY_OK, CANARY_TAMPERED, CANARY_UNKNOWN,
)


@pytest.fixture()
def vault(tmp_path):
    return CanaryVault(tmp_path / "vault.json", secrets.token_bytes(32))


@pytest.fixture()
def cipher(vault):
    return CanaryCipher(generate_master_seed(), vault)


def make_png(path, size=6000):
    path.write_bytes(bytes.fromhex("89504E470D0A1A0A") + os.urandom(size))


def test_encrypt_masks_signature(cipher, tmp_path):
    f = tmp_path / "a.png"
    make_png(f)
    cipher.encrypt_header(f)
    head = f.read_bytes()[:8]
    assert head != bytes.fromhex("89504E470D0A1A0A")
    assert cipher.check_integrity(f) == CANARY_OK


def test_decrypt_restores_signature(cipher, tmp_path):
    f = tmp_path / "b.png"
    original = bytes.fromhex("89504E470D0A1A0A") + os.urandom(6000)
    f.write_bytes(original)
    cipher.encrypt_header(f)
    cipher.decrypt_header(f)
    assert f.read_bytes() == original


def test_tampered_ciphertext_detected(cipher, vault, tmp_path):
    f = tmp_path / "c.png"
    make_png(f)
    rec = cipher.encrypt_header(f)
    # 레코드의 암호문을 한 비트 바꾼다
    ct = bytearray.fromhex(rec.header_ciphertext)
    ct[0] ^= 0x01
    rec.header_ciphertext = bytes(ct).hex()
    vault.put(rec)
    assert cipher.check_integrity(f) == CANARY_TAMPERED
    with pytest.raises(CanaryTamperedError):
        cipher.decrypt_header(f)


def test_vault_tamper_detected(tmp_path):
    key = secrets.token_bytes(32)
    v = CanaryVault(tmp_path / "v.json", key)
    v.put(__import__("remasterphantom.crypto.canary", fromlist=["CanaryRecord"])
          .CanaryRecord(file_id="x", nonce="00" * 16, header_ciphertext="00"))
    raw = (tmp_path / "v.json").read_text().replace('"nonce": "00000000000000000000000000000000"',
                                                     '"nonce": "01000000000000000000000000000000"')
    (tmp_path / "v.json").write_text(raw)
    with pytest.raises(CanaryTamperedError):
        CanaryVault(tmp_path / "v.json", key)


def test_unknown_state(cipher, tmp_path):
    f = tmp_path / "no_rec.png"
    make_png(f)
    assert cipher.check_integrity(f) == CANARY_UNKNOWN
