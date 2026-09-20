import io
import struct
import zlib

from remasterphantom.signatures.magic_db import identify_signature, MAGIC_DB


def png_bytes() -> bytes:
    sig = bytes.fromhex("89504E470D0A1A0A")
    ihdr = struct.pack(">I", 13) + b"IHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00"
    return sig + ihdr


def test_png_identified():
    info = identify_signature(png_bytes())
    assert info is not None and info.extension == "png"
    assert info.offset == 0


def test_zip_vs_docx_is_zip():
    data = bytes.fromhex("504B0304") + b"\x00" * 100
    info = identify_signature(data)
    assert info is not None and info.extension == "zip"


def test_mach_o_64():
    info = identify_signature(bytes.fromhex("CFFAEDFE") + b"\x00" * 32)
    assert info is not None and info.extension == "macho"


def test_tar_offset_257():
    data = bytearray(512)
    data[257:262] = b"ustar"
    info = identify_signature(bytes(data))
    assert info is not None and info.extension == "tar"


def test_unknown_returns_none():
    assert identify_signature(os_urandom_like()) is None


def os_urandom_like() -> bytes:
    return b"\xde\xad\xbe\xef" * 64


def test_all_db_signatures_have_min_confidence():
    for s in MAGIC_DB:
        assert 0 < s.confidence <= 1.0
        assert len(s.signature) >= 2
