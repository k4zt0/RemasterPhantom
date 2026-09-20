"""파일 시그니처(매직 바이트) 데이터베이스 및 식별기.

랜섬웨어는 파일의 매직 바이트를 깨뜨려 파일을 사용 불능으로 만든다.
RemasterPhantom은 각 파일 형식의 시그니처를 정확히 알아야 무결성 여부를
판별할 수 있다. 오프셋-시그니처 매칭으로 동작하며, 동적 우선순위를 둔다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SignatureInfo:
    extension: str
    mime: str
    description: str
    signature: bytes
    offset: int = 0
    confidence: float = 1.0
    # 매직 바이트만으로는 구분 불가한 공유 시그니처(ZIP 계열 등)의
    # 범용 컨테이너 여부. 동점 시 generic 항목이 우선한다.
    generic: bool = False


# (extension, mime, description, offset, hex signature)
_RAW: list[tuple[str, str, str, int, str]] = [
    # --- 이미지 ---
    ("png", "image/png", "PNG image", 0, "89504E470D0A1A0A"),
    ("jpg", "image/jpeg", "JPEG image", 0, "FFD8FF"),
    ("gif", "image/gif", "GIF image", 0, "474946383761"),
    ("gif", "image/gif", "GIF image (89a)", 0, "474946383961"),
    ("bmp", "image/bmp", "Windows bitmap", 0, "424D"),
    ("webp", "image/webp", "WebP image", 8, "57454250"),
    ("tiff", "image/tiff", "TIFF (little-endian)", 0, "49492A00"),
    ("tiff", "image/tiff", "TIFF (big-endian)", 0, "4D4D002A"),
    ("ico", "image/x-icon", "Windows icon", 0, "00000100"),
    ("heic", "image/heic", "HEIF/HEIC image", 4, "6674797068656963"),
    ("psd", "image/vnd.adobe.photoshop", "Adobe Photoshop", 0, "38425053"),
    # --- 문서 ---
    ("pdf", "application/pdf", "PDF document", 0, "25504446"),
    ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "Word (OOXML zip)", 0, "504B0304"),
    ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     "Excel (OOXML zip)", 0, "504B0304"),
    ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
     "PowerPoint (OOXML zip)", 0, "504B0304"),
    ("epub", "application/epub+zip", "EPUB ebook", 0, "504B0304"),
    ("rtf", "application/rtf", "Rich Text Format", 0, "7B5C727466"),
    # --- 아카이브 ---
    ("zip", "application/zip", "ZIP archive", 0, "504B0304"),
    ("zip", "application/zip", "ZIP archive (empty)", 0, "504B0506"),
    ("zip", "application/zip", "ZIP archive (spanned)", 0, "504B0708"),
    ("7z", "application/x-7z-compressed", "7-Zip archive", 0, "377ABCAF271C"),
    ("rar", "application/vnd.rar", "RAR archive", 0, "526172211A0700"),
    ("rar", "application/vnd.rar", "RAR5 archive", 0, "526172211A070100"),
    ("gz", "application/gzip", "GZip archive", 0, "1F8B"),
    ("tar", "application/x-tar", "TAR archive (ustar)", 257, "7573746172"),
    ("bz2", "application/x-bzip2", "BZip2 archive", 0, "425A68"),
    ("xz", "application/x-xz", "XZ archive", 0, "FD377A585A00"),
    # --- 오디오/비디오 ---
    ("mp3", "audio/mpeg", "MP3 audio (ID3v2)", 0, "494433"),
    ("mp3", "audio/mpeg", "MP3 audio (frame sync)", 0, "FFFB"),
    ("mp3", "audio/mpeg", "MP3 audio (frame sync V2)", 0, "FFF3"),
    ("wav", "audio/wav", "WAV audio (RIFF)", 0, "52494646"),
    ("flac", "audio/flac", "FLAC audio", 0, "664C6143"),
    ("ogg", "audio/ogg", "Ogg container", 0, "4F676753"),
    ("mp4", "video/mp4", "MP4 (isom)", 4, "6674797069736F6D"),
    ("mp4", "video/mp4", "MP4 (iso2)", 4, "6674797069736F32"),
    ("mp4", "video/mp4", "MP4 (M4A)", 4, "667479704D344120"),
    ("mov", "video/quicktime", "QuickTime movie", 4, "6674797071742020"),
    ("mkv", "video/x-matroska", "Matroska", 0, "1A45DFA3"),
    ("avi", "video/x-msvideo", "AVI (RIFF)", 0, "52494646"),
    ("wmv", "video/x-ms-asf", "Windows Media (ASF)", 0, "3026B2758E66CF11"),
    ("webm", "video/webm", "WebM (Matroska)", 0, "1A45DFA3"),
    # --- 실행 바이너리 ---
    ("exe", "application/vnd.microsoft.portable-executable",
     "Windows PE executable", 0, "4D5A"),  # MZ
    ("dll", "application/vnd.microsoft.portable-executable",
     "Windows PE DLL", 0, "4D5A"),
    ("elf", "application/x-elf", "ELF executable", 0, "7F454C46"),
    # Mach-O (macOS) — fat/thin, 각 endianness
    ("macho", "application/x-mach-binary", "Mach-O 64-bit (x86_64)", 0, "CFFAEDFE"),
    ("macho", "application/x-mach-binary", "Mach-O 64-bit (arm64)", 0, "CFFAEDFE"),
    ("macho", "application/x-mach-binary", "Mach-O 32-bit", 0, "CEFAEDFE"),
    ("macho", "application/x-mach-binary", "Mach-O fat binary", 0, "CAFEBABE"),
    ("macho", "application/x-mach-binary", "Mach-O fat binary (64)", 0, "CAFEBABF"),
    ("dmg", "application/x-apple-diskimage", "Apple DMG (UDCO)", 0, "6B6F6C79"),
    ("dmg", "application/x-apple-diskimage", "Apple DMG (UDRW)", 0, "6B6F6C79"),
    ("pkg", "application/x-newton-compatible-pkg", "macOS installer pkg (xar)", 0, "78617221"),
    ("deb", "application/vnd.debian.binary-package", "Debian package", 0, "213C617263683E"),
    ("rpm", "application/x-rpm", "RPM package", 0, "EDABEEDB"),
    # --- 데이터/DB ---
    ("sqlite", "application/vnd.sqlite3", "SQLite database", 0, "53514C69746520666F726D6174203300"),
    ("class", "application/java-vm", "Java class", 0, "CAFEBABE"),
    ("wasm", "application/wasm", "WebAssembly binary", 0, "0061736D"),
    # --- 글로벌 키스토어 등 ---
    ("keystore", "application/octet-stream", "Java KeyStore", 0, "FEEDFEED"),
    ("der", "application/x-x509-ca-cert", "X.509 DER certificate", 0, "3082"),
]

MAGIC_DB: list[SignatureInfo] = [
    SignatureInfo(
        extension=ext, mime=mime, description=desc,
        signature=bytes.fromhex(hexsig), offset=off,
        # 시그니처가 길수록 우연히 겹칠 확률이 낮아 신뢰도를 높게 준다.
        confidence=min(1.0, 0.55 + 0.09 * len(bytes.fromhex(hexsig))),
        # ZIP 시그니처를 공유하는 OOXML 계열의 범용 컨테이너로 표시
        generic=(ext == "zip"),
    )
    for ext, mime, desc, off, hexsig in _RAW
]


def identify_signature(data: bytes) -> SignatureInfo | None:
    """버퍼의 매직 바이트로 파일 형식을 식별한다.

    여러 시그니처가 매칭되면 (시그니처 길이 × 신뢰도) 점수가 높은 것을 선택하고,
    동점이면 범용 컨테이너(generic)를 우선한다. 예: 50 4B 03 04는 ZIP 계열과
    OOXML이 공유하므로 매직 바이트만으로는 'zip'으로 판정하는 것이 정직하다.
    """
    best: SignatureInfo | None = None
    best_key: tuple[float, bool] | None = None
    for sig in MAGIC_DB:
        end = sig.offset + len(sig.signature)
        if len(data) < end:
            continue
        if data[sig.offset:end] == sig.signature:
            key = (len(sig.signature) * sig.confidence, sig.generic)
            if best_key is None or key > best_key:
                best = sig
                best_key = key
    return best


def identify_file(path: str | Path, read_bytes: int = 4096) -> SignatureInfo | None:
    """파일의 첫 바이트들을 읽어 시그니처를 식별한다."""
    with open(path, "rb") as f:
        head = f.read(read_bytes)
    return identify_signature(head)


def expected_signature(path: str | Path) -> SignatureInfo | None:
    """확장자 기반 기대 시그니처 후보를 반환한다 (교차 검증용)."""
    ext = Path(path).suffix.lower().lstrip(".")
    candidates = [s for s in MAGIC_DB if s.extension == ext]
    return candidates[0] if candidates else None
