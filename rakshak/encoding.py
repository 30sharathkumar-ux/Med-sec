"""Safe encoding detection and text decoding for heterogeneous hospital exports."""

from __future__ import annotations

from dataclasses import dataclass

# Undefined bytes in Windows-1252
_CP1252_UNDEFINED = frozenset({0x81, 0x8D, 0x8F, 0x90, 0x9D})

# Binary signatures that must never be decoded as text
_BINARY_PREFIXES = (
    b"%PDF-",
    b"\xff\xd8\xff",       # JPEG
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"GIF87a",
    b"GIF89a",
    b"PK\x03\x04",         # ZIP / Office
    b"\x1f\x8b\x08",       # GZIP
    b"\x7fELF",            # ELF binary
    b"MZ",                 # PE binary
)


@dataclass(frozen=True)
class DecodedText:
    """Result of safe byte decoding."""

    text: str
    encoding: str


def is_probably_binary(raw: bytes) -> bool:
    """Detect known binary file headers or null-byte binary payloads (excluding UTF-16 BOM)."""
    for sig in _BINARY_PREFIXES:
        if raw.startswith(sig):
            return True
    if not raw.startswith((b"\xff\xfe", b"\xfe\xff")) and b"\x00" in raw:
        return True
    return False


def _has_control_bytes(raw: bytes) -> bool:
    """Reject disallowed C0 control characters outside tab/newline/CR/FF."""
    for b in raw:
        if b < 0x20 and b not in (0x09, 0x0A, 0x0D, 0x0C):
            return True
    return False


def _is_plausible_cp1252(raw: bytes) -> bool:
    """Accept legacy cp1252 typography/symbols while rejecting corrupt byte runs."""
    # Reject undefined cp1252 codepoints and embedded UTF-16 BOM markers.
    if b"\xff\xfe" in raw or b"\xfe\xff" in raw:
        return False
    high_run = 0
    for b in raw:
        if b in _CP1252_UNDEFINED:
            return False
        if b >= 0x80:
            high_run += 1
            # Consecutive non-ASCII bytes in a file that already failed UTF-8 strongly indicate
            # corrupt encoding or binary bytes rather than Indian medical cp1252 punctuation.
            if high_run >= 2:
                return False
        else:
            high_run = 0
    return True


def decode_bytes(raw: bytes) -> tuple[DecodedText | None, str | None]:
    """Decode raw bytes safely into text, returning (DecodedText, None) or (None, reason)."""
    if not raw.strip():
        return None, "empty_file"
    if is_probably_binary(raw):
        return None, "binary_payload"

    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            text = raw[3:].decode("utf-8", errors="strict")
            if _has_control_bytes(raw[3:]):
                return None, "corrupt_encoding"
            return DecodedText(text=text, encoding="utf-8-bom"), None
        except UnicodeDecodeError:
            return None, "undecodable_text"

    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            text = raw.decode("utf-16", errors="strict")
            # Reject replacement or NUL artifacts inside decoded UTF-16
            if "\x00" in text or "\ufffd" in text:
                return None, "corrupt_encoding"
            return DecodedText(text=text, encoding="utf-16"), None
        except UnicodeDecodeError:
            return None, "undecodable_text"

    if _has_control_bytes(raw):
        return None, "corrupt_encoding"

    try:
        text = raw.decode("utf-8", errors="strict")
        return DecodedText(text=text, encoding="utf-8"), None
    except UnicodeDecodeError:
        pass

    if not _is_plausible_cp1252(raw):
        return None, "corrupt_encoding"

    try:
        text = raw.decode("cp1252", errors="strict")
        return DecodedText(text=text, encoding="cp1252"), None
    except UnicodeDecodeError:
        return None, "undecodable_text"
