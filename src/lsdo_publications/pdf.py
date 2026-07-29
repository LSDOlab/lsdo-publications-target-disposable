from __future__ import annotations

import re
import zlib
from pathlib import Path

from .errors import PublicationError
from .util import sha256_bytes

MAX_BYTES = 25 * 1024 * 1024
MAX_OBJECTS = 50_000
MAX_DECODED_OBJECT_STREAM_BYTES = 64 * 1024 * 1024
MAX_TOTAL_DECODED_OBJECT_BYTES = 128 * 1024 * 1024
DOI_CANDIDATE = re.compile(rb"10\.\d{4,9}/[-._;()/:A-Z0-9]+", re.I)
ARXIV_CANDIDATE = re.compile(
    rb"(?:arxiv\s*:\s*|arxiv\.org/(?:abs|pdf)/)(\d{4}\.\d{4,5}|[a-z-]+/\d{7})(?:v\d+)?",
    re.I,
)
PDF_NAME = re.compile(
    rb"/((?:#[0-9A-Fa-f]{2}|[^\x00\t\n\f\r ()<>\[\]{}/%])+)"
)
OBJECT_HEADER = re.compile(rb"(?m)^[ \t]*\d+[ \t]+\d+[ \t]+obj\b")
STREAM_AFTER_DICTIONARY = re.compile(
    rb"[ \t\r\n\f\x00]*stream[ \t]*\r?\n"
)
DIRECT_LENGTH = re.compile(
    rb"/Length[ \t\r\n\f\x00]+(\d+)\b"
    rb"(?![ \t\r\n\f\x00]+\d+[ \t\r\n\f\x00]+R\b)"
)
INDIRECT_LENGTH = re.compile(
    rb"/Length[ \t\r\n\f\x00]+(\d+)"
    rb"[ \t\r\n\f\x00]+(\d+)[ \t\r\n\f\x00]+R\b"
)
COMPRESSED_COUNT = re.compile(rb"/N[ \t\r\n\f\x00]+(\d+)\b")
FILTER_NAMES = {
    b"ASCII85Decode",
    b"A85",
    b"ASCIIHexDecode",
    b"AHx",
    b"CCITTFaxDecode",
    b"CCF",
    b"Crypt",
    b"DCTDecode",
    b"DCT",
    b"FlateDecode",
    b"Fl",
    b"JBIG2Decode",
    b"JPXDecode",
    b"LZWDecode",
    b"LZW",
    b"RunLengthDecode",
    b"RL",
}
UNSAFE_NAMES = {
    b"Encrypt": "encrypted",
    b"JavaScript": "active JavaScript",
    b"JS": "active JavaScript",
    b"Launch": "launch action",
    b"EmbeddedFile": "embedded file",
    b"EmbeddedFiles": "embedded files",
}
HEX = frozenset(b"0123456789abcdefABCDEF")


def _decode_name(raw: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    while index < len(raw):
        if (
            raw[index] == ord("#")
            and index + 2 < len(raw)
            and raw[index + 1] in HEX
            and raw[index + 2] in HEX
        ):
            decoded.append(int(raw[index + 1 : index + 3], 16))
            index += 3
        else:
            decoded.append(raw[index])
            index += 1
    return bytes(decoded)


def _names(data: bytes) -> list[bytes]:
    return [_decode_name(match.group(1)) for match in PDF_NAME.finditer(data)]


def _reject_unsafe_names(data: bytes) -> None:
    for name in _names(data):
        reason = UNSAFE_NAMES.get(name)
        if reason is None:
            continue
        code = "E_PDF_ENCRYPTED" if name == b"Encrypt" else "E_PDF_UNSAFE"
        raise PublicationError(code, reason)


def _flate_decode(payload: bytes) -> bytes:
    last_error: zlib.error | None = None
    for window_bits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            decoder = zlib.decompressobj(window_bits)
            decoded = decoder.decompress(
                payload,
                MAX_DECODED_OBJECT_STREAM_BYTES + 1,
            )
            if (
                len(decoded) > MAX_DECODED_OBJECT_STREAM_BYTES
                or decoder.unconsumed_tail
            ):
                raise PublicationError(
                    "E_PDF_UNSAFE",
                    "decoded object stream limit exceeded",
                )
            decoded += decoder.flush(
                MAX_DECODED_OBJECT_STREAM_BYTES + 1 - len(decoded)
            )
            if len(decoded) > MAX_DECODED_OBJECT_STREAM_BYTES:
                raise PublicationError(
                    "E_PDF_UNSAFE",
                    "decoded object stream limit exceeded",
                )
            if not decoder.eof:
                raise PublicationError("E_PDF_INVALID", "truncated Flate object stream")
            return decoded
        except zlib.error as exc:
            last_error = exc
    raise PublicationError("E_PDF_INVALID", f"invalid Flate object stream: {last_error}")


def _declared_length(data: bytes, header: bytes) -> int:
    direct = DIRECT_LENGTH.search(header)
    if direct:
        return int(direct.group(1))
    indirect = INDIRECT_LENGTH.search(header)
    if indirect is None:
        raise PublicationError(
            "E_PDF_UNSAFE",
            "object stream must declare a bounded Length",
        )
    number, generation = indirect.groups()
    value = re.compile(
        rb"(?m)^[ \t]*"
        + re.escape(number)
        + rb"[ \t]+"
        + re.escape(generation)
        + rb"[ \t]+obj[ \t\r\n\f\x00]+(\d+)"
        + rb"[ \t\r\n\f\x00]+endobj\b"
    )
    matches = value.findall(data)
    if len(matches) != 1:
        raise PublicationError(
            "E_PDF_UNSAFE",
            "object stream Length reference is absent or ambiguous",
        )
    return int(matches[0])


def _object_streams(data: bytes) -> tuple[int, int]:
    compressed_objects = 0
    total_decoded = 0
    for name_match in PDF_NAME.finditer(data):
        if _decode_name(name_match.group(1)) != b"ObjStm":
            continue
        dictionary_start = data.rfind(
            b"<<",
            max(0, name_match.start() - 65_536),
            name_match.start(),
        )
        dictionary_end = data.find(
            b">>",
            name_match.end(),
            min(len(data), name_match.end() + 65_536),
        )
        if dictionary_start < 0 or dictionary_end < 0:
            raise PublicationError(
                "E_PDF_UNSAFE",
                "object stream dictionary is absent or oversized",
            )
        header = data[dictionary_start : dictionary_end + 2]
        header_names = _names(header)
        count = COMPRESSED_COUNT.search(header)
        if count is None:
            raise PublicationError(
                "E_PDF_UNSAFE",
                "object stream must declare a direct bounded N value",
            )
        size = _declared_length(data, header)
        if size > MAX_BYTES:
            raise PublicationError("E_PDF_UNSAFE", "object stream length exceeds PDF limit")
        stream = STREAM_AFTER_DICTIONARY.match(data, dictionary_end + 2)
        if stream is None:
            raise PublicationError(
                "E_PDF_INVALID",
                "object stream dictionary is not followed by stream data",
            )
        payload_start = stream.end()
        payload_end = payload_start + size
        if payload_end > len(data):
            raise PublicationError("E_PDF_INVALID", "object stream exceeds file")
        if not re.match(rb"[ \t\r\n]*endstream\b", data[payload_end : payload_end + 32]):
            raise PublicationError(
                "E_PDF_INVALID",
                "object stream length does not reach endstream",
            )
        filters = [name for name in header_names if name in FILTER_NAMES]
        if b"Filter" in header_names and not filters:
            raise PublicationError(
                "E_PDF_UNSAFE",
                "object stream uses an indirect or unknown filter",
            )
        flate_only = bool(filters) and all(
            name in {b"FlateDecode", b"Fl"} for name in filters
        )
        if filters and not flate_only:
            raise PublicationError(
                "E_PDF_UNSAFE",
                "object stream uses an unsupported filter chain",
            )
        payload = data[payload_start:payload_end]
        decoded = _flate_decode(payload) if flate_only else payload
        total_decoded += len(decoded)
        if total_decoded > MAX_TOTAL_DECODED_OBJECT_BYTES:
            raise PublicationError(
                "E_PDF_UNSAFE",
                "total decoded object stream limit exceeded",
            )
        compressed_objects += int(count.group(1))
        _reject_unsafe_names(decoded)
    return compressed_objects, total_decoded


def inspect_pdf(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise PublicationError("E_PDF_TOO_LARGE", f"{len(data)} bytes")
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-4096:]:
        raise PublicationError("E_PDF_INVALID", "missing PDF signature or EOF")
    eof = data.rfind(b"%%EOF")
    if data[eof + 5 :].strip():
        raise PublicationError("E_PDF_UNSAFE", "trailing polyglot content")
    _reject_unsafe_names(data)
    compressed_objects, _ = _object_streams(data)
    object_count = len(OBJECT_HEADER.findall(data)) + compressed_objects
    if object_count > MAX_OBJECTS:
        raise PublicationError("E_PDF_UNSAFE", "object-count limit exceeded")
    dois = sorted(
        {
            match.group(0).decode("ascii").rstrip(".,;:)]}").lower()
            for match in DOI_CANDIDATE.finditer(data)
        }
    )
    arxiv = sorted(
        {match.group(1).decode("ascii").lower() for match in ARXIV_CANDIDATE.finditer(data)}
    )
    if len(dois) + len(arxiv) == 0:
        outcome = "E_NO_IDENTIFIER"
    elif len(dois) > 1 or len(arxiv) > 1:
        outcome = "E_MULTIPLE_IDENTIFIERS"
    else:
        outcome = "identifiers-found"
    return {
        "schema_version": 1,
        "path": path.name,
        "sha256": sha256_bytes(data),
        "bytes": len(data),
        "dois": dois,
        "arxiv": arxiv,
        "outcome": outcome,
    }
