from __future__ import annotations

import re
from pathlib import Path

from .errors import PublicationError
from .util import sha256_bytes

MAX_BYTES = 25 * 1024 * 1024
MAX_OBJECTS = 50_000
DOI_CANDIDATE = re.compile(rb"10\.\d{4,9}/[-._;()/:A-Z0-9]+", re.I)
ARXIV_CANDIDATE = re.compile(
    rb"(?:arxiv\s*:\s*|arxiv\.org/(?:abs|pdf)/)(\d{4}\.\d{4,5}|[a-z-]+/\d{7})(?:v\d+)?",
    re.I,
)
UNSAFE = {
    b"/Encrypt": "encrypted",
    b"/JavaScript": "active JavaScript",
    b"/JS": "active JavaScript",
    b"/Launch": "launch action",
    b"/EmbeddedFile": "embedded file",
}


def inspect_pdf(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise PublicationError("E_PDF_TOO_LARGE", f"{len(data)} bytes")
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-4096:]:
        raise PublicationError("E_PDF_INVALID", "missing PDF signature or EOF")
    eof = data.rfind(b"%%EOF")
    if data[eof + 5 :].strip():
        raise PublicationError("E_PDF_UNSAFE", "trailing polyglot content")
    if len(re.findall(rb"(?m)^\s*\d+\s+\d+\s+obj\b", data)) > MAX_OBJECTS:
        raise PublicationError("E_PDF_UNSAFE", "object-count limit exceeded")
    for marker, reason in UNSAFE.items():
        if marker in data:
            code = "E_PDF_ENCRYPTED" if marker == b"/Encrypt" else "E_PDF_UNSAFE"
            raise PublicationError(code, reason)
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
