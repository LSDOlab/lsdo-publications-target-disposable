from __future__ import annotations

import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from lsdo_publications.errors import PublicationError
from lsdo_publications.pdf import inspect_pdf


def pdf(body: bytes) -> bytes:
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n" + body + b"\n%%EOF\n"


class PdfTests(unittest.TestCase):
    def inspect(self, data: bytes) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.pdf"
            path.write_bytes(data)
            return inspect_pdf(path)

    def test_single_doi(self) -> None:
        report = self.inspect(pdf(b"doi:10.2514/6.2026-4806"))
        self.assertEqual(["10.2514/6.2026-4806"], report["dois"])
        self.assertEqual("identifiers-found", report["outcome"])

    def test_ambiguous_doi(self) -> None:
        report = self.inspect(pdf(b"10.1000/one 10.1000/two"))
        self.assertEqual("E_MULTIPLE_IDENTIFIERS", report["outcome"])

    def test_invalid_pdf(self) -> None:
        with self.assertRaisesRegex(PublicationError, "E_PDF_INVALID"):
            self.inspect(b"not a PDF")

    def test_malicious_markers(self) -> None:
        for marker in (b"/JavaScript", b"/Launch", b"/EmbeddedFile"):
            with self.subTest(marker=marker), self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
                self.inspect(pdf(marker))

    def test_escaped_active_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
            self.inspect(pdf(b"<< /S /Java#53cript /JS (app.alert) >>"))

    def test_compressed_object_stream_active_name_is_rejected(self) -> None:
        objects = b"1 0 << /S /Java#53cript /JS (app.alert) >>"
        compressed = zlib.compress(objects)
        stream = (
            b"2 0 obj\n"
            b"<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
            + str(len(compressed)).encode("ascii")
            + b" >>\nstream\n"
            + compressed
            + b"\nendstream\nendobj"
        )
        with self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
            self.inspect(pdf(stream))

    def test_indirect_object_stream_length_is_resolved(self) -> None:
        objects = b"1 0 << /S /Java#53cript /JS (app.alert) >>"
        compressed = zlib.compress(objects)
        stream = (
            b"2 0 obj\n"
            b"<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode "
            b"/Length 3 0 R >>\nstream\n"
            + compressed
            + b"\nendstream\nendobj\n"
            + b"3 0 obj\n"
            + str(len(compressed)).encode("ascii")
            + b"\nendobj"
        )
        with self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
            self.inspect(pdf(stream))

    def test_unsupported_compressed_object_filter_fails_closed(self) -> None:
        stream = (
            b"2 0 obj\n"
            b"<< /Type /ObjStm /N 1 /First 4 /Filter /ASCII85Decode "
            b"/Length 4 >>\nstream\nnoop\nendstream\nendobj"
        )
        with self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
            self.inspect(pdf(stream))

    def test_indirect_object_stream_filter_fails_closed(self) -> None:
        stream = (
            b"2 0 obj\n"
            b"<< /Type /ObjStm /N 1 /First 4 /Filter 3 0 R "
            b"/Length 4 >>\nstream\nnoop\nendstream\nendobj\n"
            b"3 0 obj\n/FlateDecode\nendobj"
        )
        with self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
            self.inspect(pdf(stream))

    def test_object_stream_decode_limit_is_enforced(self) -> None:
        compressed = zlib.compress(b"1 0 " + b"A" * 64)
        stream = (
            b"2 0 obj\n<< /Type /ObjStm /N 1 /First 4 "
            b"/Filter /FlateDecode /Length "
            + str(len(compressed)).encode("ascii")
            + b" >>\nstream\n"
            + compressed
            + b"\nendstream\nendobj"
        )
        with (
            patch("lsdo_publications.pdf.MAX_DECODED_OBJECT_STREAM_BYTES", 32),
            self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"),
        ):
            self.inspect(pdf(stream))

    def test_encrypted(self) -> None:
        with self.assertRaisesRegex(PublicationError, "E_PDF_ENCRYPTED"):
            self.inspect(pdf(b"/Encrypt"))

    def test_escaped_encryption_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(PublicationError, "E_PDF_ENCRYPTED"):
            self.inspect(pdf(b"/Encr#79pt"))

    def test_trailing_polyglot_content(self) -> None:
        with self.assertRaisesRegex(PublicationError, "E_PDF_UNSAFE"):
            self.inspect(pdf(b"10.1000/example") + b"<script>alert(1)</script>")
