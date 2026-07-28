from __future__ import annotations

import re
import tomllib
from pathlib import Path

from .bibtex import load_bibtex
from .util import sha256_file

ALLOWED_KINDS = {
    "preprint", "submitted-manuscript", "accepted-manuscript",
    "technical-report", "supplement", "publisher-version",
}
MAX_BYTES = 25 * 1024 * 1024
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _has_symlink_component(root: Path, path: Path) -> bool:
    current = path
    while current != root:
        if current.is_symlink():
            return True
        current = current.parent
    return root.is_symlink()


def public_artifacts(root: Path) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    manifests = root / "catalog" / "artifacts"
    for path in sorted(manifests.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        approved = [
            artifact
            for artifact in data.get("artifacts", [])
            if artifact.get("public") is True
            and artifact.get("rights_status") == "approved"
        ]
        if approved:
            primary = data.get("primary_artifact")
            approved.sort(key=lambda artifact: (artifact.get("id") != primary, artifact["path"]))
            result[path.stem] = approved
    return result


def validate_artifacts(root: Path) -> list[str]:
    errors: list[str] = []
    manifests = root / "catalog" / "artifacts"
    pdf_root = root / "pdf"
    catalog_path = root / "catalog" / "publications.bib"
    catalog_keys = (
        {entry.key for entry in load_bibtex(catalog_path)}
        if catalog_path.is_file()
        else set()
    )
    described: set[Path] = set()
    digests: set[str] = set()
    for path in sorted(manifests.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        key = path.stem
        if data.get("schema_version") != 1:
            errors.append(f"E_ARTIFACT_SCHEMA: {path}")
        if data.get("publication_key") != key:
            errors.append(f"E_ARTIFACT_KEY: {path}")
        if key not in catalog_keys:
            errors.append(f"E_ARTIFACT_PUBLICATION: {key}")
        artifact_ids: set[str] = set()
        public_ids: set[str] = set()
        for artifact in data.get("artifacts", []):
            raw_path = artifact.get("path", "")
            relative = Path(raw_path)
            kind = artifact.get("kind")
            digest = artifact.get("sha256", "")
            artifact_id = artifact.get("id", "")
            expected_path = (
                f"pdf/{key}/{key}--{kind}--{digest[:12]}.pdf"
                if kind in ALLOWED_KINDS and DIGEST_RE.fullmatch(digest)
                else None
            )
            if (
                not raw_path
                or relative.is_absolute()
                or ".." in relative.parts
                or "\\" in raw_path
                or relative.as_posix() != raw_path
                or raw_path != expected_path
            ):
                errors.append(f"E_ARTIFACT_PATH: {raw_path}")
                continue
            if relative in described:
                errors.append(f"E_DUPLICATE_ARTIFACT_PATH: {relative}")
            described.add(relative)
            if not DIGEST_RE.fullmatch(digest):
                errors.append(f"E_ARTIFACT_DIGEST_FORMAT: {relative}")
            if digest in digests:
                errors.append(f"E_DUPLICATE_ARTIFACT: {digest}")
            digests.add(digest)
            if artifact_id != digest[:12] or artifact_id in artifact_ids:
                errors.append(f"E_ARTIFACT_ID: {relative}")
            artifact_ids.add(artifact_id)
            full = root / relative
            if _has_symlink_component(root, full):
                errors.append(f"E_ARTIFACT_SYMLINK: {relative}")
                continue
            if not full.is_file():
                errors.append(f"E_ARTIFACT_MISSING: {relative}")
                continue
            if sha256_file(full) != digest or full.stat().st_size != artifact.get("bytes"):
                errors.append(f"E_ARTIFACT_DIGEST: {relative}")
            if full.stat().st_size > MAX_BYTES:
                errors.append(f"E_PDF_TOO_LARGE: {relative}")
            if artifact.get("media_type") != "application/pdf":
                errors.append(f"E_ARTIFACT_MEDIA_TYPE: {relative}")
            if kind not in ALLOWED_KINDS:
                errors.append(f"E_ARTIFACT_KIND: {relative}")
            if artifact.get("public") is True:
                public_ids.add(artifact_id)
                required = ("rights_status", "rights_basis", "rights_reference", "approved_by", "approved_at")
                if artifact.get("rights_status") != "approved" or any(not artifact.get(x) for x in required[1:]):
                    errors.append(f"E_RIGHTS_UNREVIEWED: {relative}")
                if kind == "publisher-version" and not artifact.get("publisher_exception_approval"):
                    errors.append(f"E_PUBLISHER_PDF: {relative}")
            elif artifact.get("public") not in (False, None):
                errors.append(f"E_ARTIFACT_PUBLIC_FLAG: {relative}")
        primary = data.get("primary_artifact")
        if primary and primary not in public_ids:
            errors.append(f"E_ARTIFACT_PRIMARY: {path}")
    actual = {
        path.relative_to(root)
        for path in pdf_root.rglob("*.pdf")
    } if pdf_root.exists() else set()
    for path in sorted(actual - described):
        errors.append(f"E_UNMANIFESTED_PDF: {path}")
    for path in root.rglob("*.pdf"):
        relative = path.relative_to(root)
        if not str(relative).startswith(("pdf/", "tests/fixtures/pdf/", "processed/", "incoming/")):
            errors.append(f"E_PDF_SCOPE: {relative}")
    return errors
