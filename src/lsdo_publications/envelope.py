from __future__ import annotations

import re
import hashlib
import hmac
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PublicationError
from .util import sha256_bytes, sha256_file, stable_json

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_CATALOG_PATHS = {
    "catalog/publications.bib",
    "catalog/registry.toml",
    "catalog/relations.json",
}


def _fail(code: str, message: str) -> None:
    raise PublicationError(code, message)


def _canonical_payload(envelope: dict[str, Any]) -> bytes:
    payload = deepcopy(envelope)
    payload.pop("envelope_sha256", None)
    payload.pop("authorization_mac", None)
    return stable_json(payload).encode("utf-8")


def _allowed_path(raw: str) -> bool:
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in raw
        or path.as_posix() != raw
        or raw.startswith(".github/")
    ):
        return False
    if raw in SAFE_CATALOG_PATHS:
        return True
    if raw.startswith("catalog/artifacts/") and raw.endswith(".toml"):
        return len(path.parts) == 3
    if raw.startswith("pdf/") and raw.endswith(".pdf"):
        return len(path.parts) == 3
    return False


def create_envelope(
    *,
    source_repository: str,
    source_pr: int,
    source_head_sha: str,
    source_comment_id: int,
    actor: str,
    target_repository: str,
    target_base_sha: str,
    pdf_sha256: str | None,
    pdf_bytes: int,
    artifact_kind: str | None,
    proposal_sha256: str,
    metadata_approval: dict[str, str],
    rights_approval: dict[str, str] | None,
    files: list[dict[str, Any]],
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    seed = {
        "source_repository": source_repository,
        "source_pr": source_pr,
        "source_head_sha": source_head_sha,
        "target_repository": target_repository,
        "target_base_sha": target_base_sha,
        "pdf_sha256": pdf_sha256,
        "proposal_sha256": proposal_sha256,
    }
    envelope: dict[str, Any] = {
        "schema_version": 1,
        "idempotency_key": sha256_bytes(stable_json(seed).encode("utf-8")),
        "source": {
            "repository": source_repository,
            "pr": source_pr,
            "head_sha": source_head_sha,
            "comment_id": source_comment_id,
            "actor": actor,
        },
        "target": {
            "repository": target_repository,
            "base_sha": target_base_sha,
        },
        "proposal": {
            "sha256": proposal_sha256,
            "metadata_only": pdf_sha256 is None,
            "pdf_sha256": pdf_sha256,
            "pdf_bytes": pdf_bytes,
            "artifact_kind": artifact_kind,
        },
        "approvals": {
            "metadata": metadata_approval,
            "rights": rights_approval,
        },
        "files": sorted(files, key=lambda item: item["path"]),
    }
    envelope["envelope_sha256"] = sha256_bytes(_canonical_payload(envelope))
    if signing_key is not None:
        if len(signing_key) < 32:
            _fail("E_AUTHORIZATION_KEY", "authorization key must contain at least 32 bytes")
        envelope["authorization_mac"] = hmac.new(
            signing_key,
            envelope["envelope_sha256"].encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
    verify_envelope(envelope)
    return envelope


def verify_envelope(envelope: dict[str, Any], signing_key: bytes | None = None) -> None:
    if envelope.get("schema_version") != 1:
        _fail("E_ENVELOPE_SCHEMA", "unsupported authorization-envelope schema")
    expected = sha256_bytes(_canonical_payload(envelope))
    if envelope.get("envelope_sha256") != expected:
        _fail("E_ENVELOPE_DIGEST", "authorization envelope was modified")
    if signing_key is not None:
        if len(signing_key) < 32:
            _fail("E_AUTHORIZATION_KEY", "authorization key must contain at least 32 bytes")
        expected_mac = hmac.new(
            signing_key,
            expected.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(envelope.get("authorization_mac", "")), expected_mac):
            _fail("E_AUTHORIZATION_MAC", "envelope was not signed by the controller")
    if not DIGEST_RE.fullmatch(str(envelope.get("idempotency_key", ""))):
        _fail("E_IDEMPOTENCY_KEY", "invalid transaction idempotency key")
    source = envelope.get("source", {})
    target = envelope.get("target", {})
    proposal = envelope.get("proposal", {})
    approvals = envelope.get("approvals", {})
    for repository in (source.get("repository"), target.get("repository")):
        if not REPOSITORY_RE.fullmatch(str(repository or "")):
            _fail("E_ENVELOPE_REPOSITORY", "invalid repository identity")
    if not isinstance(source.get("pr"), int) or source["pr"] < 1:
        _fail("E_ENVELOPE_SOURCE", "invalid source pull request")
    if not isinstance(source.get("comment_id"), int) or source["comment_id"] < 1:
        _fail("E_ENVELOPE_SOURCE", "invalid authorization comment")
    for name, value in (
        ("source head", source.get("head_sha")),
        ("target base", target.get("base_sha")),
        ("proposal", proposal.get("sha256")),
    ):
        if not DIGEST_RE.fullmatch(str(value or "")):
            _fail("E_ENVELOPE_DIGEST", f"invalid {name} digest")
    metadata = approvals.get("metadata") or {}
    if (
        metadata.get("actor") != source.get("actor")
        or metadata.get("proposal_sha256") != proposal.get("sha256")
        or not metadata.get("approved_at")
    ):
        _fail("E_METADATA_APPROVAL", "metadata approval does not bind this proposal")
    metadata_only = proposal.get("metadata_only")
    pdf_digest = proposal.get("pdf_sha256")
    pdf_bytes = proposal.get("pdf_bytes")
    rights = approvals.get("rights")
    if metadata_only is True:
        if pdf_digest is not None or pdf_bytes != 0 or rights is not None:
            _fail("E_METADATA_ONLY", "metadata-only proposal contains PDF state")
    elif metadata_only is False:
        if (
            not DIGEST_RE.fullmatch(str(pdf_digest or ""))
            or not isinstance(pdf_bytes, int)
            or pdf_bytes < 1
            or pdf_bytes > 25 * 1024 * 1024
        ):
            _fail("E_PDF_APPROVAL", "invalid proposed PDF")
        if (
            not isinstance(rights, dict)
            or rights.get("actor") != source.get("actor")
            or rights.get("pdf_sha256") != pdf_digest
            or rights.get("kind") != proposal.get("artifact_kind")
            or not rights.get("basis")
            or not rights.get("reference")
            or not rights.get("approved_at")
        ):
            _fail("E_RIGHTS_APPROVAL", "rights approval does not bind this PDF")
        if proposal.get("artifact_kind") in {"publisher-version", "unknown", None}:
            _fail("E_RIGHTS_KIND", "publisher or unknown PDF is not rehearsal-approved")
    else:
        _fail("E_METADATA_ONLY", "metadata_only must be boolean")
    files = envelope.get("files")
    if not isinstance(files, list) or not files:
        _fail("E_ENVELOPE_FILES", "authorized file set is empty")
    seen: set[str] = set()
    for item in files:
        raw = item.get("path", "") if isinstance(item, dict) else ""
        if not _allowed_path(raw) or raw in seen:
            _fail("E_ENVELOPE_PATH", f"unauthorized or duplicate path: {raw}")
        seen.add(raw)
        if (
            not DIGEST_RE.fullmatch(str(item.get("sha256", "")))
            or not isinstance(item.get("bytes"), int)
            or item["bytes"] < 0
        ):
            _fail("E_ENVELOPE_FILE", f"invalid authorized file: {raw}")
    if "catalog/publications.bib" not in seen:
        _fail("E_ENVELOPE_FILES", "canonical BibTeX catalog is required")


def verify_target_tree(
    envelope: dict[str, Any],
    root: Path,
    *,
    source_repository: str,
    source_pr: int,
    source_head_sha: str,
    target_repository: str,
    target_base_sha: str,
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    verify_envelope(envelope, signing_key)
    source = envelope["source"]
    target = envelope["target"]
    if (
        source["repository"] != source_repository
        or source["pr"] != source_pr
        or source["head_sha"] != source_head_sha
    ):
        _fail("E_STALE_SOURCE", "source pull request no longer matches authorization")
    if target["repository"] != target_repository:
        _fail("E_TARGET_REPOSITORY", "target repository does not match authorization")
    if target["base_sha"] != target_base_sha:
        _fail("E_STALE_TARGET", "target base no longer matches authorization")
    expected = {item["path"]: item for item in envelope["files"]}
    actual: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            _fail("E_TARGET_SYMLINK", f"target contains symlink: {path.relative_to(root)}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative in {".promotion/authorization.json"}:
                continue
            actual[relative] = path
    if set(actual) != set(expected):
        extra = sorted(set(actual) - set(expected))
        missing = sorted(set(expected) - set(actual))
        _fail("E_TARGET_FILE_SET", f"extra={extra}; missing={missing}")
    for relative, path in actual.items():
        item = expected[relative]
        if path.stat().st_size != item["bytes"] or sha256_file(path) != item["sha256"]:
            _fail("E_TARGET_BYTES", f"target bytes differ: {relative}")
    return {
        "authorized": True,
        "idempotency_key": envelope["idempotency_key"],
        "envelope_sha256": envelope["envelope_sha256"],
        "files": len(actual),
    }
