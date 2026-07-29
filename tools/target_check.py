from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lsdo_publications.envelope import verify_envelope, verify_target_tree  # noqa: E402
from lsdo_publications.errors import PublicationError  # noqa: E402
from lsdo_publications.bibtex import load_bibtex, validate_entries  # noqa: E402
from lsdo_publications.pdf import inspect_pdf  # noqa: E402
from lsdo_publications.rights import validate_artifacts  # noqa: E402


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def checkout_root(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        raise PublicationError("E_TARGET_CHECKOUT", f"{name} is absent")
    root = Path(raw)
    if root.is_symlink():
        raise PublicationError("E_TARGET_SYMLINK", f"{name} is a symlink")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise PublicationError("E_TARGET_CHECKOUT", f"{name} is not a checkout directory")
    return resolved


def checkout_commit(root: Path) -> str:
    return git(root, "rev-parse", "HEAD").decode("ascii").strip()


def main() -> int:
    key = os.environ.get("PROMOTION_AUTHORIZATION_KEY")
    if not key:
        print("E_AUTHORIZATION_KEY: target secret is absent", file=sys.stderr)
        return 2
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    pull = event.get("pull_request", {})
    base = pull.get("base", {}).get("sha", "")
    head = pull.get("head", {}).get("sha", "")
    repository = os.environ["GITHUB_REPOSITORY"]
    base_repository = pull.get("base", {}).get("repo", {}).get("full_name", "")
    head_repository = pull.get("head", {}).get("repo", {}).get("full_name", "")
    if not base or not head:
        print("E_TARGET_EVENT: pull request SHAs are absent", file=sys.stderr)
        return 2
    if base_repository != repository or head_repository != repository:
        print(
            "E_TARGET_REPOSITORY: base and head must be in the protected target repository",
            file=sys.stderr,
        )
        return 2
    try:
        trusted_root = checkout_root("TARGET_TRUSTED_ROOT")
        candidate_root = checkout_root("TARGET_CANDIDATE_ROOT")
        if trusted_root != ROOT.resolve():
            raise PublicationError(
                "E_TARGET_CHECKOUT",
                "validator code is not executing from the declared trusted checkout",
            )
        if trusted_root == candidate_root:
            raise PublicationError(
                "E_TARGET_CHECKOUT",
                "trusted and candidate checkouts must be distinct",
            )
        if checkout_commit(trusted_root) != base:
            raise PublicationError(
                "E_STALE_TARGET",
                "trusted validator is not checked out at the event base",
            )
        if checkout_commit(candidate_root) != head:
            raise PublicationError(
                "E_TARGET_CHECKOUT",
                "candidate checkout does not match the event head",
            )
        envelope_path = candidate_root / ".promotion" / "authorization.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        # Authenticate and path-check the envelope before using any candidate-
        # supplied path, even as an inert copy source.
        verify_envelope(envelope, key.encode("utf-8"))
        changed = {
            item.decode("utf-8")
            for item in git(
                candidate_root,
                "diff",
                "--name-only",
                "-z",
                base,
                head,
            ).split(b"\0")
            if item
        }
        expected = {item["path"] for item in envelope["files"]}
        if changed != expected | {".promotion/authorization.json"}:
            raise PublicationError(
                "E_TARGET_FILE_SET",
                f"changed={sorted(changed)}; authorized={sorted(expected)}",
            )
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            for relative in expected:
                source = candidate_root / relative
                if source.is_symlink() or not source.is_file():
                    raise PublicationError("E_TARGET_SYMLINK", relative)
                destination = tree / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            report = verify_target_tree(
                envelope,
                tree,
                source_repository=envelope["source"]["repository"],
                source_pr=envelope["source"]["pr"],
                source_head_sha=envelope["source"]["head_sha"],
                target_repository=repository,
                target_base_sha=base,
                signing_key=key.encode("utf-8"),
            )
            entries = load_bibtex(tree / "catalog" / "publications.bib")
            catalog_errors = validate_entries(entries)
            rights_errors = validate_artifacts(tree)
            if catalog_errors or rights_errors:
                raise PublicationError(
                    "E_TARGET_VALIDATION",
                    "; ".join(catalog_errors + rights_errors),
                )
            inspected = []
            for pdf in sorted(tree.glob("pdf/*/*.pdf")):
                pdf_report = inspect_pdf(pdf)
                if pdf_report["outcome"] != "identifiers-found":
                    raise PublicationError(
                        "E_TARGET_PDF",
                        f"{pdf.relative_to(tree)}: {pdf_report['outcome']}",
                    )
                inspected.append(pdf.relative_to(tree).as_posix())
            report["metadata_records"] = len(entries)
            report["pdfs_inspected"] = inspected
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, PublicationError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
