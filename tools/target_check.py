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

from lsdo_publications.envelope import verify_target_tree  # noqa: E402
from lsdo_publications.errors import PublicationError  # noqa: E402
from lsdo_publications.bibtex import load_bibtex, validate_entries  # noqa: E402
from lsdo_publications.pdf import inspect_pdf  # noqa: E402
from lsdo_publications.rights import validate_artifacts  # noqa: E402


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def main() -> int:
    key = os.environ.get("PROMOTION_AUTHORIZATION_KEY")
    if not key:
        print("E_AUTHORIZATION_KEY: target secret is absent", file=sys.stderr)
        return 2
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    pull = event.get("pull_request", {})
    base = pull.get("base", {}).get("sha", "")
    head = pull.get("head", {}).get("sha", "")
    if not base or not head:
        print("E_TARGET_EVENT: pull request SHAs are absent", file=sys.stderr)
        return 2
    envelope_path = ROOT / ".promotion" / "authorization.json"
    try:
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        changed = {
            item.decode("utf-8")
            for item in git("diff", "--name-only", "-z", base, head).split(b"\0")
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
                source = ROOT / relative
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
                target_repository=os.environ["GITHUB_REPOSITORY"],
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
