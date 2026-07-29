from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from tools import target_check


ROOT = Path(__file__).resolve().parents[1]
BASE = "a" * 40
HEAD = "b" * 40


class TrustedBaseWorkflowTests(unittest.TestCase):
    def test_workflow_executes_only_trusted_base_validator(self) -> None:
        workflow = (ROOT / ".github/workflows/validate-promotion.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request_target:", workflow)
        self.assertNotIn("\n  pull_request:\n", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", workflow)
        self.assertIn("path: trusted", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("path: candidate", workflow)
        self.assertIn("run: python3 trusted/tools/target_check.py", workflow)
        self.assertNotIn("run: python3 candidate/", workflow)

        secret_position = workflow.index("PROMOTION_AUTHORIZATION_KEY:")
        candidate_checkout_position = workflow.index(
            "Check out candidate bytes without executing candidate code"
        )
        trusted_run_position = workflow.index(
            "run: python3 trusted/tools/target_check.py"
        )
        self.assertLess(candidate_checkout_position, secret_position)
        self.assertLess(secret_position, trusted_run_position)

    def test_candidate_workflow_or_validator_change_is_rejected_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = ROOT
            candidate = root / "candidate"
            (candidate / ".promotion").mkdir(parents=True)
            (candidate / ".github/workflows").mkdir(parents=True)
            (candidate / "tools").mkdir()
            (candidate / "catalog").mkdir()

            marker = root / "candidate-code-executed"
            (candidate / "tools/target_check.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            (candidate / ".github/workflows/validate-promotion.yml").write_text(
                "run: echo candidate-workflow-ran\n",
                encoding="utf-8",
            )
            (candidate / "catalog/publications.bib").write_text(
                "@misc{fixture,\n  title = {Fixture},\n  year = {2028},\n}\n",
                encoding="utf-8",
            )
            envelope = {
                "files": [{"path": "catalog/publications.bib"}],
                "source": {
                    "repository": "LSDOlab/intake-disposable",
                    "pr": 1,
                    "head_sha": HEAD,
                },
            }
            (candidate / ".promotion/authorization.json").write_text(
                json.dumps(envelope),
                encoding="utf-8",
            )
            event = root / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "base": {"sha": BASE},
                            "head": {"sha": HEAD},
                        }
                    }
                ),
                encoding="utf-8",
            )

            changed = (
                b".github/workflows/validate-promotion.yml\0"
                b".promotion/authorization.json\0"
                b"catalog/publications.bib\0"
                b"tools/target_check.py\0"
            )

            def fake_git(checkout: Path, *args: str) -> bytes:
                if args == ("rev-parse", "HEAD"):
                    return (BASE if checkout == ROOT else HEAD).encode()
                if args[:3] == ("diff", "--name-only", "-z"):
                    return changed
                raise AssertionError((checkout, args))

            environment = {
                "PROMOTION_AUTHORIZATION_KEY": "x" * 32,
                "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": "LSDOlab/target-disposable",
                "TARGET_TRUSTED_ROOT": str(trusted),
                "TARGET_CANDIDATE_ROOT": str(candidate),
            }
            with patch.dict(os.environ, environment, clear=True), patch.object(
                target_check, "git", side_effect=fake_git
            ), patch.object(
                target_check, "verify_envelope"
            ), redirect_stderr(StringIO()) as stderr:
                self.assertEqual(2, target_check.main())
            self.assertIn("E_TARGET_FILE_SET", stderr.getvalue())
            self.assertFalse(marker.exists())

    def test_checkout_identity_must_match_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = ROOT
            candidate = root / "candidate"
            candidate.mkdir()
            event = root / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "base": {"sha": BASE},
                            "head": {"sha": HEAD},
                        }
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "PROMOTION_AUTHORIZATION_KEY": "x" * 32,
                "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": "LSDOlab/target-disposable",
                "TARGET_TRUSTED_ROOT": str(trusted),
                "TARGET_CANDIDATE_ROOT": str(candidate),
            }

            def fake_git(checkout: Path, *args: str) -> bytes:
                if args == ("rev-parse", "HEAD"):
                    return ("c" * 40).encode()
                raise AssertionError((checkout, args))

            with patch.dict(os.environ, environment, clear=True), patch.object(
                target_check, "git", side_effect=fake_git
            ), redirect_stderr(StringIO()) as stderr:
                self.assertEqual(2, target_check.main())
            self.assertIn("E_STALE_TARGET", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
