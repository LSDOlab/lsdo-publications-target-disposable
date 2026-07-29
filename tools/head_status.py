from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


GIT_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ALLOWED_STATES = {"pending", "success", "failure"}
CONTEXT = "authorization-envelope"


def event_target() -> tuple[str, str]:
    event = json.loads(
        Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8")
    )
    pull = event.get("pull_request", {})
    repository = os.environ["GITHUB_REPOSITORY"]
    base_repository = pull.get("base", {}).get("repo", {}).get("full_name", "")
    head_repository = pull.get("head", {}).get("repo", {}).get("full_name", "")
    head = pull.get("head", {}).get("sha", "")
    if (
        not REPOSITORY_RE.fullmatch(repository)
        or base_repository != repository
        or head_repository != repository
    ):
        raise ValueError(
            "E_TARGET_REPOSITORY: base and head must be in the protected target repository"
        )
    if not GIT_OID_RE.fullmatch(head):
        raise ValueError("E_TARGET_EVENT: invalid pull-request head")
    return repository, head


def publish_status(repository: str, head: str, state: str, token: str) -> None:
    if state not in ALLOWED_STATES:
        raise ValueError(f"E_TARGET_STATUS: unsupported state: {state}")
    if not token:
        raise ValueError("E_TARGET_STATUS: status token is absent")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    target_url = (
        f"{server}/{repository}/actions/runs/{run_id}"
        if run_id
        else f"{server}/{repository}/actions"
    )
    payload = {
        "state": state,
        "context": CONTEXT,
        "description": (
            "Trusted authorization validation is running"
            if state == "pending"
            else f"Trusted authorization validation {state}"
        ),
        "target_url": target_url,
    }
    path = (
        f"/repos/{repository}/statuses/"
        f"{urllib.parse.quote(head, safe='')}"
    )
    request = urllib.request.Request(
        "https://api.github.com" + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "lsdo-publications-target-status",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "api.github.com":
                raise ValueError("E_TARGET_STATUS: unexpected API redirect")
            if response.status != 201:
                raise ValueError(f"E_TARGET_STATUS: HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ValueError(
            f"E_TARGET_STATUS: HTTP {exc.code}: {detail}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ValueError(f"E_TARGET_STATUS: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: head_status.py pending|success|failure", file=sys.stderr)
        return 2
    try:
        repository, head = event_target()
        publish_status(
            repository,
            head,
            arguments[0],
            os.environ.get("TARGET_STATUS_TOKEN", ""),
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
