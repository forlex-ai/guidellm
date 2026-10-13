# Standalone stdlib CI command, deliberately outside the product package.
# ruff: noqa: INP001
"""TruffleHog gate: scan Git data only, fail closed, and never publish secret bytes."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, cast

UTC = timezone.utc
SHA = re.compile(r"[0-9a-f]{40}\Z")
EXCEPTION_FIELDS = {
    "id",
    "repository",
    "detector",
    "path",
    "commit",
    "fingerprint",
    "owner",
    "rationale",
    "expires",
}
CHECK_NAME = "TruffleHog secret scan"
SOURCE_ASSOCIATION_LIMIT = 1_000_000
GIT_CHANGE_FIELD_COUNT = 5
GIT_OBJECT_HEADER_FIELD_COUNT = 3
REPORT_FINDING_LIMIT = 100
ACTIONS_CHECK_APP_ID = 15368


class SecretScanRefusalError(ValueError):
    """A policy or source gap refuses secret-scan admission."""


def strict_json(text):
    """Parse JSON without accepting duplicate keys.

    Returns:
    The decoded JSON value, with unique object keys.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SecretScanRefusalError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SecretScanRefusalError("invalid JSON") from error


def read_policy(path):
    """Require an exact, owned and time-bounded exception policy.

    Returns:
    Validated exact exception records.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    policy = strict_json(Path(path).read_text())
    if (
        not isinstance(policy, dict)
        or set(policy) != {"version", "exceptions"}
        or policy["version"] != 1
    ):
        raise SecretScanRefusalError("unsupported exception policy")
    rows = policy["exceptions"]
    if not isinstance(rows, list):
        raise SecretScanRefusalError("invalid exception list")
    ids = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != EXCEPTION_FIELDS:
            raise SecretScanRefusalError("incomplete exception")
        if any(
            not isinstance(value, str) or not value.strip() for value in row.values()
        ):
            raise SecretScanRefusalError("invalid exception field")
        if row["id"] in ids or not SHA.fullmatch(row["commit"]):
            raise SecretScanRefusalError("invalid exception identity")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", row["fingerprint"])
            or row["owner"] != "danielbichuetti"
        ):
            raise SecretScanRefusalError("unreviewed exception authority")
        if not row["repository"].startswith("forlex-ai/") or any(
            x in row["path"] for x in ("*", "?", "\n", "\r")
        ):
            raise SecretScanRefusalError("broad exception refused")
        date.fromisoformat(row["expires"])
        ids.add(row["id"])
    return rows


def classify(row, exceptions, repository):
    """Expose only finding locations and the narrow exception disposition.

    Returns:
    Redacted detection location and exception disposition.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    if not isinstance(row, dict):
        raise SecretScanRefusalError("invalid detection")
    try:
        source = row["SourceMetadata"]["Data"]["Git"]
        detector, raw, verified = (
            row["DetectorName"],
            row.get("RawV2") or row["Raw"],
            row["Verified"],
        )
        commit, path, line = source["commit"], source["file"], source["line"]
    except (KeyError, TypeError) as error:
        raise SecretScanRefusalError("incomplete detection") from error
    if not isinstance(verified, bool) or not isinstance(raw, str) or not raw:
        raise SecretScanRefusalError("invalid detection data")
    if (
        not isinstance(detector, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", detector)
        or not isinstance(path, str)
        or not path
    ):
        raise SecretScanRefusalError("missing detection location")
    if (
        not isinstance(commit, str)
        or not SHA.fullmatch(commit)
        or not isinstance(line, int)
        or line < 1
    ):
        raise SecretScanRefusalError("invalid Git location")
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()
    exception_id = None
    kind = source.get("kind", "file_content")
    if kind not in {"file_content", "filename", "commit_metadata"}:
        raise SecretScanRefusalError("unknown source kind")
    if not verified and kind == "file_content":
        for rule in exceptions:
            if (
                rule["repository"],
                rule["detector"],
                rule["path"],
                rule["commit"],
                rule["fingerprint"],
            ) == (
                repository,
                detector,
                path,
                commit,
                fingerprint,
            ) and date.fromisoformat(rule["expires"]) >= datetime.now(UTC).date():
                exception_id = rule["id"]
                break
    # Deliberately discard Raw, RawV2, Redacted, email and verification error text.
    return {
        "detector": detector,
        "commit": commit,
        "path_digest": hashlib.sha256(os.fsencode(path)).hexdigest(),
        "source_kind": kind,
        "line": line,
        "verification": "verified"
        if verified
        else "unknown"
        if row.get("VerificationError")
        else "unverified",
        "suppressed": exception_id is not None,
        "exception_id": exception_id,
    }


def git_range(repo, head, base):
    """Validate complete source history and retain every introduced commit.

    Returns:
    The effective merge base and all introduced commit SHAs.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    if not SHA.fullmatch(head) or (base is not None and not SHA.fullmatch(base)):
        raise SecretScanRefusalError("invalid source SHA")

    def git(*args):
        result = subprocess.run(  # noqa: S603
            ["git", "--no-replace-objects", "-C", str(repo), *args],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GIT_NO_LAZY_FETCH": "1",
                "LANG": "C.UTF-8",
            },
        )
        if result.returncode:
            raise SecretScanRefusalError("Git source unavailable")
        return result.stdout.strip()

    if git("rev-parse", "--is-shallow-repository") != "false":
        raise SecretScanRefusalError("shallow history refused")
    if git("rev-parse", head + "^{commit}") != head:
        raise SecretScanRefusalError("source identity mismatch")
    effective = git("merge-base", base, head) if base else None
    commits = git(
        "rev-list", head, *(["^" + effective] if effective else [])
    ).splitlines()
    return effective, commits


def materialize(repo, commits, directory, deadline):  # noqa: C901, PLR0912, PLR0915
    """Enumerate every changed Git blob and materialize inert, deduplicated
    data.

    Returns:
    An exact generated-path index retaining every immutable source
    association.

    Raises:
    SecretScanRefusalError: Missing objects, unsupported modes, or resource
    bounds.
    """
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_NO_LAZY_FETCH": "1",
        "LANG": "C.UTF-8",
    }
    command = ["git", "--no-replace-objects", "-C", str(repo)]

    def git(*args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecretScanRefusalError("source enumeration timeout")
        result = subprocess.run(  # noqa: S603
            command + list(args),
            capture_output=True,
            timeout=min(60, remaining),
            env=environment,
            check=False,
        )
        if result.returncode or len(result.stdout) > 256 * 1024 * 1024:
            raise SecretScanRefusalError("incomplete Git object enumeration")
        return result.stdout

    payloads: dict[Any, Any] = {}
    associations = 0

    def add(key, source):
        nonlocal associations
        associations += 1
        if associations > SOURCE_ASSOCIATION_LIMIT:
            raise SecretScanRefusalError("source association limit exceeded")
        if key not in payloads:
            path = directory / ("payload-" + str(len(payloads)))
            payloads[key] = (path, [])
        payloads[key][1].append(source)

    for commit in commits:
        parents = (
            git("rev-list", "--parents", "-n", "1", commit).decode("ascii").split()
        )
        if (
            not parents
            or parents[0] != commit
            or any(not SHA.fullmatch(value) for value in parents)
        ):
            raise SecretScanRefusalError("invalid commit identity")
        add(
            ("commit", commit),
            {"commit": commit, "file": "@commit-metadata", "kind": "commit_metadata"},
        )
        # Comparing each merge to its first parent covers newly resolved content.
        args = ["diff-tree", "--no-renames", "--no-commit-id", "--raw", "-z", "-r"]
        changes = git(
            *args, *([parents[1], commit] if len(parents) > 1 else ["--root", commit])
        ).split(b"\0")
        if changes[-1] != b"" or (len(changes) - 1) % 2:
            raise SecretScanRefusalError("incomplete changed-object stream")
        for offset in range(0, len(changes) - 1, 2):
            entry, raw_path = changes[offset], changes[offset + 1]
            fields = entry.split()
            if (
                len(fields) != GIT_CHANGE_FIELD_COUNT
                or not fields[0].startswith(b":")
                or not raw_path
            ):
                raise SecretScanRefusalError("invalid changed-object entry")
            _, mode, _, object_id, status = fields
            if status == b"D":
                continue
            if status not in {b"A", b"M", b"T"} or not SHA.fullmatch(
                object_id.decode("ascii")
            ):
                raise SecretScanRefusalError("unsupported changed-object identity")
            source_path = os.fsdecode(raw_path)
            source = {"commit": commit, "file": source_path, "kind": "file_content"}
            add(("filename", raw_path), {**source, "kind": "filename"})
            if mode == b"160000":
                # Child content belongs to its own repository's independently accepted
                # gate.
                continue
            if mode not in {b"100644", b"100755", b"120000"}:
                raise SecretScanRefusalError("unsupported Git object mode")
            add(("blob", object_id.decode("ascii")), source)

    objects = [(key, value) for key, value in payloads.items() if key[0] != "filename"]
    request = directory.parent / "git-object-request"
    request.write_bytes(b"".join(key[1].encode("ascii") + b"\n" for key, _ in objects))
    total = 0
    with (
        request.open("rb") as stdin,
        (directory.parent / "git-object-errors").open("wb") as stderr,
    ):
        process = subprocess.Popen(  # noqa: S603
            command + ["cat-file", "--batch"],
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=stderr,
            env=environment,
        )
        try:
            for (kind, object_id), (path, _) in objects:
                header = cast("BinaryIO", process.stdout).readline(200)
                fields = header.rstrip(b"\n").split()
                if (
                    len(fields) != GIT_OBJECT_HEADER_FIELD_COUNT
                    or fields[:2] != [object_id.encode("ascii"), kind.encode("ascii")]
                    or not fields[2].isdigit()
                ):
                    raise SecretScanRefusalError("missing or mismatched Git object")
                size = int(fields[2])
                total += size
                if size > 256 * 1024 * 1024 or total > 8 * 1024 * 1024 * 1024:
                    raise SecretScanRefusalError(
                        "source materialization limit exceeded"
                    )
                with path.open("wb") as output:
                    path.chmod(0o600)
                    remaining = size
                    while remaining:
                        if time.monotonic() >= deadline:
                            raise SecretScanRefusalError("source extraction timeout")
                        data = cast("BinaryIO", process.stdout).read(
                            min(1024 * 1024, remaining)
                        )
                        if not data:
                            raise SecretScanRefusalError("truncated Git object")
                        output.write(data)
                        remaining -= len(data)
                if cast("BinaryIO", process.stdout).read(1) != b"\n":
                    raise SecretScanRefusalError("invalid Git object separator")
            if (
                cast("BinaryIO", process.stdout).read(1)
                or process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0
            ):
                raise SecretScanRefusalError("incomplete Git object extraction")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            cast("BinaryIO", process.stdout).close()
    for (kind, data), (path, _) in payloads.items():
        if kind == "filename":
            path.write_bytes(data)
            path.chmod(0o600)
    return {str(path): sources for path, sources in payloads.values()}


def validate_diagnostics(path):
    """Refuse source/detector errors even when the native scanner exits zero.

    Raises:
        SecretScanRefusalError: Malformed, unknown, warning, or error diagnostics.
    """
    if path.stat().st_size > 16 * 1024 * 1024:
        raise SecretScanRefusalError("scanner diagnostic limit exceeded")
    with path.open() as stream:
        for line in stream:
            row = strict_json(line)
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("level"), str)
                or not re.fullmatch(r"(?:info(?:-[0-5])?|debug)", row["level"])
            ):
                raise SecretScanRefusalError("scanner reported incomplete detection")


def scan(repo, head, base, scanner, policy, repository, timeout):  # noqa: C901, PLR0915, PLR0917
    """Run the pinned scanner without credentials and redact its complete
    output.

    Returns:
    A redacted pass, failure or error report.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    report = {
        "version": 1,
        "repository": repository,
        "head": head,
        "base": base,
        "result": "error",
        "findings": [],
    }
    try:
        exceptions = read_policy(policy)
        effective, commits = git_range(repo, head, base)
        report.update({"effective_base": effective, "commit_count": len(commits)})
        # No candidate scripts, hooks, dependencies, provider verification or injected
        # credentials.
        command = [
            str(Path(scanner).resolve()),
            "filesystem",
            "--json",
            "--no-update",
            "--no-verification",
            "--no-ignore-tag",
            "--fail-on-scan-errors",
            "--results=verified,unknown,unverified,filtered_unverified",
            "--concurrency=4",
        ]
        with tempfile.TemporaryDirectory(
            prefix="trufflehog-private-"
        ) as directory_name:
            directory = Path(directory_name)
            deadline = time.monotonic() + timeout
            payload_directory = directory / "payloads"
            payload_directory.mkdir(mode=0o700)
            index = materialize(repo, commits, payload_directory, deadline)
            report["payload_count"] = len(index)
            command.append(str(payload_directory))
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(directory),
                "LANG": "C.UTF-8",
            }
            output, errors = directory / "raw.jsonl", directory / "stderr"
            with output.open("wb") as stdout, errors.open("wb") as stderr:
                output.chmod(0o600)
                errors.chmod(0o600)
                process = subprocess.Popen(  # noqa: S603
                    command,
                    stdout=stdout,
                    stderr=stderr,
                    env=environment,
                    start_new_session=True,
                )
                try:
                    code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise SecretScanRefusalError("scanner timeout") from None
            if code != 0:
                raise SecretScanRefusalError("scanner execution failed")
            validate_diagnostics(errors)
            if output.stat().st_size > 256 * 1024 * 1024:
                raise SecretScanRefusalError("scanner output limit exceeded")
            blocked, suppressed = 0, 0
            with output.open() as stream:
                for line in stream:
                    if len(line) > 8 * 1024 * 1024 or not line.strip():
                        raise SecretScanRefusalError("invalid scanner stream")
                    row = strict_json(line)
                    try:
                        location = row["SourceMetadata"]["Data"]["Filesystem"]
                        sources = index[location["file"]]
                        number = location["line"]
                    except (KeyError, TypeError) as error:
                        raise SecretScanRefusalError(
                            "finding not bound to enumerated source"
                        ) from error
                    for source in sources:
                        normalized = {
                            **row,
                            "SourceMetadata": {
                                "Data": {"Git": {**source, "line": number}}
                            },
                        }
                        finding = classify(normalized, exceptions, repository)
                        if finding["suppressed"]:
                            suppressed += 1
                        else:
                            blocked += 1
                        if len(report["findings"]) < REPORT_FINDING_LIMIT:
                            report["findings"].append(finding)
            report.update(
                {
                    "blocked": blocked,
                    "suppressed": suppressed,
                    "result": "fail" if blocked else "pass",
                }
            )
    except (ValueError, OSError, subprocess.SubprocessError):
        report["error"] = (
            "Source, policy, scanner execution or compl"
            "ete output validation failed; no success w"
            "as inferred."
        )
    return report


def github(repository, suffix, *, method="GET", body=None):
    """Use scoped GitHub APIs without exposing tokens or response bodies.

    Returns:
    The authenticated JSON response.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    if not re.fullmatch(r"forlex-ai/[A-Za-z0-9_.-]+", repository):
        raise SecretScanRefusalError("unexpected repository")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise SecretScanRefusalError("GitHub authentication unavailable")
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        "https://api.github.com/repos/" + repository + "/" + suffix,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return strict_json(response.read().decode())
    except (urllib.error.URLError, ValueError, OSError) as error:
        raise SecretScanRefusalError("GitHub request failed") from error


def context(event, kind, repository, pr_number=0):
    """Bind authenticated live source facts before creating the check.

    Returns:
    The current source context and newly created check identity.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    if kind not in {"pull_request_target", "push", "schedule", "workflow_dispatch"}:
        raise SecretScanRefusalError("unsupported workflow event")
    if event.get("repository", {}).get("full_name") != repository:
        raise SecretScanRefusalError("event repository mismatch")
    number = event.get("number") if kind == "pull_request_target" else pr_number
    if number:
        if not isinstance(number, int) or number < 1:
            raise SecretScanRefusalError("invalid PR")
        pr = github(repository, "pulls/" + str(number))
        if pr["state"] != "open" or pr["base"]["repo"]["full_name"] != repository:
            raise SecretScanRefusalError("closed or foreign PR")
        head, base = pr["head"]["sha"], pr["base"]["sha"]
        if kind == "pull_request_target" and (head, base) != (
            event["pull_request"]["head"]["sha"],
            event["pull_request"]["base"]["sha"],
        ):
            raise SecretScanRefusalError("stale PR event")
    else:
        head = os.environ["GITHUB_SHA"]
        base = event.get("before") if kind == "push" else None
        if base == "0" * 40:
            base = None
    if not SHA.fullmatch(head) or (base is not None and not SHA.fullmatch(base)):
        raise SecretScanRefusalError("invalid source identity")
    result = {
        "repository": repository,
        "pr": number or None,
        "head": head,
        "base": base,
    }
    created = github(
        repository,
        "check-runs",
        method="POST",
        body={"name": CHECK_NAME, "head_sha": head, "status": "in_progress"},
    )
    result["check_id"] = created["id"]
    return result


def publish(source, report):
    """Publish success only for the unchanged source and owned check.

    Returns:
    The completed GitHub check response.

    Raises:
    SecretScanRefusalError: Invalid or incomplete evidence; scan captures
    this as an error report.
    """
    repository = source["repository"]
    if source["pr"]:
        current = github(repository, "pulls/" + str(source["pr"]))
        if current["state"] != "open" or (
            current["head"]["sha"],
            current["base"]["sha"],
        ) != (
            source["head"],
            source["base"],
        ):
            raise SecretScanRefusalError("PR context changed; a fresh scan is required")
    counts = (
        report.get("blocked"),
        report.get("suppressed"),
        report.get("commit_count"),
    )
    complete = all(type(value) is int and value >= 0 for value in counts)
    success = (
        complete
        and report.get("blocked") == 0
        and report.get("version") == 1
        and not report.get("error")
        and report.get("result") == "pass"
        and (report.get("head"), report.get("base"), report.get("repository"))
        == (source["head"], source["base"], repository)
    )
    check = github(repository, "check-runs/" + str(source["check_id"]))
    if (
        check["head_sha"] != source["head"]
        or check["name"] != CHECK_NAME
        or check["app"]["id"] != ACTIONS_CHECK_APP_ID
    ):
        raise SecretScanRefusalError("check identity mismatch")
    summary = (
        f"Result: {'pass' if success else 'failure'}. "
        f"Scanned commits: {report.get('commit_count', 'unavailable')}. "
        f"Blocking detections: {report.get('blocked', 'unavailable')}. "
        f"Exact fixture exceptions: {report.get('suppressed', 0)}. "
        "Raw secrets and verification responses are never published."
    )
    return github(
        repository,
        "check-runs/" + str(source["check_id"]),
        method="PATCH",
        body={
            "status": "completed",
            "conclusion": "success" if success else "failure",
            "output": {"title": CHECK_NAME, "summary": summary},
        },
    )


def main():
    """Execute one gate stage and fail closed on incomplete evidence.

    Returns:
        Zero only for a successfully completed gate stage.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("context")
    prepare.add_argument("--event", type=Path, required=True)
    prepare.add_argument("--kind", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--pr", type=int, default=0)
    prepare.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("scan")
    run.add_argument("--context", type=Path, required=True)
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--scanner", type=Path, required=True)
    run.add_argument("--policy", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout", type=int, default=1200)
    finish = sub.add_parser("publish")
    finish.add_argument("--context", type=Path, required=True)
    finish.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "context":
            result = context(
                strict_json(args.event.read_text()), args.kind, args.repository, args.pr
            )
            args.output.write_text(json.dumps(result) + "\n")
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write("head=" + result["head"] + "\n")
        elif args.command == "scan":
            source = strict_json(args.context.read_text())
            report = scan(
                args.repo,
                source["head"],
                source["base"],
                args.scanner,
                args.policy,
                source["repository"],
                args.timeout,
            )
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            return 0 if report["result"] == "pass" else 1
        else:
            source = strict_json(args.context.read_text())
            report = (
                strict_json(args.report.read_text())
                if args.report.exists()
                else {"result": "error"}
            )
            result = publish(source, report)
            return 0 if result["conclusion"] == "success" else 1
    except (KeyError, ValueError, OSError, TypeError):
        print(  # noqa: T201
            "Secret gate refused incomplete or changed "
            "context; no secret bytes are included."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
