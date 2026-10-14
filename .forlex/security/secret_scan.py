# Standalone stdlib CI command, deliberately outside the product package.
# ruff: noqa: INP001
"""TruffleHog gate: scan Git data only, fail closed, and never publish secret bytes."""

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
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
    "proof",
}
CHECK_NAME = "TruffleHog secret scan"
HISTORY_CHECK_NAME = "TruffleHog history scan"
MERGE_POLL_ATTEMPTS = 5
MERGE_POLL_INTERVAL = 1
SOURCE_ASSOCIATION_LIMIT = 1_000_000
GIT_CHANGE_FIELD_COUNT = 5
TAG_REF_FIELD_COUNT = 2
TAG_NESTING_LIMIT = 64
TAG_HEADER_MINIMUM = 3
GIT_OBJECT_HEADER_FIELD_COUNT = 3
REPORT_FINDING_LIMIT = 100
ACTIONS_CHECK_APP_ID = 15368

OUTPUT_LIMIT = 256 * 1024 * 1024
DIAGNOSTIC_LIMIT = 16 * 1024 * 1024
POLICY_LIMIT = 1024 * 1024


class SecretScanRefusalError(ValueError):
    """A policy or source gap refuses secret-scan admission."""


def strict_json(text: Any) -> Any:
    """Parse JSON without accepting duplicate keys.

    Returns:
        The decoded JSON value, with unique object keys.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an
        error report.
    """

    def unique(pairs: Any) -> Any:
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


def read_policy(path: Any) -> Any:
    """Require an exact, owned and time-bounded exception policy.

    Returns:
        Validated exact exception records.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an
        error report.
    """
    with Path(path).open("rb") as stream:
        data = stream.read(POLICY_LIMIT + 1)
    if len(data) > POLICY_LIMIT:
        raise SecretScanRefusalError("exception policy size limit exceeded")
    return parse_policy(data.decode())


def parse_policy(text: Any) -> Any:  # noqa: C901
    """Validate policy data without accepting or executing candidate rules.

    Returns:
        Validated exact exception records.

    Raises:
        SecretScanRefusal: Invalid ownership, identity, source proof or schema.
    """
    policy = strict_json(text)
    if (
        not isinstance(policy, dict)
        or set(policy) != {"version", "exceptions"}
        or type(policy["version"]) is not int
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
        if (
            not re.fullmatch(r"forlex-ai/[A-Za-z0-9_.-]+", row["repository"])
            or any(x in row["path"] for x in ("*", "?", "\n", "\r", "\0"))
            or any(part in {"", ".", ".."} for part in row["path"].split("/"))
        ):
            raise SecretScanRefusalError("broad exception refused")
        proof = (
            "https://github.com/"
            + row["repository"]
            + "/blob/"
            + row["commit"]
            + "/"
            + urllib.parse.quote(row["path"], safe="/")
        )
        if row["proof"] != proof:
            raise SecretScanRefusalError(
                "exception source proof does not match immutable source"
            )
        if date.fromisoformat(row["expires"]).isoformat() != row["expires"]:
            raise SecretScanRefusalError("invalid exception expiry")
        ids.add(row["id"])
    return rows


def classify(row: Any, exceptions: Any, repository: Any) -> Any:
    """Expose only finding locations and the narrow exception disposition.

    Returns:
        Redacted detection location and exception disposition.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an
        error report.
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
    if kind not in {"file_content", "filename", "commit_metadata", "tag_metadata"}:
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


def git_range(  # noqa: C901
    repo: Any, head: Any, base: Any, *, full_if_nonforward: Any = False
) -> Any:
    """Validate complete source history and retain every introduced commit.

    Returns:
        The effective merge base and all introduced commit SHAs.

    Raises:
        SecretScanRefusalError: Invalid or incomplete evidence; scan captures this as
        an error report.
    """
    if not SHA.fullmatch(head) or (base is not None and not SHA.fullmatch(base)):
        raise SecretScanRefusalError("invalid source SHA")

    def git(*args: Any, ancestor_status: Any = False, missing_ok: Any = False) -> Any:
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
        if missing_ok and result.returncode == 1:
            return None
        if ancestor_status and result.returncode in {0, 1}:
            return result.returncode == 0
        if result.returncode:
            raise SecretScanRefusalError("Git source unavailable")
        return result.stdout.strip()

    if git("rev-parse", "--is-shallow-repository") != "false":
        raise SecretScanRefusalError("shallow history refused")
    if git("rev-parse", head + "^{commit}") != head:
        raise SecretScanRefusalError("source identity mismatch")
    resolved_base = None
    if base:
        resolved_base = git(
            "rev-parse",
            "--verify",
            "--quiet",
            base + "^{commit}",
            missing_ok=full_if_nonforward,
        )
        if resolved_base is not None and resolved_base != base:
            raise SecretScanRefusalError("base identity mismatch")
    if base and full_if_nonforward and resolved_base is None:
        effective = None
    elif base and full_if_nonforward:
        effective = (
            base
            if git("merge-base", "--is-ancestor", base, head, ancestor_status=True)
            else None
        )
    else:
        effective = git("merge-base", base, head) if base else None
    if base != head and effective == head:
        effective = None
    commits = git(
        "rev-list", head, *(["^" + effective] if effective else [])
    ).splitlines()
    return effective, commits


def materialize(  # noqa: C901, PLR0912, PLR0915
    repo: Any,
    commits: Any,
    directory: Any,
    deadline: Any,
    *,
    include_tags: Any = False,
    tag_object: Any = None,
    tag_head: Any = None,
) -> Any:
    """Enumerate every changed Git blob and materialize inert, deduplicated data.

    Returns:
        An exact generated-path index retaining every immutable source association.

    Raises:
        SecretScanRefusal: Missing objects, unsupported modes, or resource bounds.
    """
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_NO_LAZY_FETCH": "1",
        "LANG": "C.UTF-8",
    }
    command = ["git", "--no-replace-objects", "-C", str(repo)]

    def git(*args: Any) -> Any:
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

    def add(key: Any, source: Any) -> Any:
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
        # A merge associates only content novel at the same path/mode in every parent.
        args = ["diff-tree", "--no-renames", "--no-commit-id", "--raw", "-z", "-r"]
        novel = None
        for parent in parents[1:] or [None]:
            changes = git(
                *args, *([parent, commit] if parent else ["--root", commit])
            ).split(b"\0")
            if changes[-1] != b"" or (len(changes) - 1) % 2:
                raise SecretScanRefusalError("incomplete changed-object stream")
            changed = set()
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
                changed.add((raw_path, mode, object_id))
            novel = changed if novel is None else novel & changed
        for raw_path, mode, object_id in sorted(
            cast("set[tuple[Any, Any, Any]]", novel)
        ):
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

    if tag_object is not None and not include_tags:
        raise SecretScanRefusalError("pushed tag requires full-history admission")
    if include_tags:
        references = []
        visited = set()
        for row in git(
            "for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags"
        ).splitlines():
            fields = row.decode("ascii").split()
            if (
                len(fields) != TAG_REF_FIELD_COUNT
                or not SHA.fullmatch(fields[0])
                or fields[1] not in {"tag", "commit", "tree", "blob"}
            ):
                raise SecretScanRefusalError("invalid tag reference")
            references.append(fields)
        if tag_object is not None:
            if (
                not SHA.fullmatch(tag_object)
                or not isinstance(tag_head, str)
                or not SHA.fullmatch(tag_head)
            ):
                raise SecretScanRefusalError("invalid pushed tag binding")
            if (
                git("rev-parse", tag_object + "^{commit}").strip().decode("ascii")
                != tag_head
            ):
                raise SecretScanRefusalError("pushed tag commit identity mismatch")
            references.append(
                (tag_object, git("cat-file", "-t", tag_object).strip().decode("ascii"))
            )
        for initial_object, initial_kind in references:
            object_id, kind = initial_object, initial_kind
            depth = 0
            while kind == "tag" and object_id not in visited:
                depth += 1
                if depth > TAG_NESTING_LIMIT:
                    raise SecretScanRefusalError("tag nesting limit exceeded")
                visited.add(object_id)
                add(
                    ("tag", object_id),
                    {
                        "commit": object_id,
                        "file": "@tag-metadata",
                        "kind": "tag_metadata",
                    },
                )
                headers = (
                    git("cat-file", "tag", object_id).partition(b"\n\n")[0].splitlines()
                )
                if (
                    len(headers) < TAG_HEADER_MINIMUM
                    or not headers[0].startswith(b"object ")
                    or not headers[1].startswith(b"type ")
                ):
                    raise SecretScanRefusalError("invalid annotated tag object")
                object_id, kind = (
                    headers[0][7:].decode("ascii"),
                    headers[1][5:].decode("ascii"),
                )
                if not SHA.fullmatch(object_id) or kind not in {
                    "tag",
                    "commit",
                    "tree",
                    "blob",
                }:
                    raise SecretScanRefusalError("invalid tag target")
                if git("cat-file", "-t", object_id).strip().decode("ascii") != kind:
                    raise SecretScanRefusalError("tag target identity mismatch")

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
                    Path(path).chmod(0o600)
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
            Path(path).chmod(0o600)
    return {str(path): sources for path, sources in payloads.values()}


def validate_diagnostics(path: Any) -> None:
    """Refuse source/detector errors even when the native scanner exits zero.

    Raises:
        SecretScanRefusal: Malformed, unknown, warning, or error diagnostics.
    """
    if path.stat().st_size > DIAGNOSTIC_LIMIT:
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


def run_bounded_scanner(
    command: Any,
    environment: Any,
    output: Any,
    errors: Any,
    deadline: Any,
    *,
    output_limit: Any = None,
    error_limit: Any = None,
) -> Any:
    """Cap both scanner pipes while writing and always terminate its process group.

    Returns:
        The scanner exit status after both complete streams close.

    Raises:
        SecretScanRefusal: Timeout or a stream exceeding its fixed resource bound.
    """
    limits = (
        OUTPUT_LIMIT if output_limit is None else output_limit,
        DIAGNOSTIC_LIMIT if error_limit is None else error_limit,
    )
    with output.open("wb") as stdout, errors.open("wb") as stderr:
        Path(output).chmod(0o600)
        Path(errors).chmod(0o600)
        process = subprocess.Popen(  # noqa: S603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
            bufsize=0,
        )
        try:
            with selectors.DefaultSelector() as selector:
                for pipe, destination, limit in (
                    (cast("BinaryIO", process.stdout), stdout, limits[0]),
                    (cast("BinaryIO", process.stderr), stderr, limits[1]),
                ):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(
                        pipe, selectors.EVENT_READ, [destination, limit, 0]
                    )
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SecretScanRefusalError("scanner timeout")
                    for key, _ in selector.select(min(0.1, remaining)):
                        data = os.read(key.fd, 64 * 1024)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        destination, limit, size = key.data
                        if size + len(data) > limit:
                            raise SecretScanRefusalError(
                                "scanner stream limit exceeded"
                            )
                        destination.write(data)
                        key.data[2] += len(data)
            try:
                return process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise SecretScanRefusalError("scanner timeout") from None
        finally:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            cast("BinaryIO", process.stdout).close()
            cast("BinaryIO", process.stderr).close()


def source_git(repo: Any, *arguments: Any) -> Any:
    """Read inert local Git facts without hooks, lazy fetch or replacement objects.

    Returns:
        The complete bounded Git command output.

    Raises:
        SecretScanRefusal: Missing or incomplete source objects.
    """
    result = subprocess.run(  # noqa: S603
        ["git", "--no-replace-objects", "-C", str(repo), *arguments],  # noqa: S607
        capture_output=True,
        timeout=60,
        check=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_NO_LAZY_FETCH": "1",
            "LANG": "C.UTF-8",
        },
    )
    if result.returncode or len(result.stdout) > POLICY_LIMIT:
        raise SecretScanRefusalError("source binding unavailable")
    return result.stdout


def validate_candidate_policy(
    repo: Any, revision: Any, path: Any = ".forlex/security/exceptions.json"
) -> Any:
    """Parse the prospective policy's Git blob, never its executable code or rules.

    Returns:
        Immutable policy blob identity after strict, inert schema validation.

    Raises:
        SecretScanRefusal: Missing, symlinked, oversized or invalid candidate policy.
    """
    if (
        not isinstance(revision, str)
        or not SHA.fullmatch(revision)
        or not isinstance(path, str)
        or "\0" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise SecretScanRefusalError("invalid candidate policy location")
    entry = source_git(repo, "ls-tree", "-z", revision, "--", ":(literal)" + path)
    if not entry.endswith(b"\0") or entry.count(b"\0") != 1:
        raise SecretScanRefusalError("candidate exception policy unavailable")
    header, separator, raw_path = entry[:-1].partition(b"\t")
    fields = header.split()
    if (
        not separator
        or raw_path != os.fsencode(path)
        or len(fields) != GIT_OBJECT_HEADER_FIELD_COUNT
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or not SHA.fullmatch(fields[2].decode("ascii"))
    ):
        raise SecretScanRefusalError(
            "candidate exception policy must be regular Git data"
        )
    object_id = fields[2].decode("ascii")
    size = source_git(repo, "cat-file", "-s", object_id).strip()
    if not size.isdigit() or int(size) > POLICY_LIMIT:
        raise SecretScanRefusalError("candidate exception policy size limit exceeded")
    data = source_git(repo, "cat-file", "blob", object_id)
    if len(data) != int(size):
        raise SecretScanRefusalError("candidate exception policy incomplete")
    parse_policy(data.decode())
    return object_id


def scan(  # noqa: C901, PLR0912, PLR0915
    repo: Any,
    head: Any,
    base: Any,
    scanner: Any,
    policy: Any,
    repository: Any,
    timeout: Any,
    *,
    tag_object: Any = None,
    tag_ref: Any = None,
    merge: Any = None,
    candidate_policy: Any = None,
    full_if_nonforward: Any = False,
) -> Any:
    """Run the pinned scanner without credentials and redact its complete output.

    Returns:
        A redacted pass, failure or error report.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an
        error report.
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
        if tag_object is not None:
            if (
                not isinstance(tag_object, str)
                or not SHA.fullmatch(tag_object)
                or not isinstance(tag_ref, str)
                or not tag_ref.startswith("refs/tags/")
                or base is not None
            ):
                raise SecretScanRefusalError("invalid pushed tag source")
            report.update(
                {
                    "tag_object": tag_object,
                    "tag_ref_digest": hashlib.sha256(os.fsencode(tag_ref)).hexdigest(),
                }
            )
        elif tag_ref is not None:
            raise SecretScanRefusalError("incomplete pushed tag source")
        exceptions = read_policy(policy)
        effective, commits = git_range(
            repo, head, base, full_if_nonforward=full_if_nonforward
        )
        if merge is not None:
            if (
                not isinstance(merge, str)
                or not SHA.fullmatch(merge)
                or base is None
                or tag_object is not None
            ):
                raise SecretScanRefusalError("invalid prospective merge source")
            parents = (
                source_git(repo, "rev-list", "--parents", "-n", "1", merge)
                .decode("ascii")
                .split()
            )
            if parents != [merge, base, head]:
                raise SecretScanRefusalError(
                    "prospective merge does not match base and head"
                )
            report["merge"] = merge
            if merge not in commits:
                commits.append(merge)
        if candidate_policy is not None:
            evaluated = merge or head
            report["candidate_policy_blob"] = validate_candidate_policy(
                repo, evaluated, candidate_policy
            )
            report.update(
                {
                    "candidate_policy_validated": True,
                    "candidate_policy_source": evaluated,
                }
            )
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
            "--deduplication-cache-size=0",
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
            index = materialize(
                repo,
                commits,
                payload_directory,
                deadline,
                include_tags=effective is None,
                tag_object=tag_object,
                tag_head=head,
            )
            report["payload_count"] = len(index)
            command.append(str(payload_directory))
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(directory),
                "LANG": "C.UTF-8",
            }
            output, errors = directory / "raw.jsonl", directory / "stderr"
            code = run_bounded_scanner(command, environment, output, errors, deadline)
            if code != 0:
                raise SecretScanRefusalError("scanner execution failed")
            validate_diagnostics(errors)
            if output.stat().st_size > OUTPUT_LIMIT:
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
            "Source, policy, scanner execution or complete ou"
            "tput validation failed; no success was inferred."
        )
    return report


def github(
    repository: Any, suffix: Any, *, method: Any = "GET", body: Any = None
) -> Any:
    """Use scoped GitHub APIs without exposing tokens or response bodies.

    Returns:
        The authenticated JSON response.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an
        error report.
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
    if data is not None:
        headers["Content-Type"] = "application/json"
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


def pr_facts(repository: Any, number: Any, integration_branch: Any) -> Any:
    """Authenticate current accepted base, live head and exact prospective parents.

    Returns:
        The current immutable PR source and its allowed branch binding.

    Raises:
        SecretScanRefusalError: Auxiliary bases or stale/incomplete prospective source.
    """
    try:
        # Each API read has a 30-second network timeout; five attempts and four
        # one-second waits bound both pending computation and stale parent retries.
        for attempt in range(MERGE_POLL_ATTEMPTS):
            facts = _pr_facts(repository, number, integration_branch)
            if facts is not None:
                return facts
            if attempt + 1 < MERGE_POLL_ATTEMPTS:
                time.sleep(MERGE_POLL_INTERVAL)
        raise SecretScanRefusalError("prospective merge readiness was not confirmed")
    except (KeyError, TypeError, ValueError, OSError):
        raise SecretScanRefusalError("live PR source binding unavailable") from None


def _pr_facts(repository: Any, number: Any, integration_branch: Any) -> Any:  # noqa: C901
    """Read the authenticated PR, current branch ref and prospective object parents.

    Returns:
        Validated immutable source facts.

    Raises:
        SecretScanRefusalError: Unexpected source, branch, or merge identity.
    """
    pr = github(repository, "pulls/" + str(number))
    if pr["state"] != "open" or pr["base"]["repo"]["full_name"] != repository:
        raise SecretScanRefusalError("closed or foreign PR")
    metadata = github(repository, "")
    default = metadata["default_branch"]
    base_ref = pr["base"]["ref"]
    for name in (default, base_ref, integration_branch):
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
        ):
            raise SecretScanRefusalError("invalid accepted branch identity")
    if metadata["full_name"] != repository or base_ref not in {
        default,
        integration_branch,
    }:
        raise SecretScanRefusalError("PR base is not an accepted integration branch")
    reference = github(
        repository, "git/ref/heads/" + urllib.parse.quote(base_ref, safe="")
    )
    if (
        reference["ref"] != "refs/heads/" + base_ref
        or reference["object"]["type"] != "commit"
    ):
        raise SecretScanRefusalError("current base branch identity unavailable")
    head, base, merge = (
        pr["head"]["sha"],
        reference["object"]["sha"],
        pr["merge_commit_sha"],
    )
    if any(
        not isinstance(value, str) or not SHA.fullmatch(value) for value in (head, base)
    ):
        raise SecretScanRefusalError("current PR source identity unavailable")
    readiness = pr["mergeable"]
    if readiness is None:
        return None
    if readiness is not True:
        raise SecretScanRefusalError(
            "prospective merge is conflicting or has invalid readiness"
        )
    if not isinstance(merge, str) or not SHA.fullmatch(merge):
        raise SecretScanRefusalError("prospective source identity unavailable")
    if merge in {head, base}:
        raise SecretScanRefusalError(
            "prospective merge is not a distinct source object"
        )
    prospective = github(repository, "git/commits/" + merge)
    if prospective["sha"] != merge or [
        parent["sha"] for parent in prospective["parents"]
    ] != [base, head]:
        return None
    return {
        "head": head,
        "base": base,
        "merge": merge,
        "base_ref": base_ref,
        "default_branch": default,
        "integration_branch": integration_branch,
    }


def owned_check(
    check: Any, target: Any, identity: Any, expected_name: Any = CHECK_NAME
) -> Any:
    """Verify an acknowledged original check before any terminal mutation.

    Returns:
        Whether all immutable source and issuer identity fields match exactly.
    """
    return (
        isinstance(target, str)
        and SHA.fullmatch(target) is not None
        and isinstance(check, dict)
        and type(identity) is int
        and identity > 0
        and type(check.get("id")) is int
        and check["id"] == identity
        and check.get("head_sha") == target
        and expected_name in {CHECK_NAME, HISTORY_CHECK_NAME}
        and check.get("name") == expected_name
        and isinstance(check.get("app"), dict)
        and type(check["app"].get("id")) is int
        and check["app"]["id"] == ACTIONS_CHECK_APP_ID
    )


def fail_known_checks(
    repository: Any, targets: Any, expected_name: Any = CHECK_NAME
) -> Any:
    """Best-effort fail each freshly verified original check after a partial error.

    Returns:
        True only if every known target's terminal failure was confirmed. Unknown
        creation identities and unverifiable or foreign checks are never mutated.
    """
    confirmed = True
    summary = (
        "Result: failure. Check creation or completion wa"
        "s incomplete; a fresh scan is required. Raw secr"
        "ets and verification responses are never publish"
        "ed."
    )
    for target, identity in targets:
        if (
            type(identity) is not int
            or identity < 1
            or not isinstance(target, str)
            or not SHA.fullmatch(target)
        ):
            confirmed = False
            continue
        try:
            check = github(repository, "check-runs/" + str(identity))
            if not owned_check(check, target, identity, expected_name):
                confirmed = False
                continue
            result = github(
                repository,
                "check-runs/" + str(identity),
                method="PATCH",
                body={
                    "status": "completed",
                    "conclusion": "failure",
                    "output": {"title": expected_name, "summary": summary},
                },
            )
            if (
                not owned_check(result, target, identity, expected_name)
                or result.get("status") != "completed"
                or result.get("conclusion") != "failure"
            ):
                confirmed = False
        except (KeyError, TypeError, ValueError, OSError):
            confirmed = False
    return confirmed


def context(  # noqa: C901, PLR0912
    event: Any,
    kind: Any,
    repository: Any,
    pr_number: Any = 0,
    integration_branch: Any = "test",
) -> Any:
    """Bind authenticated live source facts before creating the check.

    Returns:
        The current source context and newly created check identity.

    Raises:
        SecretScanRefusalError: Invalid or incomplete evidence; scan captures this as
        an error report.
    """
    if kind not in {"pull_request_target", "push", "schedule", "workflow_dispatch"}:
        raise SecretScanRefusalError("unsupported workflow event")
    if event.get("repository", {}).get("full_name") != repository:
        raise SecretScanRefusalError("event repository mismatch")
    number = event.get("number") if kind == "pull_request_target" else pr_number
    tag_object, tag_ref = None, None
    if number:
        if not isinstance(number, int) or number < 1:
            raise SecretScanRefusalError("invalid PR")
        facts = pr_facts(repository, number, integration_branch)
        head, base = facts["head"], facts["base"]
        if kind == "pull_request_target" and (head, facts["base_ref"]) != (
            event["pull_request"]["head"]["sha"],
            event["pull_request"]["base"]["ref"],
        ):
            raise SecretScanRefusalError("stale PR event")
    else:
        head = os.environ["GITHUB_SHA"]
        base = event.get("before") if kind == "push" else None
        if kind == "push" and event.get("ref", "").startswith("refs/tags/"):
            tag_object, tag_ref = event.get("after"), event["ref"]
            if (
                not isinstance(tag_object, str)
                or not SHA.fullmatch(tag_object)
                or tag_object == "0" * 40
            ):
                raise SecretScanRefusalError("pushed tag object unavailable")
            base = None
        elif kind == "push" and event.get("after") == "0" * 40:
            # GitHub sets GITHUB_SHA to the default head for branch deletion.
            # Retain the deleted branch tip as the only source and scan it fully.
            head, base = event.get("before"), None
            if not isinstance(head, str) or not SHA.fullmatch(head) or head == "0" * 40:
                raise SecretScanRefusalError("deleted branch tip unavailable")
        if base == "0" * 40:
            base = None
    if not SHA.fullmatch(head) or (base is not None and not SHA.fullmatch(base)):
        raise SecretScanRefusalError("invalid source identity")
    result = {
        "repository": repository,
        "pr": number or None,
        "head": head,
        "base": base,
        "kind": kind,
    }
    if number:
        result.update(facts)
    if tag_object is not None:
        result.update({"tag_object": tag_object, "tag_ref": tag_ref})
    expected_name = CHECK_NAME if number else HISTORY_CHECK_NAME
    targets = []
    try:
        for target, key in [(head, "check_id")] + (
            [(result["merge"], "merge_check_id")] if number else []
        ):
            created = github(
                repository,
                "check-runs",
                method="POST",
                body={
                    "name": expected_name,
                    "head_sha": target,
                    "status": "in_progress",
                },
            )
            identity = created["id"]
            if type(identity) is not int or identity < 1:
                raise SecretScanRefusalError("created check identity unavailable")
            result[key] = identity
            targets.append((target, identity))
    except (KeyError, TypeError, ValueError, OSError):
        fail_known_checks(repository, targets, expected_name)
        raise SecretScanRefusalError(
            "check creation was not confirmed; no success was inferred"
        ) from None
    return result


def publish(source: Any, report: Any) -> Any:  # noqa: C901, PLR0915
    """Complete verified head and prospective checks only for unchanged live source.

    Returns:
        The verified original head check's terminal response.

    Raises:
        SecretScanRefusalError: Unverifiable check identity or completion.
    """
    repository = source["repository"]
    expected_name = CHECK_NAME if source["pr"] else HISTORY_CHECK_NAME

    def unchanged_pr() -> Any:
        try:
            current = pr_facts(
                repository, source["pr"], source.get("integration_branch", "test")
            )
            return all(current[key] == source[key] for key in current)
        except (KeyError, TypeError, ValueError, OSError):
            return False

    current_context = True
    if source["pr"]:
        current_context = unchanged_pr()
    counts = (
        report.get("blocked"),
        report.get("suppressed"),
        report.get("commit_count"),
    )
    complete = all(type(value) is int and value >= 0 for value in counts)
    tag_matches = report.get("tag_object") == source.get("tag_object") and (
        source.get("tag_object") is None
        or (
            isinstance(source.get("tag_ref"), str)
            and report.get("tag_ref_digest")
            == hashlib.sha256(os.fsencode(source["tag_ref"])).hexdigest()
        )
    )
    merge_matches = report.get("merge") == source.get("merge")
    candidate_valid = not source["pr"] or (
        report.get("candidate_policy_validated") is True
        and report.get("candidate_policy_source") == source.get("merge")
        and isinstance(report.get("candidate_policy_blob"), str)
        and SHA.fullmatch(report["candidate_policy_blob"])
    )
    success = (
        current_context
        and complete
        and tag_matches
        and merge_matches
        and candidate_valid
        and report.get("blocked") == 0
        and type(report.get("version")) is int
        and report.get("version") == 1
        and not report.get("error")
        and report.get("result") == "pass"
        and (report.get("head"), report.get("base"), report.get("repository"))
        == (source["head"], source["base"], repository)
    )
    targets = [(source["head"], source["check_id"])]
    if source.get("merge") is not None:
        targets.append((source["merge"], source["merge_check_id"]))
    elif source["pr"]:
        success = False

    # Verify both original identities before granting either a terminal success.
    # This preflight has the same independent cleanup boundary as terminal writes.
    try:
        for target, identity in targets:
            check = github(repository, "check-runs/" + str(identity))
            if not owned_check(check, target, identity, expected_name):
                raise SecretScanRefusalError("check identity mismatch")
    except (KeyError, TypeError, ValueError, OSError):
        fail_known_checks(repository, targets, expected_name)
        raise SecretScanRefusalError(
            "check identity verification was not confirmed; no success was inferred"
        ) from None
    blocked, suppressed, commits = (
        value if type(value) is int and value >= 0 else "unavailable"
        for value in counts
    )
    summary = (
        f"Result: "
        f"{('pass' if success else 'failure')}"
        f". Scanned commits: "
        f"{commits}"
        f". Blocking detections: "
        f"{blocked}"
        f". Exact fixture exceptions: "
        f"{suppressed}"
        f". Raw secrets and verification responses"
        f" are never published."
    )
    if not current_context:
        summary += (
            " Current PR context changed or could not be veri"
            "fied; a fresh scan is required."
        )
    conclusion = "success" if success else "failure"
    results: list[Any] = []

    def complete_check(
        target: Any, identity: Any, conclusion: Any, summary: Any
    ) -> Any:
        try:
            result = github(
                repository,
                "check-runs/" + str(identity),
                method="PATCH",
                body={
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": {"title": expected_name, "summary": summary},
                },
            )
        except (KeyError, TypeError, ValueError, OSError):
            raise SecretScanRefusalError("check completion unavailable") from None
        if (
            not owned_check(result, target, identity, expected_name)
            or result.get("status") != "completed"
            or result.get("conclusion") != conclusion
        ):
            raise SecretScanRefusalError("check completion was not confirmed")
        return result

    try:
        for target, identity in targets:
            if success and source["pr"] and not unchanged_pr():
                success = False
                conclusion = "failure"
                summary = (
                    "Result: failure. Current PR context changed or c"
                    "ould not be verified; a fresh scan is required. "
                    "Raw secrets and verification responses are never"
                    " published."
                )
                for index, (previous_target, previous_id) in enumerate(
                    targets[: len(results)]
                ):
                    results[index] = complete_check(
                        previous_target, previous_id, conclusion, summary
                    )
            results.append(complete_check(target, identity, conclusion, summary))
        if success and source["pr"] and not unchanged_pr():
            summary = (
                "Result: failure. Current PR context changed or c"
                "ould not be verified; a fresh scan is required. "
                "Raw secrets and verification responses are never"
                " published."
            )
            results = [
                complete_check(target, identity, "failure", summary)
                for target, identity in targets
            ]
        return results[0]
    except (KeyError, TypeError, ValueError, OSError):
        fail_known_checks(repository, targets, expected_name)
        raise SecretScanRefusalError(
            "check completion was not confirmed; no success was inferred"
        ) from None


def main() -> int:  # noqa: C901, PLR0915
    """Execute one gate stage and fail closed on incomplete evidence.

    Returns:
        Zero only for a successfully completed gate stage.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-policy")
    validate.add_argument("--policy", type=Path, required=True)
    prepare = sub.add_parser("context")
    prepare.add_argument("--event", type=Path, required=True)
    prepare.add_argument("--kind", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--pr", type=int, default=0)
    prepare.add_argument("--integration-branch", default="test")
    prepare.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("scan")
    run.add_argument("--context", type=Path, required=True)
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--scanner", type=Path, required=True)
    run.add_argument("--policy", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout", type=int, default=1200)
    run.add_argument("--candidate-policy", default=".forlex/security/exceptions.json")
    finish = sub.add_parser("publish")
    finish.add_argument("--context", type=Path, required=True)
    finish.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-policy":
            read_policy(args.policy)
        elif args.command == "context":
            result = context(
                strict_json(args.event.read_text()),
                args.kind,
                args.repository,
                args.pr,
                args.integration_branch,
            )
            targets = [(result["head"], result["check_id"])]
            if result.get("merge") is not None:
                targets.append((result["merge"], result["merge_check_id"]))
            try:
                args.output.write_text(json.dumps(result) + "\n")
                with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
                    stream.write("head=" + result["head"] + "\n")
                    if result.get("merge") is not None:
                        stream.write("merge=" + result["merge"] + "\n")
                    if result.get("tag_object") is not None:
                        stream.write("tag_object=" + result["tag_object"] + "\n")
            except (KeyError, ValueError, OSError, TypeError):
                fail_known_checks(
                    result["repository"],
                    targets,
                    CHECK_NAME if result["pr"] else HISTORY_CHECK_NAME,
                )
                raise SecretScanRefusalError(
                    "context persistence was not confirmed; no success was inferred"
                ) from None
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
                tag_object=source.get("tag_object"),
                tag_ref=source.get("tag_ref"),
                merge=source.get("merge"),
                candidate_policy=args.candidate_policy if source.get("pr") else None,
                full_if_nonforward=source.get("kind") == "push",
            )
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            return 0 if report["result"] == "pass" else 1
        else:
            source = strict_json(args.context.read_text())
            try:
                report = strict_json(args.report.read_text())
            except (ValueError, OSError, TypeError):
                report = {"result": "error"}
            if not isinstance(report, dict):
                report = {"result": "error"}
            result = publish(source, report)
            return 0 if result["conclusion"] == "success" else 1
    except (KeyError, ValueError, OSError, TypeError):
        print(  # noqa: T201
            "Secret gate refused incomplete or changed contex"
            "t; no secret bytes are included."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
