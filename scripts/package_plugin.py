#!/usr/bin/env python3
"""Build deterministic, allowlisted Codex Build Visualizer distributions."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import BinaryIO, Union
import unicodedata
import uuid
import zipfile


PLUGIN_NAME = "codex-build-visualizer"
PLUGIN_DESCRIPTION = (
    "Visualize and audit observable Codex coding work as a privacy-enhanced "
    "timeline, replay dashboard, and Token-usage report."
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

RUNTIME_FILES = (
    "SKILL.md",
    "agents/openai.yaml",
    "assets/icon.svg",
    "assets/viewer.html",
    "scripts/trace.py",
)
MAINTAINER_DISTRIBUTION_PREFIX = "\nFor a deterministic installable plugin archive"
REPOSITORY_FILES = (
    "references/distribution.md",
    "scripts/package_plugin.py",
    "tests/test_distribution.py",
    "tests/test_browser.py",
    "tests/test_trace.py",
    "tests/test_viewer.py",
)

SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

CI_WORKFLOW = """name: test

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    name: ${{ matrix.os }} / Python ${{ matrix.python }}
    runs-on: ${{ matrix.os }}
    # Linux is the supported release gate. macOS and Windows remain visible
    # compatibility probes while their platform-specific filesystem semantics
    # are being hardened; failures there must not hide Linux/browser health.
    continue-on-error: ${{ matrix.os != 'ubuntu-latest' }}
    timeout-minutes: 20
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python: ["3.9", "3.12"]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: ${{ matrix.python }}
      - name: Run skill tests
        run: python -B tests/run_repo_tests.py

  browser:
    name: Chromium / mobile / CSP
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.12"
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: "24"
          package-manager-cache: false
      - name: Install pinned Playwright and Chromium
        run: |
          npm install --no-save --ignore-scripts playwright@1.62.0 jsdom@26.1.0
          npx playwright install --with-deps chromium
      - name: Run real-browser checks
        run: python -B tests/run_repo_tests.py test_browser
        env:
          CBV_REQUIRE_BROWSER: "1"
          CBV_REQUIRE_JSDOM: "1"
"""

REPO_TEST_RUNNER = r'''"""Stage the packaged skill and run its maintainer tests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[1]
PACKAGED_SKILL = (
    REPOSITORY / "plugins" / "codex-build-visualizer" / "skills"
    / "codex-build-visualizer"
)


def main() -> int:
    modules = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="codex-build-visualizer-ci.") as temporary:
        stage = Path(temporary) / "codex-build-visualizer"
        shutil.copytree(PACKAGED_SKILL, stage)
        shutil.copytree(REPOSITORY / "tests", stage / "tests")
        (stage / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            REPOSITORY / "scripts" / "package_plugin.py",
            stage / "scripts" / "package_plugin.py",
        )
        (stage / "references").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            REPOSITORY / "docs" / "distribution.md",
            stage / "references" / "distribution.md",
        )
        arguments = [sys.executable, "-B", "-m", "unittest"]
        if modules == ["test_browser"]:
            arguments.extend(["tests.test_viewer", "tests.test_browser", "-v"])
        elif not modules:
            arguments.extend(["discover", "-s", str(stage / "tests"), "-v"])
        else:
            arguments.extend(modules)
        environment = os.environ.copy()
        repository_modules = str(REPOSITORY / "node_modules")
        environment["NODE_PATH"] = repository_modules + (
            os.pathsep + environment["NODE_PATH"]
            if environment.get("NODE_PATH") else ""
        )
        return subprocess.call(arguments, cwd=stage, env=environment)


if __name__ == "__main__":
    raise SystemExit(main())
'''


class PackagingError(ValueError):
    """Raised when a distribution cannot be built safely."""


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _text_bytes(value: str) -> bytes:
    return value.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _normalize_text(data: bytes, label: str) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackagingError(f"source file is not UTF-8 text: {label}") from error
    return _text_bytes(text)


def validate_version(version: str) -> str:
    if len(version) > 64:
        raise PackagingError("version must be 64 characters or fewer")
    match = SEMVER_RE.fullmatch(version)
    if not match:
        raise PackagingError("version must be valid SemVer, for example 1.0.0")
    prerelease = match.group(4)
    if prerelease:
        for identifier in prerelease.split("."):
            if identifier.isascii() and identifier.isdigit() and len(identifier) > 1 and identifier[0] == "0":
                raise PackagingError("numeric prerelease identifiers must not contain leading zeroes")
    return version


def _link_like(path: Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if reparse_flag and getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        return True
    is_junction = getattr(os.path, "isjunction", None)
    return bool(is_junction and is_junction(path))


def _absolute_lexical(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    # macOS exposes a few root-level compatibility aliases (notably /var and
    # /tmp) as system-owned symlinks into /private.  tempfile returns the
    # lexical /var spelling while the same file is reported as /private/var by
    # resolved script paths.  Normalize only these fixed root aliases; never
    # realpath arbitrary user-controlled descendants, which would weaken the
    # no-follow checks below.
    if sys.platform == "darwin" and absolute.is_absolute() and len(absolute.parts) > 1:
        aliases = {"var": "var", "tmp": "tmp", "etc": "etc"}
        alias = aliases.get(absolute.parts[1])
        if alias is not None:
            absolute = Path("/private") / alias / Path(*absolute.parts[2:])
    return absolute


def _validate_directory_chain(directory: Path) -> None:
    directory = _absolute_lexical(directory)
    anchor = Path(directory.anchor)
    current = anchor
    parts = directory.parts[1:] if directory.anchor else directory.parts
    for part in parts:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError as error:
            raise PackagingError(f"directory does not exist: {current}") from error
        if _link_like(current, metadata):
            raise PackagingError(f"link or reparse-point path component is not allowed: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise PackagingError(f"path component is not a directory: {current}")


def _open_posix_directory(directory: Path) -> int:
    """Open an absolute directory through no-follow descriptors for every component."""
    absolute = _absolute_lexical(directory)
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(os.sep, flags)
        for part in absolute.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(f"not a directory: {absolute}")
        return descriptor
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise PackagingError(f"could not safely open directory: {absolute}") from error


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_mode),
        int(metadata.st_size),
        int(getattr(metadata, "st_dev", 0)),
        int(getattr(metadata, "st_ino", 0)),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
        int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (
        stat.S_IFMT(metadata.st_mode),
        int(getattr(metadata, "st_dev", 0)),
        int(getattr(metadata, "st_ino", 0)),
    )


def _read_regular_file(
    skill_root: Path, relative: str, *, root_descriptor: int | None = None,
) -> bytes:
    path = skill_root.joinpath(*relative.split("/"))
    if os.name != "nt" and root_descriptor is not None:
        parts = Path(relative).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise PackagingError(f"unsafe source path: {relative}")
        parent_descriptor = os.dup(root_descriptor)
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            for part in parts[:-1]:
                next_descriptor = os.open(part, directory_flags, dir_fd=parent_descriptor)
                os.close(parent_descriptor)
                parent_descriptor = next_descriptor
            before = os.stat(parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise PackagingError(f"source must be a regular, single-link file: {relative}")
            if before.st_size > MAX_SOURCE_FILE_BYTES:
                raise PackagingError(f"source file exceeds {MAX_SOURCE_FILE_BYTES} bytes: {relative}")
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
                    raise PackagingError(f"source file changed while opening: {relative}")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, min(1024 * 1024, MAX_SOURCE_FILE_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > MAX_SOURCE_FILE_BYTES:
                        raise PackagingError(f"source file exceeds {MAX_SOURCE_FILE_BYTES} bytes: {relative}")
                after_open = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after_name = os.stat(parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
            if _identity(after_open) != _identity(before) or _identity(after_name) != _identity(before):
                raise PackagingError(f"source file changed while reading: {relative}")
            data = b"".join(chunks)
            if len(data) != before.st_size:
                raise PackagingError(f"source file size changed while reading: {relative}")
            return _normalize_text(data, relative)
        except PackagingError:
            raise
        except OSError as error:
            raise PackagingError(f"could not safely open source file: {relative}") from error
        finally:
            os.close(parent_descriptor)
    _validate_directory_chain(path.parent)
    try:
        before = os.lstat(path)
    except FileNotFoundError as error:
        raise PackagingError(f"required source file is missing: {relative}") from error
    if _link_like(path, before) or not stat.S_ISREG(before.st_mode):
        raise PackagingError(f"source must be a regular, non-link file: {relative}")
    if before.st_size > MAX_SOURCE_FILE_BYTES:
        raise PackagingError(f"source file exceeds {MAX_SOURCE_FILE_BYTES} bytes: {relative}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PackagingError(f"could not safely open source file: {relative}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise PackagingError(f"source file changed while opening: {relative}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_SOURCE_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_FILE_BYTES:
                raise PackagingError(f"source file exceeds {MAX_SOURCE_FILE_BYTES} bytes: {relative}")
    finally:
        os.close(descriptor)

    after = os.lstat(path)
    if _link_like(path, after) or _identity(after) != _identity(before):
        raise PackagingError(f"source file changed while reading: {relative}")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise PackagingError(f"source file size changed while reading: {relative}")
    return _normalize_text(data, relative)


def _plugin_manifest(version: str) -> bytes:
    return _json_bytes(
        {
            "description": PLUGIN_DESCRIPTION,
            "name": PLUGIN_NAME,
            "skills": "./skills/",
            "version": version,
        }
    )


def _marketplace_manifest() -> bytes:
    return _json_bytes(
        {
            "interface": {"displayName": "Codex Build Visualizer"},
            "name": "codex-build-visualizer",
            "plugins": [
                {
                    "category": "Productivity",
                    "name": PLUGIN_NAME,
                    "policy": {
                        "authentication": "ON_INSTALL",
                        "installation": "AVAILABLE",
                    },
                    "source": {
                        "path": f"./plugins/{PLUGIN_NAME}",
                        "source": "local",
                    },
                }
            ],
        }
    )


def _packaged_skill(data: bytes) -> bytes:
    text = data.decode("utf-8")
    marker = text.find(MAINTAINER_DISTRIBUTION_PREFIX)
    if marker < 0:
        # A generated repository intentionally contains the already-trimmed
        # runtime SKILL. Permit deterministic re-packaging only when no dangling
        # maintainer-only link or command survived the prior transformation.
        if "references/distribution.md" in text or "scripts/package_plugin.py" in text:
            raise PackagingError("SKILL.md has dangling maintainer distribution references")
        return _text_bytes(text.rstrip() + "\n")
    return _text_bytes(text[:marker].rstrip() + "\n")


def _runtime_entries(
    skill_root: Path, prefix: str, *, root_descriptor: int | None,
) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    for relative in RUNTIME_FILES:
        content = _read_regular_file(skill_root, relative, root_descriptor=root_descriptor)
        entries[f"{prefix}{relative}"] = _packaged_skill(content) if relative == "SKILL.md" else content
    return entries


def collect_entries(skill_root: Path, mode: str, version: str) -> dict[str, bytes]:
    version = validate_version(version)
    skill_root = _absolute_lexical(skill_root)
    _validate_directory_chain(skill_root)
    root_descriptor = _open_posix_directory(skill_root) if os.name != "nt" else None
    try:
        if mode == "plugin":
            entries = _runtime_entries(skill_root, f"skills/{PLUGIN_NAME}/", root_descriptor=root_descriptor)
            entries[".codex-plugin/plugin.json"] = _plugin_manifest(version)
        elif mode == "repo":
            plugin_prefix = f"plugins/{PLUGIN_NAME}/"
            entries = _runtime_entries(
                skill_root,
                f"{plugin_prefix}skills/{PLUGIN_NAME}/",
                root_descriptor=root_descriptor,
            )
            entries[f"{plugin_prefix}.codex-plugin/plugin.json"] = _plugin_manifest(version)
            entries[".agents/plugins/marketplace.json"] = _marketplace_manifest()
            entries[".github/workflows/test.yml"] = _text_bytes(CI_WORKFLOW)
            entries["tests/run_repo_tests.py"] = _text_bytes(REPO_TEST_RUNNER)
            for relative in REPOSITORY_FILES:
                archive_name = (
                    f"docs/{Path(relative).name}"
                    if relative.startswith("references/")
                    else relative
                )
                entries[archive_name] = _read_regular_file(
                    skill_root, relative, root_descriptor=root_descriptor,
                )
        else:
            raise PackagingError("mode must be 'plugin' or 'repo'")
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)

    total = sum(len(data) for data in entries.values())
    if total > MAX_ARCHIVE_BYTES:
        raise PackagingError(f"archive content exceeds {MAX_ARCHIVE_BYTES} bytes")
    if len(entries) != len(set(entries)):
        raise PackagingError("archive contains duplicate entry names")
    return entries


def _zip_info(name: str) -> zipfile.ZipInfo:
    parts = name.split("/")
    if (
        name.startswith("/") or "\\" in name or re.match(r"^[A-Za-z]:", name)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PackagingError(f"unsafe archive member name: {name}")
    info = zipfile.ZipInfo(filename=name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.internal_attr = 0
    info.extra = b""
    info.comment = b""
    return info


def _write_zip(destination: Union[Path, BinaryIO], entries: dict[str, bytes]) -> None:
    normalized_names: set[str] = set()
    for name in entries:
        normalized = unicodedata.normalize("NFC", name).casefold()
        if normalized in normalized_names:
            raise PackagingError(f"archive member name collides after normalization: {name}")
        normalized_names.add(normalized)
    with zipfile.ZipFile(destination, mode="w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = b""
        for name in sorted(entries):
            archive.writestr(_zip_info(name), entries[name])


def _publish_exclusive(temporary: Path, output: Path) -> None:
    # The Windows implementation of os.link varies by filesystem, privilege,
    # developer-mode and runner configuration.  An exclusive destination open
    # provides the same no-overwrite guarantee without depending on hard links.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        destination = os.open(output, flags, 0o600)
    except FileExistsError as error:
        raise PackagingError(f"output already exists: {output}") from error
    try:
        source = os.open(temporary, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            while True:
                chunk = os.read(source, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination, view)
                    view = view[written:]
            os.fsync(destination)
        finally:
            os.close(source)
    except Exception:
        os.close(destination)
        try:
            os.unlink(output)
        except OSError:
            pass
        raise
    else:
        os.close(destination)


def _safe_output_path(output: Path) -> Path:
    output = _absolute_lexical(output.expanduser())
    if output.name in {"", ".", ".."} or output.suffix.lower() != ".zip":
        raise PackagingError("output must be a new .zip file")
    _validate_directory_chain(output.parent)
    if os.path.lexists(output):
        raise PackagingError(f"output already exists: {output}")
    return output


def build_archive(
    *, mode: str, version: str, output: Path, skill_root: Path | None = None,
) -> tuple[Path, str, int]:
    if skill_root is None:
        script = _absolute_lexical(Path(__file__))
        try:
            script_metadata = os.lstat(script)
        except FileNotFoundError as error:
            raise PackagingError("packager script location is unavailable") from error
        if _link_like(script, script_metadata) or not stat.S_ISREG(script_metadata.st_mode):
            raise PackagingError("packager must be invoked from a regular, non-link file")
        skill_root = script.parent.parent

    output = _safe_output_path(output)
    entries = collect_entries(skill_root, mode, version)
    if os.name != "nt":
        parent_descriptor = _open_posix_directory(output.parent)
        temporary_name = f".{output.name}.{uuid.uuid4().hex}.tmp"
        temporary_created = False
        published = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            temporary_created = True
            with os.fdopen(descriptor, "w+b", closefd=True) as stream:
                _write_zip(stream, entries)
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
                digest_builder = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    digest_builder.update(chunk)
                digest = digest_builder.hexdigest()
            try:
                os.link(
                    temporary_name, output.name,
                    src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise PackagingError(f"output already exists: {output}") from error
            except OSError as error:
                raise PackagingError(f"could not publish output safely: {output}") from error
            published = True
            os.fsync(parent_descriptor)
            # Ensure the lexical output parent still names the directory pinned
            # above. If it was swapped, remove the pinned artifact and fail.
            current_descriptor = _open_posix_directory(output.parent)
            try:
                if _directory_identity(os.fstat(current_descriptor)) != _directory_identity(os.fstat(parent_descriptor)):
                    raise PackagingError("output directory changed during publication")
            finally:
                os.close(current_descriptor)
        except Exception:
            if published:
                try:
                    os.unlink(output.name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            raise
        finally:
            if temporary_created:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            os.close(parent_descriptor)
    else:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            _write_zip(temporary, entries)
            with temporary.open("rb") as stream:
                digest = hashlib.sha256(stream.read()).hexdigest()
            _publish_exclusive(temporary, output)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return output, digest, len(entries)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic Codex Build Visualizer distribution ZIP."
    )
    parser.add_argument("--mode", choices=("plugin", "repo"), required=True)
    parser.add_argument("--version", required=True, help="SemVer release, for example 1.0.0")
    parser.add_argument("--output", type=Path, required=True, help="new .zip output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        output, digest, count = build_archive(
            mode=arguments.mode,
            version=arguments.version,
            output=arguments.output,
        )
    except (PackagingError, OSError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"created {arguments.mode} ZIP: {output}")
    print(f"files: {count}")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
