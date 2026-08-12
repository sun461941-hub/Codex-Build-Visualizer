#!/usr/bin/env python3
"""Create a privacy-enhanced, replayable trace of observable Codex work."""

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterator
import uuid


TRACE_DIR = ".codex-visualizer"
STATE_NAME = "trace.json"
PUBLIC_NAME = "events.js"
META_NAME = "meta.js"
HISTORY_STATE_NAME = "history.json"
HISTORY_PUBLIC_NAME = "history.js"
JOURNAL_NAME = "journal.jsonl"
VIEWER_NAME = "index.html"
SCHEMA_VERSION = 6
MAX_SCAN_FILES = 10_000
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_PUBLIC_CHANGES = 2_000
MAX_CAPTURE_BYTES = 128_000
MAX_OUTPUT_EXCERPT = 6_000
MAX_JSONL_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 50_000
MAX_TOKEN_VALUE = 10**12
MAX_EVENTS = 5_000
MAX_ARCHIVES = 20
MAX_TOKEN_HISTORY = 200
MAX_TOKEN_SAMPLE_IDS = 500
MAX_TOKEN_CUMULATIVE_SCOPES = 100
MAX_JOURNAL_BYTES = 96 * 1024 * 1024
AUTO_SNAPSHOT_DEBOUNCE_MS = 1_200
AUTO_SNAPSHOT_LEASE_MS = 30_000
AUTO_SNAPSHOT_SPAWN_GRACE_MS = 2_000
INGEST_BATCH_SIZE = 2_000
MAX_INGEST_BATCH_BYTES = 8 * 1024 * 1024
_LOCK_CONTEXT = threading.local()

IGNORE_DIRS = {
    ".git", ".hg", ".svn", TRACE_DIR, "node_modules", "bower_components",
    "vendor", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".next", ".nuxt", ".turbo", ".cache",
    "coverage", "dist", "build", "target", "DerivedData",
}
IGNORE_FILES: set[str] = set()

SECRET_SUBSTITUTIONS = (
    (re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)", re.I | re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?:sk-(?:proj-|test-)?|[sr]k_(?:live|test)_|whsec_)[A-Za-z0-9_-]{12,}", re.I), "[REDACTED]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{20,})\b", re.I), "[REDACTED]"),
    (re.compile(r"\b(?:glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{16,}|hf_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{30,})\b", re.I), "[REDACTED]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b", re.I), "[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:basic|bearer))\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(?:bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(?<!\w)(--?(?:api[-_]?key|token|access[-_]?token|auth[-_]?token|password|passwd|secret|client[-_]?secret|credential|authorization))(\s+|=)(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|token|password|passwd|secret|credential)[A-Z0-9_]*)(\s*[:=]\s*)([^\s,;]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/@\s:]+):([^@/\s]+)@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)([?&](?:x-amz-(?:signature|credential|security-token)|signature|sig|token|access_token|api_key|key)=)[^&#\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[REDACTED_EMAIL]"),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def elapsed_ms(started: str | None) -> int | None:
    parsed = parse_iso(started)
    if not parsed:
        return None
    return max(0, round((datetime.now(timezone.utc) - parsed).total_seconds() * 1_000))


def redact_text(value: Any) -> str:
    text = (value if isinstance(value, str) else "" if value is None else str(value)).replace("\x00", "")
    for pattern, replacement in SECRET_SUBSTITUTIONS:
        text = pattern.sub(replacement, text)
    return text


def safe_text(value: Any, limit: int = 4_000) -> str:
    return redact_text(value)[:limit]


SENSITIVE_ARGUMENTS = {
    "api-key", "apikey", "token", "access-token", "auth-token", "oauth-token",
    "refresh-token", "id-token", "session-token", "password", "passwd", "secret",
    "passphrase", "cookie", "cookie-jar", "client-secret", "secret-key", "secret-access-key", "private-key", "credential", "authorization",
    "user", "proxy-user", "userpwd", "proxy-userpwd", "http-user", "ftp-user",
}
SENSITIVE_SHORT_ARGUMENTS = {"-u", "-U"}
AUTH_SCHEME_ARGUMENTS = {"authorization", "proxy-authorization"}


def safe_command_text(command: list[Any] | str, limit: int = 1_000) -> str:
    """Render argv while redacting values paired with recognized secret flags."""
    if isinstance(command, str):
        try:
            parsed = shlex.split(command)
        except ValueError:
            parsed = []
        return safe_command_text(parsed, limit) if parsed else safe_text(command, limit)
    redacted: list[str] = []
    hide_next = False
    hide_authorization_credential = False
    for raw in command:
        argument = str(raw)
        if hide_next:
            redacted.append("[REDACTED]")
            hide_next = False
            if hide_authorization_credential and argument.rstrip(":").lower() in {"bearer", "basic", "token"}:
                hide_next = True
            hide_authorization_credential = False
            continue
        if len(argument) > 2 and argument[:2] in SENSITIVE_SHORT_ARGUMENTS:
            redacted.append(argument[:2] + "[REDACTED]")
            continue
        head, separator, _ = argument.partition("=")
        normalized = head.lstrip("-/").lower().replace("_", "-")
        option_prefix = head.startswith("-") or head.startswith("/")
        if head in SENSITIVE_SHORT_ARGUMENTS or (option_prefix and normalized in SENSITIVE_ARGUMENTS):
            if separator:
                redacted.append(f"{head}=[REDACTED]")
            else:
                redacted.append(head)
                hide_next = True
                hide_authorization_credential = normalized in AUTH_SCHEME_ARGUMENTS
            continue
        redacted.append(argument)
    return safe_text(shlex.join(redacted), limit)


def localized(state: dict[str, Any], english: str, chinese: str) -> str:
    return chinese if state.get("lang") == "zh" else english


def root_path(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"Project root is not a directory: {root}")
    return root


def trace_dir(root: Path) -> Path:
    return root / TRACE_DIR


def is_windows_reparse(metadata: os.stat_result) -> bool:
    if os.name != "nt":
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def validate_windows_directory_components(path: Path) -> None:
    absolute = path.absolute()
    for candidate in reversed((absolute, *absolute.parents)):
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or is_windows_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise OSError(f"Refusing linked or non-directory component: {candidate}")


def open_safe_directory_fd(path: Path) -> int:
    """Open an absolute directory path without following any symlink component."""
    if os.name == "nt":
        raise OSError("Directory descriptors are unavailable on Windows; validate components instead.")
    absolute = path.absolute()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    locked_path = getattr(_LOCK_CONTEXT, "trace_path", None)
    locked_fd = getattr(_LOCK_CONTEXT, "trace_fd", None)
    if isinstance(locked_path, Path) and isinstance(locked_fd, int):
        try:
            relative = absolute.relative_to(locked_path)
        except ValueError:
            relative = None
        if relative is not None:
            descriptor = os.dup(locked_fd)
            try:
                for part in relative.parts:
                    if part in {"", "."}:
                        continue
                    next_descriptor = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = next_descriptor
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise
    descriptor = os.open(os.sep, flags)
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError(f"Not a directory: {absolute}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def ensure_safe_directory(path: Path, *, create: bool = True, private: bool = False) -> Path:
    """Create or verify one managed directory without following a final symlink."""
    if os.name == "nt":
        try:
            validate_windows_directory_components(path.parent)
        except OSError as exc:
            raise SystemExit(f"Cannot safely inspect parent directory for {path}: {exc}") from exc
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if not create:
                raise SystemExit(f"Required directory does not exist: {path}")
            try:
                path.mkdir(mode=0o700 if private else 0o755)
                metadata = path.lstat()
            except FileExistsError:
                metadata = path.lstat()
            except OSError as exc:
                raise SystemExit(f"Cannot create managed directory {path}: {exc}") from exc
        except OSError as exc:
            raise SystemExit(f"Cannot inspect managed directory {path}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or is_windows_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Refusing unsafe managed directory: {path}")
        try:
            os.chmod(path, 0o700 if private else metadata.st_mode & 0o777)
        except OSError:
            pass
        return path
    try:
        descriptor = open_safe_directory_fd(path)
    except FileNotFoundError:
        if not create:
            raise SystemExit(f"Required directory does not exist: {path}")
        try:
            parent_descriptor = open_safe_directory_fd(path.parent)
            try:
                try:
                    os.mkdir(path.name, 0o700 if private else 0o755, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except OSError as exc:
            raise SystemExit(f"Cannot create managed directory {path}: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Cannot inspect managed directory {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Refusing unsafe managed directory: {path}")
        if private:
            os.fchmod(descriptor, 0o700)
    except (NotImplementedError, OSError) as exc:
        raise SystemExit(f"Cannot secure managed directory {path}: {exc}") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return path


def safe_file_metadata(path: Path) -> os.stat_result | None:
    if os.name == "nt":
        try:
            metadata = path.lstat()
            if is_windows_reparse(metadata):
                raise SystemExit(f"Refusing unsafe managed file: {path}")
            return metadata
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SystemExit(f"Cannot safely inspect {path}: {exc}") from exc
    parent_descriptor: int | None = None
    try:
        parent_descriptor = open_safe_directory_fd(path.parent)
        return os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemExit(f"Cannot safely inspect {path}: {exc}") from exc
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def secure_read_text(path: Path, *, max_bytes: int = MAX_STATE_BYTES, single_link: bool = True) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    parent_descriptor: int | None = None
    try:
        if os.name == "nt":
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or is_windows_reparse(metadata):
                raise SystemExit(f"Refusing unsafe managed file: {path}")
            descriptor = os.open(path, flags)
        else:
            parent_descriptor = open_safe_directory_fd(path.parent)
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise SystemExit(f"Cannot safely read {path}: {exc}") from exc
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (single_link and metadata.st_nlink != 1):
            raise SystemExit(f"Refusing unsafe managed file: {path}")
        if metadata.st_size > max_bytes:
            raise SystemExit(f"Managed file exceeds the {max_bytes}-byte limit: {path}")
        chunks = bytearray()
        while len(chunks) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > max_bytes:
            raise SystemExit(f"Managed file exceeds the {max_bytes}-byte limit: {path}")
        return bytes(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"Managed file is not valid UTF-8: {path}") from exc
    finally:
        os.close(descriptor)


def atomic_write(path: Path, content: str, *, mode: int = 0o600, private_parent: bool = False) -> None:
    """Atomically replace a file through a verified directory descriptor."""
    directory = ensure_safe_directory(path.parent, private=private_parent)
    encoded = content.encode("utf-8")
    temp_name = f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    if os.name != "nt":
        try:
            directory_fd = open_safe_directory_fd(directory)
            descriptor = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=directory_fd,
            )
            try:
                os.fchmod(descriptor, mode)
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temp_name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError as exc:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except (OSError, UnboundLocalError):
                pass
            raise SystemExit(f"Cannot safely write {path}: {exc}") from exc
        finally:
            try:
                os.close(directory_fd)
            except (OSError, UnboundLocalError):
                pass
        return
    temp = directory / temp_name
    try:
        with temp.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp, mode, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
        os.replace(temp, path)
        try:
            os.chmod(path, mode, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
    except (NotImplementedError, OSError) as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        raise SystemExit(f"Cannot safely write {path}: {exc}") from exc


def secure_append(path: Path, content: str, *, max_bytes: int) -> None:
    """Append one durable record without following links or accepting non-files."""
    directory = ensure_safe_directory(path.parent, private=True)
    encoded = content.encode("utf-8")
    descriptor: int | None = None
    directory_descriptor: int | None = None
    flags = (
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        if os.name == "nt":
            existing = safe_file_metadata(path)
            if existing is not None and (
                stat.S_ISLNK(existing.st_mode) or is_windows_reparse(existing)
                or not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
            ):
                raise SystemExit(f"Refusing unsafe managed file: {path}")
            descriptor = os.open(path, flags, 0o600)
        else:
            directory_descriptor = open_safe_directory_fd(directory)
            descriptor = os.open(path.name, flags, 0o600, dir_fd=directory_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SystemExit(f"Refusing unsafe managed file: {path}")
        if metadata.st_size + len(encoded) > max_bytes:
            raise SystemExit(f"Managed append file would exceed the {max_bytes}-byte limit: {path}")
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        if directory_descriptor is not None:
            os.fsync(directory_descriptor)
    except OSError as exc:
        raise SystemExit(f"Cannot safely append {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def json_dump(value: Any, *, indent: int | None = None, compact: bool = False) -> str:
    separators = (",", ":") if compact else None
    return json.dumps(value, ensure_ascii=True, indent=indent, separators=separators, allow_nan=False)


def json_for_script(value: Any) -> str:
    return (json_dump(value, compact=True).replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


JOURNAL_INTERNAL_KEYS = {
    "integrity", "_journal_hash", "_journal_event_seq", "_journal_revision",
    "_scan_cache_dirty", "_recovered_from_journal", "_journal_torn_tail",
}
JOURNAL_IMMUTABLE_KEYS = {"baseline", "git_baseline"}


def integrity_state(state: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in state.items() if key not in JOURNAL_INTERNAL_KEYS}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def integrity_checksum(state: dict[str, Any]) -> str:
    payload = canonical_json(integrity_state(state)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def legacy_integrity_checksum(state: dict[str, Any]) -> str:
    return hashlib.sha256(json_dump(integrity_state(state), compact=True).encode("utf-8")).hexdigest()


def journal_record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


def legacy_journal_record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(json_dump(record, compact=True).encode("utf-8")).hexdigest()


def journal_checkpoint_payload(state: dict[str, Any]) -> dict[str, Any]:
    return integrity_state(state)


def journal_delta_payload(state: dict[str, Any]) -> dict[str, Any]:
    watermark = safe_integer(state.get("_journal_event_seq"), maximum=10**18) or 0
    events = [
        copy.deepcopy(item) for item in state.get("events", [])
        if isinstance(item, dict) and (safe_integer(item.get("seq"), maximum=10**18) or 0) > watermark
    ]
    replace: dict[str, Any] = {}
    preserve: list[str] = []
    for key, value in state.items():
        if key == "events" or key in JOURNAL_INTERNAL_KEYS or key in JOURNAL_IMMUTABLE_KEYS:
            continue
        if key == "_scan_cache" and not state.get("_scan_cache_dirty"):
            preserve.append(key)
            continue
        replace[key] = copy.deepcopy(value)
    return {
        "events": events,
        "retained_seqs": [
            safe_integer(item.get("seq"), maximum=10**18) or 0
            for item in state.get("events", []) if isinstance(item, dict)
        ],
        "replace": replace,
        "present": sorted(replace),
        "preserve": preserve,
    }


def write_journal(root: Path, state: dict[str, Any]) -> None:
    """Write-ahead a bounded hash-chained recovery record for this revision."""
    path = trace_dir(root) / JOURNAL_NAME
    metadata = safe_file_metadata(path)
    previous = str(state.get("_journal_hash") or "")
    integrity = state.get("integrity") if isinstance(state.get("integrity"), dict) else {}
    integrity_head = str(integrity.get("head") or "")
    if metadata is not None and not previous and integrity_head:
        # The cursor is reconstructible from the verified checkpoint. Losing an
        # excluded private cursor must never silently reset the same trace's chain.
        previous = integrity_head
    if metadata is not None and previous and integrity_head and previous != integrity_head:
        raise SystemExit("Trace journal cursor does not match the verified integrity head.")
    checkpoint = metadata is None or state.pop("_journal_torn_tail", False) is True
    if metadata is not None and not checkpoint and not previous:
        # A new trace legitimately replaces the prior generation's journal. All
        # same-generation mutations arrive through load_state(), which restores
        # the verified cursor above.
        checkpoint = True
    payload = journal_checkpoint_payload(state) if checkpoint else journal_delta_payload(state)
    record: dict[str, Any] = {
        "version": 1,
        "kind": "checkpoint" if checkpoint else "delta",
        "trace_id": str(state.get("trace_id") or ""),
        "revision": safe_integer(state.get("revision"), maximum=10**12) or 0,
        "at": now_iso(),
        "prev": "" if checkpoint else previous,
        "checksum": integrity_checksum(state),
        "payload": payload,
    }
    record_hash = journal_record_hash(record)
    line = json_dump({**record, "hash": record_hash}, compact=True) + "\n"
    if metadata is not None and metadata.st_size + len(line.encode("utf-8")) > MAX_JOURNAL_BYTES:
        record["kind"] = "checkpoint"
        record["prev"] = ""
        record["payload"] = journal_checkpoint_payload(state)
        record_hash = journal_record_hash(record)
        line = json_dump({**record, "hash": record_hash}, compact=True) + "\n"
        checkpoint = True
    if checkpoint:
        atomic_write(path, line, private_parent=True)
    else:
        secure_append(path, line, max_bytes=MAX_JOURNAL_BYTES)
    events = [item for item in state.get("events", []) if isinstance(item, dict)]
    state["_journal_hash"] = record_hash
    state["_journal_revision"] = record["revision"]
    state["_journal_event_seq"] = max(
        (safe_integer(item.get("seq"), maximum=10**18) or 0 for item in events), default=0,
    )
    state.pop("_scan_cache_dirty", None)
    state["integrity"] = {
        "algorithm": "sha256-chain-v1", "head": record_hash,
        "state_checksum": record["checksum"], "journal_revision": record["revision"],
    }


def recover_journal(root: Path) -> dict[str, Any]:
    path = trace_dir(root) / JOURNAL_NAME
    if safe_file_metadata(path) is None:
        raise SystemExit("Trace state is unreadable and no recovery journal is available.")
    raw = secure_read_text(path, max_bytes=MAX_JOURNAL_BYTES)
    recovered: dict[str, Any] | None = None
    expected_hash = ""
    accepted = 0
    prior_revision: int | None = None
    torn_tail = False
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        last_unterminated = index == len(lines) - 1 and not raw.endswith("\n")
        try:
            if not line or len(line.encode("utf-8")) > MAX_STATE_BYTES + MAX_JSONL_BYTES:
                raise ValueError("invalid journal record size")
            record = json.loads(line, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (json.JSONDecodeError, RecursionError, ValueError):
            if last_unterminated:
                torn_tail = True
                break
            raise SystemExit("Trace recovery journal is corrupt before its final record.") from None
        try:
            if not isinstance(record, dict):
                raise ValueError("record is not an object")
            supplied_hash = record.pop("hash", None)
            if not isinstance(supplied_hash, str) or supplied_hash not in {
                journal_record_hash(record), legacy_journal_record_hash(record),
            }:
                raise ValueError("record hash mismatch")
            revision = safe_integer(record.get("revision"), maximum=10**12)
            if revision is None:
                raise ValueError("invalid revision")
            kind = record.get("kind")
            if kind == "checkpoint":
                if accepted or record.get("prev") != "" or not isinstance(record.get("payload"), dict):
                    raise ValueError("unexpected checkpoint")
                candidate = copy.deepcopy(record["payload"])
            elif kind == "delta" and recovered is not None:
                if (
                    record.get("prev") != expected_hash
                    or not isinstance(record.get("payload"), dict)
                    or prior_revision is None or revision != prior_revision + 1
                ):
                    raise ValueError("non-contiguous delta")
                candidate = copy.deepcopy(recovered)
                payload = record["payload"]
                replacement = payload.get("replace")
                present = payload.get("present")
                preserve = payload.get("preserve") if isinstance(payload.get("preserve"), list) else []
                if not isinstance(replacement, dict) or not isinstance(present, list):
                    raise ValueError("invalid delta payload")
                mutable_existing = [
                    key for key in candidate
                    if key not in {"events", *JOURNAL_IMMUTABLE_KEYS} and key not in JOURNAL_INTERNAL_KEYS
                ]
                present_keys = {key for key in present if isinstance(key, str)}
                present_keys.update(key for key in preserve if isinstance(key, str))
                for key in mutable_existing:
                    if key not in present_keys:
                        candidate.pop(key, None)
                for key, value in replacement.items():
                    if isinstance(key, str) and key not in JOURNAL_INTERNAL_KEYS and key != "events":
                        candidate[key] = copy.deepcopy(value)
                prior_events = candidate.get("events") if isinstance(candidate.get("events"), list) else []
                new_events = payload.get("events") if isinstance(payload.get("events"), list) else []
                event_map = {
                    safe_integer(item.get("seq"), maximum=10**18) or 0: item
                    for item in [*prior_events, *new_events] if isinstance(item, dict)
                }
                retained = payload.get("retained_seqs") if isinstance(payload.get("retained_seqs"), list) else []
                candidate["events"] = [
                    event_map[seq] for raw_seq in retained
                    if (seq := safe_integer(raw_seq, maximum=10**18)) in event_map
                ]
            else:
                raise ValueError("invalid record kind")
            if (
                not isinstance(candidate, dict)
                or record.get("trace_id") != candidate.get("trace_id")
                or safe_integer(candidate.get("revision"), maximum=10**12) != revision
            ):
                raise ValueError("record identity mismatch")
            if record.get("checksum") not in {
                integrity_checksum(candidate), legacy_integrity_checksum(candidate),
            }:
                raise ValueError("state checksum mismatch")
        except (TypeError, ValueError):
            raise SystemExit("Trace recovery journal failed integrity or revision validation.") from None
        recovered = candidate
        expected_hash = supplied_hash
        prior_revision = revision
        accepted += 1
    if raw and not raw.endswith("\n"):
        # Even a complete, hash-valid JSON record is not durably framed until its
        # terminating newline exists. Seal it by checkpoint replacement before
        # any future append so two JSON objects can never be concatenated.
        torn_tail = True
    if recovered is None or not accepted:
        raise SystemExit("Trace state is unreadable and its recovery journal is invalid.")
    recovered["_journal_hash"] = expected_hash
    recovered["_journal_revision"] = safe_integer(recovered.get("revision"), maximum=10**12) or 0
    recovered["_journal_event_seq"] = max(
        (safe_integer(item.get("seq"), maximum=10**18) or 0 for item in recovered.get("events", []) if isinstance(item, dict)),
        default=0,
    )
    recovered["_recovered_from_journal"] = True
    if torn_tail:
        recovered["_journal_torn_tail"] = True
    recovered["integrity"] = {
        "algorithm": "sha256-chain-v1", "head": expected_hash,
        "state_checksum": integrity_checksum(recovered),
        "journal_revision": recovered["_journal_revision"], "recovered": True,
    }
    return recovered


@contextmanager
def state_lock(root: Path) -> Iterator[None]:
    """Serialize trace mutations, including concurrently launched Codex hooks."""
    directory = ensure_safe_directory(trace_dir(root), private=True)
    lock_path = directory / ".trace.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor: int | None = None
    descriptor: int | None = None
    try:
        if os.name == "nt":
            existing = safe_file_metadata(lock_path)
            if existing is not None and (stat.S_ISLNK(existing.st_mode) or is_windows_reparse(existing) or not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1):
                raise SystemExit(f"Refusing unsafe trace lock: {lock_path}")
            descriptor = os.open(lock_path, flags, 0o600)
        else:
            directory_descriptor = open_safe_directory_fd(directory)
            descriptor = os.open(lock_path.name, flags, 0o600, dir_fd=directory_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SystemExit(f"Refusing unsafe trace lock: {lock_path}")
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        else:
            try:
                os.chmod(lock_path, 0o600, follow_symlinks=False)
            except (NotImplementedError, OSError):
                pass
        handle = os.fdopen(descriptor, "r+b", closefd=True)
        descriptor = None
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise SystemExit(f"Cannot safely lock trace state: {exc}") from exc
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise
    try:
        if os.name == "nt":
            import msvcrt
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        if os.name != "nt":
            _LOCK_CONTEXT.trace_path = directory.absolute()
            _LOCK_CONTEXT.trace_fd = directory_descriptor
        yield
    finally:
        _LOCK_CONTEXT.trace_path = None
        _LOCK_CONTEXT.trace_fd = None
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            if directory_descriptor is not None:
                os.close(directory_descriptor)


def load_state(root: Path) -> dict[str, Any]:
    path = trace_dir(root) / STATE_NAME
    if safe_file_metadata(path) is None:
        state = recover_journal(root)
    else:
        try:
            raw = secure_read_text(path)
            state = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (json.JSONDecodeError, RecursionError, ValueError):
            state = recover_journal(root)
    if not isinstance(state, dict):
        raise SystemExit("Trace state must be a JSON object.")
    integrity = state.get("integrity")
    current_schema = safe_integer(state.get("schema_version"), maximum=10**6) or 0
    state_revision = safe_integer(state.get("revision"), maximum=10**12) or 0
    has_checksum = isinstance(integrity, dict) and isinstance(integrity.get("state_checksum"), str)
    integrity_valid = bool(
        isinstance(integrity, dict)
        and integrity.get("algorithm") == "sha256-chain-v1"
        and isinstance(integrity.get("head"), str) and len(integrity["head"]) == 64
        and safe_integer(integrity.get("journal_revision"), maximum=10**12) == state_revision
        and has_checksum and integrity["state_checksum"] in {
            integrity_checksum(state), legacy_integrity_checksum(state),
        }
    )
    # A checksum-less legacy checkpoint is accepted only when no recovery
    # journal exists. Once a journal exists, mutable schema metadata cannot be
    # used to downgrade the integrity gate.
    state_valid = bool(integrity_valid or (current_schema < SCHEMA_VERSION and not has_checksum))
    journal_path = trace_dir(root) / JOURNAL_NAME
    if safe_file_metadata(journal_path) is not None:
        recovered = recover_journal(root)
        recovered_revision = safe_integer(recovered.get("revision"), maximum=10**12) or 0
        recovered_integrity = recovered.get("integrity") if isinstance(recovered.get("integrity"), dict) else {}
        recovered_head = str(recovered_integrity.get("head") or "")
        state_head = str(integrity.get("head") or "") if isinstance(integrity, dict) else ""
        state_valid = integrity_valid
        if not state_valid or recovered_revision > state_revision or (
            recovered_revision == state_revision and state_head != recovered_head
        ):
            state = recovered
            state_valid = True
        elif state_revision > recovered_revision:
            raise SystemExit("Trace checkpoint revision is newer than its verified recovery journal.")
        else:
            state["_journal_hash"] = recovered_head
            state["_journal_revision"] = recovered_revision
            state["_journal_event_seq"] = recovered.get("_journal_event_seq", 0)
        if recovered.get("_journal_torn_tail") is True:
            state["_journal_torn_tail"] = True
    if not state_valid:
        raise SystemExit("Trace state checksum does not match and no newer valid journal state is available.")
    state.setdefault("schema_version", 1)
    state.setdefault("privacy_mode", "standard")
    if not isinstance(state.get("observability"), dict):
        state["observability"] = {"hooks": False, "ingest_sources": []}
    for key in ("events", "plan", "latest_files", "token_history", "_token_sample_ids", "_generated_paths", "_stream_plan_ids"):
        if not isinstance(state.get(key), list):
            state[key] = []
    compact_events(state)
    state["plan"] = [item for item in state["plan"] if isinstance(item, dict)][:500]
    state["latest_files"] = [item for item in state["latest_files"] if isinstance(item, dict)][:MAX_PUBLIC_CHANGES]
    state["token_history"] = [item for item in state["token_history"] if isinstance(item, dict)][-MAX_TOKEN_HISTORY:]
    state["_token_sample_ids"] = [item for item in state["_token_sample_ids"] if isinstance(item, str)][-MAX_TOKEN_SAMPLE_IDS:]
    state["_generated_paths"] = [item for item in state["_generated_paths"] if isinstance(item, str)][:2_000]
    state["_stream_plan_ids"] = [item for item in state["_stream_plan_ids"] if isinstance(item, str)][:500]
    for key in ("baseline", "git_baseline", "token_usage", "aggregates", "snapshot_policy", "_auto_snapshot", "_token_adapter_state", "_pending_observations", "_scan_cache", "_actor_aliases"):
        if not isinstance(state.get(key), dict):
            state[key] = {}
    state["_token_adapter_state"] = normalize_token_adapter_state(
        state["_token_adapter_state"], state.get("_token_sample_ids", []),
    )
    state["baseline"] = {key: value for key, value in state["baseline"].items() if isinstance(key, str) and isinstance(value, dict)}
    state["_pending_observations"] = {key: value for key, value in state["_pending_observations"].items() if isinstance(key, str) and isinstance(value, dict)}
    started = parse_iso(state.get("started_at"))
    fallback_generation = int(started.timestamp() * 1_000_000_000) if started else time.time_ns()
    state["generation_order"] = safe_integer(state.get("generation_order"), maximum=10**30) or fallback_generation
    sessions = state.setdefault("_hook_sessions", {})
    if not isinstance(sessions, dict):
        sessions = {}
        state["_hook_sessions"] = sessions
    legacy_session = safe_text(state.get("_hook_session_id"), 160)
    if legacy_session and legacy_session not in sessions:
        sessions[legacy_session] = {"trace_id": str(state.get("trace_id") or ""), "migrated": True}
    state.pop("_hook_session_id", None)
    state["revision"] = safe_integer(state.get("revision"), maximum=10**12) or 0
    state["_scan_generation"] = safe_integer(state.get("_scan_generation"), maximum=10**12) or 0
    if state.pop("_recovered_from_journal", False):
        observability = state.setdefault("observability", {})
        observability["journal_recoveries"] = (safe_integer(observability.get("journal_recoveries"), maximum=10**12) or 0) + 1
    return state


def require_active(state: dict[str, Any]) -> None:
    if state.get("status") != "active":
        raise SystemExit("This trace is already finished. Run 'init' to start a new trace.")


def private_path_alias(path: str, salt: str = "") -> str:
    digest = hashlib.sha256(f"{salt}\0{path}".encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"file-{digest}"


def normalized_observed_path(value: Any) -> str:
    raw = safe_text(value, 1_000).replace("\\", "/").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if raw.startswith("./"):
        raw = raw[2:]
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    if not raw or raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or ".." in parts:
        return private_path_alias(raw or "external-file")
    return "/".join(parts)[:1_000]


def empty_aggregates() -> dict[str, Any]:
    return {
        "total_events": 0, "checks": {"total": 0, "passed": 0, "failed": 0},
        "tools": 0, "agents": 0, "observed_duration_ms": 0,
        "files_changed": 0, "added": 0, "deleted": 0,
        "diff_quality": "metadata", "complete": True,
    }


def ensure_aggregates(state: dict[str, Any]) -> dict[str, Any]:
    existing = state.get("aggregates")
    if isinstance(existing, dict) and safe_integer(existing.get("total_events"), maximum=10**12) is not None:
        return existing
    aggregate = empty_aggregates()
    lanes: set[str] = set()
    for event in state.get("events", []):
        if not isinstance(event, dict):
            continue
        aggregate["total_events"] += 1
        kind = event.get("kind")
        if kind in {"command", "test", "build", "verify"}:
            aggregate["checks"]["total"] += 1
            bucket = "passed" if event.get("status") == "success" else "failed"
            aggregate["checks"][bucket] += 1
        if kind == "tool":
            aggregate["tools"] += 1
        actor = event.get("actor")
        if isinstance(actor, dict) and isinstance(actor.get("lane"), str) and actor.get("lane") != "main":
            lanes.add(actor["lane"])
        aggregate["observed_duration_ms"] += safe_integer(event.get("duration_ms"), maximum=10**15) or 0
    aggregate["agents"] = len(lanes)
    if (state.get("observability") or {}).get("events_dropped"):
        aggregate["complete"] = False
    latest = state.get("latest_files") if isinstance(state.get("latest_files"), list) else []
    aggregate["files_changed"] = len(latest)
    aggregate["added"] = sum(safe_integer(item.get("added")) or 0 for item in latest if isinstance(item, dict))
    aggregate["deleted"] = sum(safe_integer(item.get("deleted")) or 0 for item in latest if isinstance(item, dict))
    state["aggregates"] = aggregate
    state["_aggregate_agent_lanes"] = sorted(lanes)
    return aggregate


def update_aggregates_for_event(state: dict[str, Any], event: dict[str, Any]) -> None:
    aggregate = ensure_aggregates(state)
    aggregate["total_events"] = (safe_integer(aggregate.get("total_events"), maximum=10**12) or 0) + 1
    kind = event.get("kind")
    if kind in {"command", "test", "build", "verify"}:
        checks = aggregate.setdefault("checks", {})
        checks["total"] = (safe_integer(checks.get("total"), maximum=10**12) or 0) + 1
        bucket = "passed" if event.get("status") == "success" else "failed"
        checks[bucket] = (safe_integer(checks.get(bucket), maximum=10**12) or 0) + 1
    if kind == "tool":
        aggregate["tools"] = (safe_integer(aggregate.get("tools"), maximum=10**12) or 0) + 1
    actor = event.get("actor")
    if isinstance(actor, dict) and isinstance(actor.get("lane"), str) and actor.get("lane") != "main":
        lanes = state.setdefault("_aggregate_agent_lanes", [])
        if actor["lane"] not in lanes:
            lanes.append(actor["lane"])
        aggregate["agents"] = len(lanes)
    aggregate["observed_duration_ms"] = (
        (safe_integer(aggregate.get("observed_duration_ms"), maximum=10**15) or 0)
        + (safe_integer(event.get("duration_ms"), maximum=10**15) or 0)
    )


def actor_for(state: dict[str, Any], raw_id: Any, role: Any = "") -> dict[str, str] | None:
    identifier = safe_text(str(raw_id or ""), 160)
    if not identifier:
        return None
    aliases = state.setdefault("_actor_aliases", {})
    lane = aliases.get(identifier)
    if not isinstance(lane, str):
        lane = f"agent-{len(aliases) + 1}"
        aliases[identifier] = lane
    actor = {"lane": lane, "type": "agent", "parent_lane": "main"}
    safe_role = safe_text(str(role or ""), 80)
    if safe_role:
        actor["role"] = safe_role
    return actor


def public_state(state: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "schema_version", "generation_order", "title", "project_name", "lang",
        "started_at", "updated_at", "finished_at", "status", "summary",
        "plan", "events", "latest_files", "token_usage", "token_history",
        "aggregates", "integrity", "privacy_mode", "observability", "revision",
    )
    public = copy.deepcopy({key: state.get(key) for key in allowed if key in state})
    public["generation"] = hashlib.sha256(str(state.get("trace_id") or "").encode()).hexdigest()[:16]
    mode = public.get("privacy_mode", "standard")
    raw_observability = public.get("observability") if isinstance(public.get("observability"), dict) else {}
    public["observability"] = {
        "hooks": raw_observability.get("hooks") is True,
        "hooks_ever_installed": raw_observability.get("hooks_ever_installed") is True,
        "ingest_sources": [source for source in raw_observability.get("ingest_sources", []) if source in {"app-server", "codex-jsonl"}][:8]
        if isinstance(raw_observability.get("ingest_sources"), list) else [],
        "events_dropped": safe_integer(raw_observability.get("events_dropped"), maximum=10**12) or 0,
        "failures_dropped": safe_integer(raw_observability.get("failures_dropped"), maximum=10**12) or 0,
        "timeline_truncated": raw_observability.get("timeline_truncated") is True,
        "journal_recoveries": safe_integer(raw_observability.get("journal_recoveries"), maximum=10**12) or 0,
        "automatic_snapshots": safe_integer(raw_observability.get("automatic_snapshots"), maximum=10**12) or 0,
        "auto_snapshot_failures": safe_integer(raw_observability.get("auto_snapshot_failures"), maximum=10**12) or 0,
        "last_scan": copy.deepcopy(raw_observability.get("last_scan")) if isinstance(raw_observability.get("last_scan"), dict) else {},
    }
    snapshot_policy = state.get("snapshot_policy") if isinstance(state.get("snapshot_policy"), dict) else {}
    auto_snapshot = state.get("_auto_snapshot") if isinstance(state.get("_auto_snapshot"), dict) else {}
    public["observability"].update({
        "auto_snapshot_enabled": snapshot_policy.get("mode", "auto") == "auto",
        "auto_snapshot_pending": auto_snapshot.get("pending_generation") is not None,
        "auto_snapshot_debounce_ms": min(10_000, max(100, safe_integer(snapshot_policy.get("debounce_ms"), maximum=10_000) or AUTO_SNAPSHOT_DEBOUNCE_MS)),
        "auto_snapshot_last_completed_at": safe_text(auto_snapshot.get("last_completed_at"), 64),
    })

    alias_salt = str(state.get("trace_id") or "private")

    def filter_files(files: Any) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        if not isinstance(files, list):
            return result
        for raw in files[:MAX_PUBLIC_CHANGES]:
            if not isinstance(raw, dict):
                continue
            path = normalized_observed_path(raw.get("path"))
            if mode == "strict" and path:
                path = private_path_alias(path, alias_salt)
            result.append({
                "path": path,
                "status": safe_text(raw.get("status"), 40),
                "added": safe_integer(raw.get("added")) or 0,
                "deleted": safe_integer(raw.get("deleted")) or 0,
                "binary": raw.get("binary") is True,
            })
        return result

    public["latest_files"] = filter_files(public.get("latest_files"))
    strict_plan_aliases: dict[str, str] = {}
    if mode == "strict":
        for raw in public.get("plan") or []:
            if isinstance(raw, dict) and isinstance(raw.get("id"), str) and raw["id"] not in strict_plan_aliases:
                strict_plan_aliases[raw["id"]] = f"step-{len(strict_plan_aliases) + 1}"
        for raw_event in public.get("events") or []:
            data = raw_event.get("data") if isinstance(raw_event, dict) else None
            raw_id = data.get("plan_id") if isinstance(data, dict) else None
            if isinstance(raw_id, str) and raw_id not in strict_plan_aliases:
                strict_plan_aliases[raw_id] = f"step-{len(strict_plan_aliases) + 1}"
    safe_event_kinds = {
        "session", "plan", "edit", "snapshot", "command", "test", "build", "verify",
        "tool", "approval", "error", "turn", "agent", "context", "tokens", "finish", "note",
    }
    for event in public.get("events") or []:
        if not isinstance(event, dict):
            continue
        data = event.get("data")
        actor = event.get("actor")
        if isinstance(actor, dict):
            lane = safe_text(actor.get("lane"), 40)
            if re.fullmatch(r"(?:main|agent-\d+)", lane):
                filtered_actor = {"lane": lane, "type": "agent" if lane != "main" else "main", "parent_lane": "main"}
                if mode != "strict" and actor.get("role"):
                    filtered_actor["role"] = safe_text(actor.get("role"), 80)
                event["actor"] = filtered_actor
            else:
                event.pop("actor", None)
        if isinstance(data, dict):
            for identifier_key in ("agent_id", "turn_id", "tool_use_id", "session_id", "thread_id"):
                data.pop(identifier_key, None)
        if isinstance(data, dict) and mode != "demo":
            data.pop("output_excerpt", None)
        if mode == "strict":
            filtered: dict[str, Any] = {}
            if isinstance(data, dict):
                for key in ("file_count", "added", "deleted", "diff_quality", "truncated", "exit_code", "timed_out", "tests", "plan_status"):
                    if key in data and isinstance(data[key], (str, int, float, bool, dict)):
                        filtered[key] = copy.deepcopy(data[key])
                if "files" in data:
                    filtered["files"] = filter_files(data.get("files"))
                if isinstance(data.get("token_usage"), dict):
                    filtered["token_usage"] = sanitize_public_token_usage(data["token_usage"], strict=True)
                raw_plan_id = data.get("plan_id")
                if isinstance(raw_plan_id, str) and raw_plan_id in strict_plan_aliases:
                    alias = strict_plan_aliases[raw_plan_id]
                    filtered["plan_id"] = alias
                    step_number = alias.rsplit("-", 1)[-1]
                    filtered["plan_title"] = localized(state, f"Step {step_number}", f"步骤 {step_number}")
            if filtered:
                event["data"] = filtered
            else:
                event.pop("data", None)
            canonical_kind = safe_text(event.get("kind"), 40).lower()
            if canonical_kind not in safe_event_kinds:
                canonical_kind = "activity"
            event["kind"] = canonical_kind
            event["title"] = localized(state, f"{canonical_kind.title()} update", "活动更新" if canonical_kind == "activity" else f"{canonical_kind} 更新")
            event["detail"] = ""
    if mode == "strict":
        public["project_name"] = "project"
        public["title"] = localized(state, "Codex build trace", "Codex 编码记录")
        public["summary"] = localized(state, "Trace completed." if public.get("status") == "completed" else "", "记录已完成。" if public.get("status") == "completed" else "")
        anonymized_plan = []
        for index, raw in enumerate(public.get("plan") or [], 1):
            if not isinstance(raw, dict):
                continue
            alias = strict_plan_aliases.get(str(raw.get("id") or ""), f"step-{index}")
            step_number = alias.rsplit("-", 1)[-1]
            anonymized_plan.append({
                "id": alias,
                "title": localized(state, f"Step {step_number}", f"步骤 {step_number}"),
                "status": raw.get("status"),
                "updated_at": raw.get("updated_at"),
            })
        public["plan"] = anonymized_plan
    public["token_usage"] = sanitize_public_token_usage(public.get("token_usage"), strict=mode == "strict")
    public["token_history"] = sanitize_token_history(public.get("token_history"))
    public["token_usage"]["trends"] = token_trends(public["token_history"])
    public["aggregates"] = sanitize_aggregates(ensure_aggregates(state))
    integrity = state.get("integrity") if isinstance(state.get("integrity"), dict) else {}
    public["integrity"] = {
        "algorithm": "sha256-chain-v1",
        "status": "recovered" if integrity.get("recovered") is True else "verified" if integrity.get("state_checksum") in {integrity_checksum(state), legacy_integrity_checksum(state)} else "unverified",
        "journal_revision": safe_integer(integrity.get("journal_revision"), maximum=10**12) or 0,
        "recovered": integrity.get("recovered") is True,
    }
    public["privacy"] = "Observable metadata only; known sensitive text is minimized and redacted."
    return public


def public_run_summary(state: dict[str, Any]) -> dict[str, Any]:
    aggregate = sanitize_aggregates(ensure_aggregates(state))
    usage = sanitize_public_token_usage(state.get("token_usage"), strict=True)
    summary = {
        "generation": hashlib.sha256(str(state.get("trace_id") or "").encode()).hexdigest()[:16],
        "order": safe_integer(state.get("generation_order"), maximum=10**30) or 0,
        "started_at": safe_text(state.get("started_at"), 64),
        "finished_at": safe_text(state.get("finished_at"), 64),
        "status": state.get("status") if state.get("status") in {"active", "completed", "failed"} else "unknown",
        "complete": aggregate.get("complete") is True,
        "metrics": {
            **aggregate,
            "model_input_tokens": safe_integer(usage.get("model_input_tokens")),
            "model_input_quality": (usage.get("field_quality") or {}).get("model_input_tokens", usage.get("quality", "unavailable")),
            "effective_user_tokens": safe_integer(usage.get("effective_user_tokens")),
            "saved_tokens": safe_integer(usage.get("saved_tokens")),
        },
    }
    return summary


def normalize_history(value: Any) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    raw_runs = value.get("runs") if isinstance(value, dict) and isinstance(value.get("runs"), list) else []
    for raw in raw_runs[-MAX_ARCHIVES:]:
        if not isinstance(raw, dict) or not isinstance(raw.get("metrics"), dict):
            continue
        metrics = raw["metrics"]
        aggregate = sanitize_aggregates(metrics)
        runs.append({
            "generation": safe_text(raw.get("generation"), 32),
            "order": safe_integer(raw.get("order"), maximum=10**30) or 0,
            "started_at": safe_text(raw.get("started_at"), 64),
            "finished_at": safe_text(raw.get("finished_at"), 64),
            "status": raw.get("status") if raw.get("status") in {"active", "completed", "failed", "unknown"} else "unknown",
            "complete": raw.get("complete") is True,
            "metrics": {
                **aggregate,
                "model_input_tokens": safe_integer(metrics.get("model_input_tokens")),
                "model_input_quality": metrics.get("model_input_quality") if metrics.get("model_input_quality") in {"actual", "estimated", "derived", "mixed", "unavailable"} else "unavailable",
                "effective_user_tokens": safe_integer(metrics.get("effective_user_tokens")),
                "saved_tokens": safe_integer(metrics.get("saved_tokens")),
            },
        })
    return {"schema_version": 1, "runs": runs}


def load_history(directory: Path) -> dict[str, Any]:
    path = directory / HISTORY_STATE_NAME
    if safe_file_metadata(path) is None:
        return {"schema_version": 1, "runs": []}
    try:
        raw = json.loads(secure_read_text(path, max_bytes=4 * 1024 * 1024), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SystemExit(f"Cannot read trace history: {exc}") from exc
    return normalize_history(raw)


def save_history(directory: Path, history: dict[str, Any]) -> None:
    normalized = normalize_history(history)
    atomic_write(directory / HISTORY_STATE_NAME, json_dump(normalized, indent=2) + "\n", private_parent=True)
    atomic_write(
        directory / HISTORY_PUBLIC_NAME,
        "window.CODEX_BUILD_HISTORY=" + json_for_script(normalized) + ";\n",
        private_parent=True,
    )


def append_history(directory: Path, state: dict[str, Any]) -> None:
    history = load_history(directory)
    summary = public_run_summary(state)
    runs = [item for item in history["runs"] if item.get("generation") != summary["generation"]]
    runs.append(summary)
    history["runs"] = sorted(runs, key=lambda item: int(item.get("order") or 0))[-MAX_ARCHIVES:]
    save_history(directory, history)


def repair_public_artifacts(root: Path, state: dict[str, Any]) -> None:
    install_viewer(root)
    public = public_state(state)
    atomic_write(
        trace_dir(root) / PUBLIC_NAME,
        "window.CODEX_BUILD_TRACE=" + json_for_script(public)
        + ";if(window.__codexTraceReceive){window.__codexTraceReceive(window.CODEX_BUILD_TRACE);}\n",
        private_parent=True,
    )
    atomic_write(
        trace_dir(root) / META_NAME,
        "window.CODEX_BUILD_META=" + json_for_script({
            "generation": public.get("generation"), "revision": public.get("revision"),
        }) + ";if(window.__codexTraceMeta){window.__codexTraceMeta(window.CODEX_BUILD_META);}\n",
        private_parent=True,
    )


def save_state(root: Path, state: dict[str, Any]) -> None:
    compact_events(state)
    state["schema_version"] = SCHEMA_VERSION
    state["updated_at"] = now_iso()
    state["revision"] = int(state.get("revision", 0)) + 1
    directory = trace_dir(root)
    install_viewer(root)
    ensure_aggregates(state)
    preflight = json_dump(state, indent=2) + "\n"
    if len(preflight.encode("utf-8")) > MAX_STATE_BYTES:
        raise SystemExit(f"Trace state would exceed the {MAX_STATE_BYTES}-byte safety limit; reduce captured events or start a new trace.")
    write_journal(root, state)
    serialized = json_dump(state, indent=2) + "\n"
    if len(serialized.encode("utf-8")) > MAX_STATE_BYTES:
        raise SystemExit(f"Trace state would exceed the {MAX_STATE_BYTES}-byte safety limit; reduce captured events or start a new trace.")
    atomic_write(directory / STATE_NAME, serialized, private_parent=True)
    repair_public_artifacts(root, state)
    if safe_file_metadata(directory / HISTORY_PUBLIC_NAME) is None:
        save_history(directory, {"schema_version": 1, "runs": []})


def install_viewer(root: Path) -> None:
    source = Path(__file__).resolve().parent.parent / "assets" / "viewer.html"
    if not source.exists():
        raise SystemExit(f"Viewer asset is missing: {source}")
    destination = trace_dir(root) / VIEWER_NAME
    atomic_write(destination, source.read_text(encoding="utf-8"), private_parent=True)


def install_trace_gitignore(root: Path) -> None:
    """Keep generated trace artifacts out of Git without touching root ignore rules."""
    destination = trace_dir(root) / ".gitignore"
    atomic_write(destination, "*\n", private_parent=True)


def add_event(
    state: dict[str, Any], kind: str, title: str, detail: str = "",
    status: str = "info", data: dict[str, Any] | None = None,
    duration_ms: int | None = None, actor: dict[str, str] | None = None,
) -> dict[str, Any]:
    ensure_aggregates(state)
    events = state.setdefault("events", [])
    next_seq = int(state.get("_next_event_seq") or (max((int(item.get("seq", 0)) for item in events if isinstance(item, dict)), default=0) + 1))
    event: dict[str, Any] = {
        "seq": next_seq,
        "at": now_iso(),
        "kind": safe_text(kind, 40) or "note",
        "title": safe_text(title, 240) or "Update",
        "detail": safe_text(detail),
        "status": safe_text(status, 40) or "info",
    }
    if data:
        event["data"] = data
    if duration_ms is not None:
        event["duration_ms"] = max(0, int(duration_ms))
    if actor:
        event["actor"] = copy.deepcopy(actor)
    events.append(event)
    state["_next_event_seq"] = next_seq + 1
    update_aggregates_for_event(state, event)
    return event


def compact_events(state: dict[str, Any]) -> None:
    """Bound the timeline in one linear pass while preferring failure evidence."""
    raw_events = state.get("events")
    if not isinstance(raw_events, list):
        state["events"] = []
        return
    events = [item for item in raw_events if isinstance(item, dict)]
    invalid_dropped = len(raw_events) - len(events)
    if len(events) <= MAX_EVENTS and not invalid_dropped:
        state["events"] = events
        return
    failure_indices = [index for index, item in enumerate(events) if item.get("status") == "failure"]
    if len(failure_indices) >= MAX_EVENTS:
        keep_indices = failure_indices[-MAX_EVENTS:]
    else:
        remaining = MAX_EVENTS - len(failure_indices)
        non_failure_indices = [index for index, item in enumerate(events) if item.get("status") != "failure"]
        keep_indices = sorted(failure_indices + non_failure_indices[-remaining:])
    keep = set(keep_indices)
    removed = [item for index, item in enumerate(events) if index not in keep]
    state["events"] = [events[index] for index in keep_indices]
    dropped = invalid_dropped + len(removed)
    if dropped:
        observability = state.setdefault("observability", {})
        prior_dropped = safe_integer(observability.get("events_dropped"), maximum=10**12) or 0
        prior_failures = safe_integer(observability.get("failures_dropped"), maximum=10**12) or 0
        observability["events_dropped"] = prior_dropped + dropped
        observability["failures_dropped"] = prior_failures + sum(1 for item in removed if item.get("status") == "failure")
        observability["timeline_truncated"] = True


def safe_integer(value: Any, *, maximum: int = MAX_TOKEN_VALUE) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        return None
    integer = int(value)
    if integer < 0 or integer > maximum:
        return None
    return integer


def nonnegative(value: int | None, label: str) -> int | None:
    if value is None:
        return None
    integer = safe_integer(value)
    if integer is None:
        raise SystemExit(f"{label} must be a whole number from 0 to {MAX_TOKEN_VALUE:,}.")
    return integer


def sanitize_public_token_usage(value: Any, *, strict: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        return empty_token_usage()
    allowed = {
        "quality", "source", "method", "updated_at", "field_quality", "field_source", "sources",
        "semantics", "reset",
        "model_input_tokens", "cached_input_tokens", "model_output_tokens", "reasoning_output_tokens",
        "user_visible_tokens", "effective_user_tokens", "candidate_context_tokens",
        "retained_context_tokens", "saved_tokens",
    }
    result = {key: copy.deepcopy(raw) for key, raw in value.items() if key in allowed}
    if strict:
        result["method"] = ""
    return result


def sanitize_token_history(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    allowed_values = {
        "model_input_tokens", "cached_input_tokens", "model_output_tokens", "reasoning_output_tokens",
        "user_visible_tokens", "effective_user_tokens", "candidate_context_tokens",
        "retained_context_tokens", "saved_tokens",
    }
    if not isinstance(value, list):
        return result
    for raw in value[-MAX_TOKEN_HISTORY:]:
        if not isinstance(raw, dict):
            continue
        values = raw.get("values") if isinstance(raw.get("values"), dict) else {}
        deltas = raw.get("deltas") if isinstance(raw.get("deltas"), dict) else {}
        qualities = raw.get("field_quality") if isinstance(raw.get("field_quality"), dict) else {}
        sources = raw.get("field_source") if isinstance(raw.get("field_source"), dict) else {}
        filtered_values = {
            key: integer for key, item in values.items()
            if key in allowed_values and (integer := safe_integer(item)) is not None
        }
        if not filtered_values:
            continue
        filtered_deltas = {
            key: integer for key, item in deltas.items()
            if key in allowed_values and (integer := safe_integer(item)) is not None
        }
        item = {
            "seq": safe_integer(raw.get("seq"), maximum=10**18) or 0,
            "at": safe_text(raw.get("at"), 64),
            "values": filtered_values,
            "field_quality": {key: value for key, value in qualities.items() if key in filtered_values and value in {"actual", "estimated", "derived", "mixed"}},
            "field_source": {key: value for key, value in sources.items() if key in filtered_values and value in {"app-server", "codex-jsonl", "api", "otel", "codex-status", "estimate", "manual", "derived"}},
            "semantics": raw.get("semantics") if raw.get("semantics") in {"snapshot", "cumulative", "delta"} else "snapshot",
            "reset": raw.get("reset") is True,
        }
        if filtered_deltas:
            item["deltas"] = filtered_deltas
        result.append(item)
    return result


def sanitize_aggregates(value: Any) -> dict[str, Any]:
    aggregate = value if isinstance(value, dict) else {}
    checks = aggregate.get("checks") if isinstance(aggregate.get("checks"), dict) else {}
    return {
        "total_events": safe_integer(aggregate.get("total_events"), maximum=10**12) or 0,
        "checks": {
            "total": safe_integer(checks.get("total"), maximum=10**12) or 0,
            "passed": safe_integer(checks.get("passed"), maximum=10**12) or 0,
            "failed": safe_integer(checks.get("failed"), maximum=10**12) or 0,
        },
        "tools": safe_integer(aggregate.get("tools"), maximum=10**12) or 0,
        "agents": safe_integer(aggregate.get("agents"), maximum=10**12) or 0,
        "observed_duration_ms": safe_integer(aggregate.get("observed_duration_ms"), maximum=10**15) or 0,
        "files_changed": safe_integer(aggregate.get("files_changed"), maximum=10**12) or 0,
        "added": safe_integer(aggregate.get("added"), maximum=10**12) or 0,
        "deleted": safe_integer(aggregate.get("deleted"), maximum=10**12) or 0,
        "diff_quality": aggregate.get("diff_quality") if aggregate.get("diff_quality") in {"exact", "net", "metadata", "partial"} else "metadata",
        "complete": aggregate.get("complete") is not False,
    }


def token_quality(field_quality: dict[str, str]) -> str:
    qualities = {value for value in field_quality.values() if value}
    if not qualities:
        return "unavailable"
    if qualities == {"actual"}:
        return "actual"
    if qualities <= {"estimated", "derived"}:
        return "derived" if qualities == {"derived"} else "estimated"
    return "mixed"


def token_trends(history: list[dict[str, Any]]) -> dict[str, Any]:
    actual: list[dict[str, Any]] = []
    estimated: list[dict[str, Any]] = []
    for item in sanitize_token_history(history)[-20:]:
        semantics = item.get("semantics", "snapshot")
        values = item.get("values", {})
        if semantics in {"cumulative", "delta"}:
            values = item.get("deltas", {})
            if item.get("reset") or not values:
                continue
        qualities = {
            value for key, value in item.get("field_quality", {}).items()
            if key in values
        }
        bucket = actual if qualities and qualities <= {"actual"} else estimated
        bucket.append({"seq": item.get("seq"), "at": item.get("at"), "values": values})
    return {"version": 1, "actual": actual, "estimated": estimated}


def is_git_repo(root: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def git_text(root: Path, arguments: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace")


def git_bytes(root: Path, arguments: list[str]) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def git_baseline(root: Path) -> dict[str, Any]:
    if not is_git_repo(root):
        return {"available": False, "clean": False, "head": None}
    head = (git_text(root, ["rev-parse", "HEAD"]) or "").strip() or None
    prefix = (git_text(root, ["rev-parse", "--show-prefix"]) or "").strip()
    status = git_bytes(root, ["status", "--porcelain", "-z", "--untracked-files=normal", "--", "."])
    records = [] if status is None else [record for record in status.split(b"\0") if record]
    relevant = []
    for record in records:
        raw_path = record[3:] if len(record) >= 3 else record
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if not ignored(Path(path)) and path != TRACE_DIR:
            relevant.append(path)
    clean = bool(head and status is not None and not relevant)
    return {"available": bool(head), "clean": clean, "head": head, "prefix": prefix}


def ignored(relative: Path) -> bool:
    return any(part in IGNORE_DIRS for part in relative.parts) or relative.as_posix() in IGNORE_FILES


def git_file_list(root: Path) -> list[str] | None:
    if not is_git_repo(root):
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z", "--", "."],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return [path for path in result.stdout.decode("utf-8", errors="surrogateescape").split("\0") if path]


def walk_file_list(root: Path) -> tuple[list[str], bool]:
    """Return a bounded inventory plus whether enumeration was incomplete."""
    result: list[str] = []
    incomplete = False

    def note_error(_error: OSError) -> None:
        nonlocal incomplete
        incomplete = True

    for current, directories, files in os.walk(root, onerror=note_error):
        directories[:] = [name for name in directories if name not in IGNORE_DIRS]
        base = Path(current)
        for name in files:
            relative = (base / name).relative_to(root)
            if not ignored(relative):
                result.append(relative.as_posix())
            # Read one item past the public cap so exactly MAX_SCAN_FILES can be
            # distinguished from a truncated enumeration.
            if len(result) > MAX_SCAN_FILES:
                return result, True
    return result, incomplete


def _fingerprint_once(path: Path) -> dict[str, Any] | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        metadata = path.stat()
        size = metadata.st_size
        if size > MAX_FILE_BYTES:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                offsets = sorted({0, max(0, size // 2 - 32 * 1024), max(0, size - 64 * 1024)})
                for offset in offsets:
                    handle.seek(offset)
                    digest.update(handle.read(64 * 1024))
            return {
                "hash": f"large:{size}:{digest.hexdigest()}",
                "size": size, "lines": 0, "binary": True, "fingerprint_quality": "sampled",
                "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns,
                "inode": metadata.st_ino, "device": metadata.st_dev, "mode": metadata.st_mode,
            }
        digest = hashlib.sha256()
        lines = 0
        binary = False
        with path.open("rb") as handle:
            while chunk := handle.read(64 * 1024):
                digest.update(chunk)
                if b"\x00" in chunk:
                    binary = True
                if not binary:
                    lines += chunk.count(b"\n")
        if size and not binary:
            with path.open("rb") as handle:
                handle.seek(-1, os.SEEK_END)
                if handle.read(1) != b"\n":
                    lines += 1
        return {
            "hash": digest.hexdigest(), "size": size, "lines": 0 if binary else lines,
            "binary": binary, "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns,
            "inode": metadata.st_ino, "device": metadata.st_dev, "mode": metadata.st_mode,
        }
    except (OSError, ValueError):
        return None


def fingerprint(path: Path) -> dict[str, Any] | None:
    """Fingerprint a stable file image; retry once if metadata changes mid-read."""
    for _ in range(2):
        try:
            before = path.lstat()
        except OSError:
            return None
        item = _fingerprint_once(path)
        if item is None:
            return None
        try:
            after = path.lstat()
        except OSError:
            return None
        before_signature = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_signature = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if before_signature == after_signature:
            return item
    return None


def scan_workspace(root: Path, state: dict[str, Any] | None = None, *, force: bool = False) -> tuple[dict[str, dict[str, Any]], bool]:
    started = time.monotonic()
    git_paths = git_file_list(root)
    if git_paths is not None:
        paths = git_paths
        enumeration_incomplete = False
    else:
        paths, enumeration_incomplete = walk_file_list(root)
    result: dict[str, dict[str, Any]] = {}
    truncated = len(paths) > MAX_SCAN_FILES
    cache = state.get("_scan_cache") if isinstance(state, dict) and isinstance(state.get("_scan_cache"), dict) else {}
    reused = 0
    hashed = 0
    unstable = 0
    for raw in paths[:MAX_SCAN_FILES]:
        relative = Path(raw)
        if relative.is_absolute() or ".." in relative.parts or ignored(relative):
            continue
        target = root / relative
        cached = cache.get(relative.as_posix()) if isinstance(cache.get(relative.as_posix()), dict) else None
        item = None
        if not force and cached is not None:
            try:
                metadata = target.stat()
                if (
                    target.is_file() and not target.is_symlink()
                    and safe_integer(cached.get("size"), maximum=10**15) == metadata.st_size
                    and safe_integer(cached.get("mtime_ns"), maximum=10**30) == metadata.st_mtime_ns
                    and safe_integer(cached.get("ctime_ns"), maximum=10**30) == metadata.st_ctime_ns
                    and safe_integer(cached.get("inode"), maximum=10**30) == metadata.st_ino
                    and safe_integer(cached.get("device"), maximum=10**30) == metadata.st_dev
                    and safe_integer(cached.get("mode"), maximum=10**30) == metadata.st_mode
                ):
                    item = copy.deepcopy(cached)
                    reused += 1
            except OSError:
                item = None
        if item is None:
            item = fingerprint(target)
            hashed += 1
            if item is None:
                unstable += 1
                baseline = state.get("baseline") if isinstance(state, dict) and isinstance(state.get("baseline"), dict) else {}
                fallback = cached if cached is not None else baseline.get(relative.as_posix())
                if isinstance(fallback, dict):
                    item = copy.deepcopy(fallback)
        if item is not None:
            result[relative.as_posix()] = item
    partial = truncated or enumeration_incomplete or unstable > 0
    if partial and cache:
        # Absence is evidence of deletion only after a complete inventory. Keep
        # previously observed entries through bounded, unreadable, or unstable
        # scans so a partial view cannot publish fabricated deletions.
        for relative, item in cache.items():
            if relative not in result and isinstance(relative, str) and isinstance(item, dict):
                result[relative] = copy.deepcopy(item)
    if isinstance(state, dict):
        if result != cache:
            state["_scan_cache_dirty"] = True
        state["_scan_cache"] = copy.deepcopy(result)
        state.setdefault("observability", {})["last_scan"] = {
            "files": len(result), "reused": reused, "hashed": hashed,
            "unstable": unstable, "complete": not partial,
            "truncated": truncated, "enumeration_errors": 1 if enumeration_incomplete else 0,
            "duration_ms": round((time.monotonic() - started) * 1_000),
        }
    return result, partial


def compare_files(
    baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for path in sorted(set(baseline) | set(current)):
        before = baseline.get(path)
        after = current.get(path)
        if before is None and after is not None:
            changes.append({"path": path, "status": "added", "added": int(after.get("lines", 0)), "deleted": 0, "binary": bool(after.get("binary"))})
        elif before is not None and after is None:
            changes.append({"path": path, "status": "deleted", "added": 0, "deleted": int(before.get("lines", 0)), "binary": bool(before.get("binary"))})
        elif before and after and before.get("hash") != after.get("hash"):
            before_lines = int(before.get("lines", 0))
            after_lines = int(after.get("lines", 0))
            changes.append({
                "path": path, "status": "modified",
                "added": max(after_lines - before_lines, 0),
                "deleted": max(before_lines - after_lines, 0),
                "binary": bool(before.get("binary") or after.get("binary")),
            })
    return changes


def git_exact_changes(
    root: Path, state: dict[str, Any], current: dict[str, dict[str, Any]],
) -> list[dict[str, Any]] | None:
    baseline = state.get("git_baseline") or {}
    generated_paths = {str(path) for path in state.get("_generated_paths", []) if isinstance(path, str)}
    head = baseline.get("head")
    prefix = str(baseline.get("prefix") or "")
    if not baseline.get("clean") or not head:
        return None
    numstat = git_bytes(root, ["diff", "--numstat", "--no-renames", "-z", str(head), "--", "."])
    names = git_bytes(root, ["diff", "--name-status", "--no-renames", "-z", str(head), "--", "."])
    if numstat is None or names is None:
        return None
    status_by_path: dict[str, str] = {}
    name_records = [record for record in names.split(b"\0") if record]
    for index in range(0, len(name_records) - 1, 2):
        status_raw = name_records[index].decode("ascii", errors="replace")
        raw_path = name_records[index + 1].decode("utf-8", errors="surrogateescape")
        path = raw_path[len(prefix):] if prefix and raw_path.startswith(prefix) else raw_path
        if ignored(Path(path)) or path in generated_paths:
            continue
        status_by_path[path] = {"A": "added", "D": "deleted"}.get(status_raw[:1], "modified")
    counts: dict[str, tuple[int, int, bool]] = {}
    for record in numstat.split(b"\0"):
        parts = record.split(b"\t", 2)
        if len(parts) != 3:
            continue
        added_raw_bytes, deleted_raw_bytes, raw_path_bytes = parts
        added_raw = added_raw_bytes.decode("ascii", errors="replace")
        deleted_raw = deleted_raw_bytes.decode("ascii", errors="replace")
        path = raw_path_bytes.decode("utf-8", errors="surrogateescape")
        path = path[len(prefix):] if prefix and path.startswith(prefix) else path
        if ignored(Path(path)) or path in generated_paths:
            continue
        binary = added_raw == "-" or deleted_raw == "-"
        counts[path] = (0 if binary else int(added_raw), 0 if binary else int(deleted_raw), binary)
    net = compare_files(state.get("baseline", {}), current)
    for item in net:
        if item["status"] == "added" and item["path"] not in counts:
            counts[item["path"]] = (int(item["added"]), 0, bool(item["binary"]))
            status_by_path[item["path"]] = "added"
    changes = []
    for path in sorted(counts):
        added, deleted, binary = counts[path]
        changes.append({
            "path": path, "status": status_by_path.get(path, "modified"),
            "added": added, "deleted": deleted, "binary": binary,
        })
    return changes


def publish_changes(
    state: dict[str, Any], changes: list[dict[str, Any]], title: str,
    detail: str = "", diff_quality: str = "net", truncated: bool = False,
) -> None:
    published = changes[:MAX_PUBLIC_CHANGES]
    added = sum(int(item.get("added", 0)) for item in changes)
    deleted = sum(int(item.get("deleted", 0)) for item in changes)
    state["latest_files"] = published
    aggregate = ensure_aggregates(state)
    aggregate["files_changed"] = len(changes)
    aggregate["added"] = added
    aggregate["deleted"] = deleted
    aggregate["diff_quality"] = diff_quality
    quality_labels = {
        "exact": ("exact Git diff", "精确 Git 差异"),
        "metadata": ("file metadata only", "仅文件元数据"),
        "partial": ("partial diff", "部分差异"),
        "net": ("net line delta", "净行数变化"),
    }
    quality_label = localized(state, *quality_labels.get(diff_quality, quality_labels["net"]))
    summary = localized(
        state,
        f"{len(changes)} files changed, +{added} / -{deleted} ({quality_label})",
        f"{len(changes)} 个文件有变化，+{added} / -{deleted}（{quality_label}）",
    )
    limited = truncated or len(changes) > MAX_PUBLIC_CHANGES
    if limited:
        summary += localized(state, " (display limited)", "（显示数量受限）")
    add_event(state, "edit", title, detail or summary, "success", {
        "files": published, "file_count": len(changes), "added": added,
        "deleted": deleted, "diff_quality": diff_quality, "truncated": limited,
    })


def prepare_snapshot(root: Path, state: dict[str, Any], *, force: bool = False) -> tuple[list[dict[str, Any]], bool, str]:
    current, truncated = scan_workspace(root, state, force=force)
    exact = git_exact_changes(root, state, current)
    changes = exact if exact is not None else compare_files(state.get("baseline", {}), current)
    generated_paths = {str(path) for path in state.get("_generated_paths", []) if isinstance(path, str)}
    changes = [item for item in changes if item.get("path") not in generated_paths]
    return changes, truncated, "partial" if truncated else "exact" if exact is not None else "net"


def publish_prepared_snapshot(
    state: dict[str, Any], changes: list[dict[str, Any]], truncated: bool,
    quality: str, title: str, detail: str = "",
) -> None:
    if not changes and truncated and state.get("latest_files"):
        add_event(state, "snapshot", title, detail or localized(
            state,
            "The bounded scan found no changes but was incomplete; retained the prior file view.",
            "受限扫描未发现变化但并不完整；已保留先前文件视图。",
        ), "warning", {"file_count": 0, "diff_quality": "partial", "truncated": True})
        return
    publish_changes(state, changes, title, detail, quality, truncated)
    aggregate = ensure_aggregates(state)
    aggregate["files_changed"] = len(changes)
    aggregate["added"] = sum(safe_integer(item.get("added")) or 0 for item in changes)
    aggregate["deleted"] = sum(safe_integer(item.get("deleted")) or 0 for item in changes)
    aggregate["diff_quality"] = quality


def snapshot_event(
    root: Path, state: dict[str, Any], title: str, detail: str = "", *, force: bool = False,
) -> list[dict[str, Any]]:
    changes, truncated, quality = prepare_snapshot(root, state, force=force)
    publish_prepared_snapshot(state, changes, truncated, quality, title, detail)
    return changes


def cancel_automatic_snapshot(state: dict[str, Any]) -> None:
    auto = state.setdefault("_auto_snapshot", {})
    auto.pop("ticket", None)
    auto.pop("due_at_ms", None)
    auto.pop("pending_generation", None)
    auto.pop("ticket_created_at_ms", None)
    auto.pop("worker_started_at_ms", None)
    auto.pop("heartbeat_at_ms", None)
    auto.pop("lease_until_ms", None)


def schedule_automatic_snapshot(state: dict[str, Any], *, immediate: bool = False) -> str | None:
    policy = state.get("snapshot_policy") if isinstance(state.get("snapshot_policy"), dict) else {}
    if policy.get("mode", "auto") != "auto":
        return None
    debounce = safe_integer(policy.get("debounce_ms"), maximum=10_000) or AUTO_SNAPSHOT_DEBOUNCE_MS
    debounce = min(10_000, max(100, debounce))
    auto = state.setdefault("_auto_snapshot", {})
    generation = (safe_integer(auto.get("edit_generation"), maximum=10**12) or 0) + (0 if immediate else 1)
    if not immediate:
        auto["edit_generation"] = generation
    else:
        generation = safe_integer(auto.get("edit_generation"), maximum=10**12) or 0
    auto["pending_generation"] = generation
    current_ms = round(time.time() * 1_000)
    auto["due_at_ms"] = current_ms + (0 if immediate else debounce)
    ticket = auto.get("ticket") if isinstance(auto.get("ticket"), str) else ""
    lease_until = safe_integer(auto.get("lease_until_ms"), maximum=10**15) or 0
    if ticket and lease_until <= current_ms:
        cancel_automatic_snapshot(state)
        auto["pending_generation"] = generation
        auto["due_at_ms"] = current_ms + (0 if immediate else debounce)
        ticket = ""
    if not ticket:
        ticket = uuid.uuid4().hex
        auto["ticket"] = ticket
        auto["ticket_created_at_ms"] = current_ms
        auto["lease_until_ms"] = current_ms + AUTO_SNAPSHOT_LEASE_MS
        return ticket
    created_at = safe_integer(auto.get("ticket_created_at_ms"), maximum=10**15) or current_ms
    if (
        safe_integer(auto.get("worker_started_at_ms"), maximum=10**15) is None
        and current_ms - created_at >= AUTO_SNAPSHOT_SPAWN_GRACE_MS
    ):
        # Re-return an unclaimed ticket so a later hook can recover the narrow
        # crash window between state commit and worker spawn. Duplicate workers
        # share the same fenced ticket, so at most one can commit.
        auto["lease_until_ms"] = current_ms + AUTO_SNAPSHOT_LEASE_MS
        return ticket
    return None


def detect_language(title: str, requested: str) -> str:
    if requested in {"en", "zh"}:
        return requested
    locale = os.environ.get("LANG", "").lower()
    return "zh" if re.search(r"[\u3400-\u9fff]", title) or locale.startswith("zh") else "en"


def archive_existing(directory: Path) -> None:
    state_path = directory / STATE_NAME
    if safe_file_metadata(state_path) is None:
        return
    content = secure_read_text(state_path)
    try:
        prior_state = json.loads(content, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, RecursionError, ValueError):
        prior_state = None
    if isinstance(prior_state, dict):
        append_history(directory, prior_state)
    archive = ensure_safe_directory(directory / "archive", private=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if os.name == "nt":
        names = {item.name for item in archive.iterdir()}
        destination = archive / f"trace-{stamp}.json"
        counter = 1
        while destination.name in names:
            destination = archive / f"trace-{stamp}-{counter}.json"
            counter += 1
        atomic_write(destination, content)
        records: list[tuple[int, Path]] = []
        for item in archive.iterdir():
            try:
                metadata = item.lstat()
            except OSError:
                continue
            if item.name.startswith("trace-") and item.suffix == ".json" and stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode) and not is_windows_reparse(metadata) and metadata.st_nlink == 1:
                records.append((metadata.st_mtime_ns, item))
        for _, item in sorted(records)[:-MAX_ARCHIVES]:
            item.unlink()
        return
    try:
        archive_descriptor = open_safe_directory_fd(archive)
        names = set(os.listdir(archive_descriptor))
    except OSError as exc:
        raise SystemExit(f"Cannot safely inspect trace archive: {exc}") from exc
    try:
        destination = archive / f"trace-{stamp}.json"
        counter = 1
        while destination.name in names:
            destination = archive / f"trace-{stamp}-{counter}.json"
            counter += 1
        atomic_write(destination, content)
        records: list[tuple[int, str]] = []
        for name in os.listdir(archive_descriptor):
            if not name.startswith("trace-") or not name.endswith(".json"):
                continue
            metadata = os.stat(name, dir_fd=archive_descriptor, follow_symlinks=False)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                records.append((metadata.st_mtime_ns, name))
        for _, name in sorted(records)[:-MAX_ARCHIVES]:
            os.unlink(name, dir_fd=archive_descriptor)
    except OSError as exc:
        raise SystemExit(f"Cannot safely prune trace archive: {exc}") from exc
    finally:
        os.close(archive_descriptor)


TOKEN_METRIC_FIELDS = (
    "model_input_tokens", "cached_input_tokens", "model_output_tokens", "reasoning_output_tokens",
    "user_visible_tokens", "effective_user_tokens", "candidate_context_tokens",
    "retained_context_tokens", "saved_tokens",
)
MODEL_TOKEN_FIELDS = TOKEN_METRIC_FIELDS[:4]
USER_TOKEN_FIELDS = TOKEN_METRIC_FIELDS[4:6]
CONTEXT_TOKEN_FIELDS = TOKEN_METRIC_FIELDS[6:]


def empty_token_usage() -> dict[str, Any]:
    return {
        "quality": "unavailable", "source": "", "method": "",
        "updated_at": None, "entries": [], "field_quality": {},
        "field_source": {}, "sources": [], "semantics": "snapshot", "reset": False,
    }


def normalize_token_adapter_state(value: Any, legacy_seen: Any = None) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    seen_source = raw.get("seen_ids") if isinstance(raw.get("seen_ids"), list) else legacy_seen
    seen: list[str] = []
    for item in seen_source if isinstance(seen_source, list) else []:
        if isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) and item not in seen:
            seen.append(item)
    last: dict[str, dict[str, Any]] = {}
    raw_last = raw.get("last_cumulative") if isinstance(raw.get("last_cumulative"), dict) else {}
    for key, item in list(raw_last.items())[-MAX_TOKEN_CUMULATIVE_SCOPES:]:
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) or not isinstance(item, dict):
            continue
        raw_values = item.get("values") if isinstance(item.get("values"), dict) else {}
        values = {
            field: integer for field, candidate in raw_values.items()
            if field in TOKEN_METRIC_FIELDS and (integer := safe_integer(candidate)) is not None
        }
        if values:
            last[key] = {"values": values, "updated_at": safe_text(item.get("updated_at"), 64)}
    return {"version": 1, "seen_ids": seen[-MAX_TOKEN_SAMPLE_IDS:], "last_cumulative": last}


def token_sample_key(source: str, sample_id: str, scope: str = "") -> str:
    # Preserve the legacy key for an empty scope so existing traces retain deduplication.
    material = f"{source}\0{sample_id}" if not scope else f"{source}\0{scope}\0{sample_id}"
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def token_scope_key(source: str, scope: str) -> str:
    return hashlib.sha256(f"{source}\0{scope or 'default'}".encode("utf-8", errors="replace")).hexdigest()


def token_usage_snapshot(value: Any) -> dict[str, Any]:
    usage = value if isinstance(value, dict) else empty_token_usage()
    return {key: copy.deepcopy(item) for key, item in usage.items() if key != "entries"}


def record_token_sample(
    state: dict[str, Any], supplied: dict[str, int | None], source: str,
    quality: str, label: str, method: str, *, semantics: str = "snapshot",
    sample_id: str = "", scope: str = "",
) -> tuple[dict[str, Any], bool]:
    """Validate and apply one Token sample, returning (public snapshot, changed)."""
    if quality == "actual" and source not in {"app-server", "otel", "codex-status", "api", "codex-jsonl"}:
        raise SystemExit("Exact Token values require an official source: app-server, OTel, Codex status, or API usage.")
    if semantics not in {"snapshot", "cumulative", "delta"}:
        raise SystemExit("Token semantics must be snapshot, cumulative, or delta.")
    if not any(value is not None for value in supplied.values()):
        raise SystemExit("Provide at least one token metric.")
    normalized = {
        key: nonnegative(value, key.replace("_", " ")) if value is not None else None
        for key, value in supplied.items() if key in TOKEN_METRIC_FIELDS
    }
    sample_values = {key: value for key, value in normalized.items() if value is not None}
    current_usage = state.get("token_usage") if isinstance(state.get("token_usage"), dict) else empty_token_usage()
    current_snapshot = token_usage_snapshot(current_usage)
    safe_sample_id = safe_text(sample_id, 200)
    safe_scope = safe_text(scope, 200)
    adapter_state = normalize_token_adapter_state(
        state.get("_token_adapter_state"), state.get("_token_sample_ids", []),
    )
    sample_key = token_sample_key(source, safe_sample_id, safe_scope) if safe_sample_id else ""
    if sample_key and sample_key in adapter_state["seen_ids"]:
        return current_snapshot, False

    deltas: dict[str, int] = {}
    reset = False
    applied_values = dict(sample_values)
    scope_key = token_scope_key(source, safe_scope)
    if semantics == "cumulative":
        prior_entry = adapter_state["last_cumulative"].get(scope_key)
        prior_values = dict(prior_entry.get("values", {})) if isinstance(prior_entry, dict) else {}
        reset = any(
            key in prior_values and value < prior_values[key]
            for key, value in sample_values.items()
        )
        if reset:
            cumulative_values = dict(sample_values)
        else:
            cumulative_values = {**prior_values, **sample_values}
            deltas = {
                key: value - prior_values[key]
                for key, value in sample_values.items()
                if key in prior_values and value > prior_values[key]
            }
        if prior_values and cumulative_values == prior_values:
            return current_snapshot, False
        applied_values = cumulative_values
        adapter_state["last_cumulative"].pop(scope_key, None)
        adapter_state["last_cumulative"][scope_key] = {
            "values": cumulative_values, "updated_at": now_iso(),
        }
        while len(adapter_state["last_cumulative"]) > MAX_TOKEN_CUMULATIVE_SCOPES:
            adapter_state["last_cumulative"].pop(next(iter(adapter_state["last_cumulative"])))
    elif semantics == "delta":
        deltas = dict(sample_values)

    usage = copy.deepcopy(current_usage)
    field_quality = usage.get("field_quality") if isinstance(usage.get("field_quality"), dict) else {}
    field_source = usage.get("field_source") if isinstance(usage.get("field_source"), dict) else {}
    field_quality = copy.deepcopy(field_quality)
    field_source = copy.deepcopy(field_source)
    usage["field_quality"] = field_quality
    usage["field_source"] = field_source
    entries = usage.get("entries") if isinstance(usage.get("entries"), list) else []
    usage["entries"] = copy.deepcopy(entries[-50:])

    # Delta samples and cumulative counter resets are coherent observations, not
    # patches over a prior response. Clear absent sibling fields before checking
    # invariants so an API response cannot inherit another response's cache count.
    if semantics == "delta" or reset:
        for group in (MODEL_TOKEN_FIELDS, USER_TOKEN_FIELDS, CONTEXT_TOKEN_FIELDS):
            if any(key in sample_values for key in group):
                for key in group:
                    usage.pop(key, None)
                    field_quality.pop(key, None)
                    field_source.pop(key, None)
    for key, value in applied_values.items():
        usage[key] = value
        field_quality[key] = quality
        field_source[key] = source

    visible = usage.get("user_visible_tokens")
    effective = usage.get("effective_user_tokens")
    if visible is not None and effective is not None and effective > visible:
        raise SystemExit("effective user tokens cannot exceed user-visible tokens.")
    model_input = usage.get("model_input_tokens")
    cached_input = usage.get("cached_input_tokens")
    if model_input is not None and cached_input is not None and cached_input > model_input:
        raise SystemExit("cached input tokens cannot exceed model input tokens.")
    model_output = usage.get("model_output_tokens")
    reasoning_output = usage.get("reasoning_output_tokens")
    if model_output is not None and reasoning_output is not None and reasoning_output > model_output:
        raise SystemExit("reasoning output tokens cannot exceed model output tokens.")
    candidate = usage.get("candidate_context_tokens")
    retained = usage.get("retained_context_tokens")
    context_touched = any(key in sample_values for key in CONTEXT_TOKEN_FIELDS)
    if context_touched and candidate is not None and retained is not None and retained > candidate:
        raise SystemExit("retained context tokens cannot exceed candidate context tokens.")
    expected_saved = candidate - retained if candidate is not None and retained is not None else None
    supplied_saved = normalized.get("saved_tokens")
    if supplied_saved is not None and expected_saved is None:
        raise SystemExit("saved tokens require both candidate and retained context values.")
    if supplied_saved is not None and supplied_saved != expected_saved:
        raise SystemExit("saved tokens must equal candidate context minus retained context.")
    if expected_saved is not None and context_touched:
        usage["saved_tokens"] = expected_saved
        field_quality["saved_tokens"] = "derived"
        field_source["saved_tokens"] = "derived"
    if normalized.get("effective_user_tokens") is not None:
        field_quality["effective_user_tokens"] = "derived"
        field_source["effective_user_tokens"] = "derived"
    if normalized.get("saved_tokens") is not None:
        field_quality["saved_tokens"] = "derived"
        field_source["saved_tokens"] = "derived"

    usage["sources"] = sorted({value for value in field_source.values() if value != "derived"})
    usage["source"] = safe_text(" + ".join(usage["sources"]), 160)
    usage["method"] = safe_text(method, 400)
    usage["updated_at"] = now_iso()
    usage["quality"] = token_quality(field_quality)
    usage["semantics"] = semantics
    usage["reset"] = reset
    entry_values = dict(sample_values)
    if context_touched and expected_saved is not None:
        entry_values["saved_tokens"] = expected_saved
    entry: dict[str, Any] = {
        "at": usage["updated_at"], "label": safe_text(label, 240),
        "source": safe_text(source, 80), "quality": quality,
        "method": usage["method"], "semantics": semantics, "reset": reset,
        "scope_key": scope_key, "values": entry_values,
    }
    if sample_key:
        entry["sample_key"] = sample_key
    if deltas:
        entry["deltas"] = copy.deepcopy(deltas)
    usage["entries"].append(entry)
    del usage["entries"][:-50]

    if sample_key:
        adapter_state["seen_ids"].append(sample_key)
        adapter_state["seen_ids"] = list(dict.fromkeys(adapter_state["seen_ids"]))[-MAX_TOKEN_SAMPLE_IDS:]
    state["_token_adapter_state"] = adapter_state
    state.pop("_token_sample_ids", None)
    state["token_usage"] = usage
    labels = {
        "model_input_tokens": ("model input", "模型输入"),
        "user_visible_tokens": ("user-visible", "用户可见"),
        "effective_user_tokens": ("effective user", "有效用户"),
        "saved_tokens": ("saved", "已节省"),
    }
    summary_parts = [
        f"{localized(state, *names)}: {usage[key]:,}"
        for key, names in labels.items() if usage.get(key) is not None
    ]
    snapshot = token_usage_snapshot(usage)
    event = add_event(state, "tokens", label, "; ".join(summary_parts), "success", {"token_usage": snapshot})
    trend_values = {
        key: value for key, value in usage.items()
        if key in TOKEN_METRIC_FIELDS and safe_integer(value) is not None
    }
    history_entry: dict[str, Any] = {
        "seq": event["seq"], "at": event["at"], "values": trend_values,
        "field_quality": copy.deepcopy(field_quality), "field_source": copy.deepcopy(field_source),
        "semantics": semantics, "reset": reset,
    }
    if deltas:
        history_entry["deltas"] = copy.deepcopy(deltas)
    state.setdefault("token_history", []).append(history_entry)
    del state["token_history"][:-MAX_TOKEN_HISTORY]
    return snapshot, True


def record_token_usage(
    state: dict[str, Any], supplied: dict[str, int | None], source: str,
    quality: str, label: str, method: str, *, semantics: str = "snapshot",
    sample_id: str = "", scope: str = "",
) -> dict[str, Any]:
    """Compatibility wrapper for callers that only need the resulting snapshot."""
    snapshot, _ = record_token_sample(
        state, supplied, source, quality, label, method,
        semantics=semantics, sample_id=sample_id, scope=scope,
    )
    return snapshot


def parse_test_summary(output: str) -> dict[str, Any] | None:
    text = output[-MAX_CAPTURE_BYTES:]
    summary: dict[str, int | float] = {}
    rust = re.search(r"test result: \w+\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored", text, re.I)
    if rust:
        summary.update(passed=int(rust.group(1)), failed=int(rust.group(2)), skipped=int(rust.group(3)))
    else:
        for key, pattern in {
            "passed": r"(?<![\w])([0-9]+)\s+passed\b",
            "failed": r"(?<![\w])([0-9]+)\s+failed\b",
            "skipped": r"(?<![\w])([0-9]+)\s+(?:skipped|ignored)\b",
            "errors": r"(?<![\w])([0-9]+)\s+errors?\b",
        }.items():
            matches = re.findall(pattern, text, re.I)
            if matches:
                summary[key] = int(matches[-1])
        gradle = re.search(r"(\d+) tests? completed(?:,\s*(\d+) failed)?(?:,\s*(\d+) skipped)?", text, re.I)
        if gradle:
            total = int(gradle.group(1))
            failed = int(gradle.group(2) or 0)
            skipped = int(gradle.group(3) or 0)
            summary.update(total=total, failed=failed, skipped=skipped, passed=max(0, total - failed - skipped))
        unittest_ran = re.search(r"\bRan\s+(\d+)\s+tests?\b", text, re.I)
        if unittest_ran:
            total = int(unittest_ran.group(1))
            failed_match = re.search(r"FAILED\s*\(([^)]*)\)", text, re.I)
            failed = errors = skipped = 0
            if failed_match:
                values = dict((key.lower(), int(value)) for key, value in re.findall(r"(failures|errors|skipped)\s*=\s*(\d+)", failed_match.group(1), re.I))
                failed, errors, skipped = values.get("failures", 0), values.get("errors", 0), values.get("skipped", 0)
            elif not re.search(r"\bOK\b", text):
                failed = 1
            summary.update(total=total, failed=failed, errors=errors, skipped=skipped, passed=max(0, total - failed - errors - skipped))
    if summary and "total" not in summary:
        summary["total"] = sum(int(summary.get(key, 0)) for key in ("passed", "failed", "skipped", "errors"))
    coverage = re.findall(r"\bTOTAL\b[^\n]*?([0-9]{1,3})%\s*$", text, re.I | re.M)
    if coverage:
        summary["coverage_percent"] = min(100, int(coverage[-1]))
    return summary or None


def process_tree_pids(root_pid: int) -> list[int]:
    """Return known descendants before their parent can be reaped."""
    if os.name == "nt":
        return [root_pid]
    children: dict[int, list[int]] = {}
    proc = Path("/proc")
    if proc.is_dir():
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_text(encoding="utf-8").split()
                pid, parent = int(fields[0]), int(fields[3])
            except (OSError, ValueError, IndexError, UnicodeDecodeError):
                continue
            children.setdefault(parent, []).append(pid)
    else:
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid=,ppid="], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False, timeout=2, text=True,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) == 2:
                    children.setdefault(int(parts[1]), []).append(int(parts[0]))
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return [root_pid]
    found: list[int] = []
    queue = [root_pid]
    seen = {root_pid}
    while queue:
        parent = queue.pop()
        for pid in children.get(parent, []):
            if pid not in seen:
                seen.add(pid)
                found.append(pid)
                queue.append(pid)
    return found + [root_pid]


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5,
            )
            if result.returncode != 0 and process.poll() is None:
                process.kill()
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return
    targets = process_tree_pids(process.pid)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    for pid in targets:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.1)
    survivors = targets
    for pid in survivors:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def execute_streaming(command: list[str], cwd: Path, timeout: float) -> tuple[int, bool, str, str]:
    captured = bytearray()
    capture_lock = threading.Lock()
    pump_error = ""
    try:
        popen_options: dict[str, Any] = {}
        if os.name == "nt":
            popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_options["start_new_session"] = True
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **popen_options)
    except OSError as exc:
        return 127, False, "", safe_text(str(exc), 1_000)

    def pump() -> None:
        nonlocal pump_error
        try:
            assert process.stdout is not None
            while chunk := process.stdout.read(4_096):
                try:
                    if hasattr(sys.stdout, "buffer"):
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                    else:
                        sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                        sys.stdout.flush()
                except (BrokenPipeError, OSError):
                    pass
                with capture_lock:
                    captured.extend(chunk)
                    if len(captured) > MAX_CAPTURE_BYTES:
                        del captured[:-MAX_CAPTURE_BYTES]
        except OSError as exc:
            pump_error = safe_text(str(exc), 1_000)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    timed_out = False
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_tree(process)
        return_code = 124
    reader.join(timeout=0.5)
    with capture_lock:
        raw = bytes(captured).decode("utf-8", errors="replace")
    return return_code, timed_out, raw, pump_error


def parse_unified_diff(diff: str) -> list[dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    in_hunk = False
    for line in diff[:MAX_JSONL_BYTES].splitlines():
        if line.startswith("diff --git "):
            if len(files) >= MAX_PUBLIC_CHANGES:
                break
            in_hunk = False
            try:
                parts = shlex.split(line)
                raw = parts[-1]
            except (ValueError, IndexError):
                raw = "unknown"
            path = normalized_observed_path(raw[2:] if raw.startswith("b/") else raw)
            current = files.setdefault(path, {"path": path, "status": "modified", "added": 0, "deleted": 0, "binary": False})
        elif current is not None and line.startswith("new file mode"):
            current["status"] = "added"
        elif current is not None and line.startswith("deleted file mode"):
            current["status"] = "deleted"
        elif current is not None and line.startswith("Binary files"):
            current["binary"] = True
        elif current is not None and line.startswith("@@"):
            in_hunk = True
        elif current is not None and in_hunk and line.startswith("+"):
            current["added"] += 1
        elif current is not None and in_hunk and line.startswith("-"):
            current["deleted"] += 1
    return list(files.values())


TOKEN_ALIASES = {
    "model_input_tokens": ("inputtokens", "prompttokens", "modelinputtokens", "totalinputtokens"),
    "cached_input_tokens": ("cachedinputtokens", "cachedtokens", "inputcachedtokens", "cachedprompttokens"),
    "model_output_tokens": ("outputtokens", "completiontokens", "modeloutputtokens", "totaloutputtokens"),
    "reasoning_output_tokens": ("reasoningoutputtokens", "reasoningtokens"),
}


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def extract_token_metrics(payload: Any) -> dict[str, int | None]:
    """Extract only direct, allowlisted Token fields from an explicit usage object."""
    result: dict[str, int | None] = {key: None for key in TOKEN_ALIASES}
    if not isinstance(payload, dict):
        return result
    normalized = {normalized_key(str(key)): value for key, value in list(payload.items())[:2_000]}
    for field, aliases in TOKEN_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                result[field] = safe_integer(normalized[alias])
                break
    return result


def api_token_adapter(payload: Any, *, explicit: bool = False) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    usage: dict[str, Any] | None = None
    response = payload.get("response") if isinstance(payload.get("response"), dict) else None
    if isinstance(payload.get("usage"), dict):
        usage = payload["usage"]
    elif response is not None and isinstance(response.get("usage"), dict):
        usage = response["usage"]
    elif explicit:
        usage = payload
    if usage is None:
        return None
    metrics = extract_token_metrics(usage)
    details_in = usage.get("input_tokens_details") if isinstance(usage.get("input_tokens_details"), dict) else usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
    details_out = usage.get("output_tokens_details") if isinstance(usage.get("output_tokens_details"), dict) else usage.get("completion_tokens_details") if isinstance(usage.get("completion_tokens_details"), dict) else {}
    if metrics["cached_input_tokens"] is None and isinstance(details_in, dict):
        metrics["cached_input_tokens"] = safe_integer(details_in.get("cached_tokens"))
    if metrics["reasoning_output_tokens"] is None and isinstance(details_out, dict):
        metrics["reasoning_output_tokens"] = safe_integer(details_out.get("reasoning_tokens"))
    if not any(value is not None for value in metrics.values()):
        return None
    sample_id = payload.get("id") or (response.get("id") if response is not None else "")
    return {
        "metrics": metrics, "source": "api", "semantics": "delta",
        "sample_id": safe_text(str(sample_id or ""), 200), "scope": "",
        "method": "Imported from API response usage",
    }


OTEL_TOKEN_ATTRIBUTES = {
    "gen_ai.usage.input_tokens": "model_input_tokens",
    "gen_ai.usage.cached_input_tokens": "cached_input_tokens",
    "gen_ai.usage.cached_tokens": "cached_input_tokens",
    "gen_ai.usage.output_tokens": "model_output_tokens",
    "gen_ai.usage.reasoning_tokens": "reasoning_output_tokens",
    "gen_ai.usage.reasoning_output_tokens": "reasoning_output_tokens",
}


def otel_token_adapter(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    event = payload.get("event") if isinstance(payload.get("event"), dict) else payload
    name = (
        event.get("name") or event.get("event_name") or event.get("eventName")
        or event.get("type") or (payload.get("event") if isinstance(payload.get("event"), str) else "")
    )
    if normalized_key(str(name or "")) not in {"responsecompleted", "genairesponsecompleted"}:
        return None
    attributes = event.get("attributes") if isinstance(event.get("attributes"), dict) else payload.get("attributes")
    if not isinstance(attributes, dict):
        return None
    metrics: dict[str, int | None] = {key: None for key in TOKEN_ALIASES}
    for raw_key, field in OTEL_TOKEN_ATTRIBUTES.items():
        if raw_key in attributes:
            metrics[field] = safe_integer(attributes[raw_key])
    if not any(value is not None for value in metrics.values()):
        return None
    sample_id = (
        event.get("id") or event.get("span_id") or payload.get("span_id")
        or attributes.get("gen_ai.response.id") or ""
    )
    scope = payload.get("trace_id") or event.get("trace_id") or attributes.get("service.name") or ""
    return {
        "metrics": metrics, "source": "otel", "semantics": "delta",
        "sample_id": safe_text(str(sample_id or ""), 200),
        "scope": safe_text(str(scope or ""), 200),
        "method": "Imported from OTel response.completed attributes",
    }


def app_server_token_adapter(message: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
    usage: Any = params
    for key in ("tokenUsage", "token_usage", "totalTokenUsage", "total_token_usage"):
        if isinstance(params.get(key), dict):
            usage = params[key]
            break
    if isinstance(usage, dict):
        for key in ("total", "totalUsage", "total_usage"):
            if isinstance(usage.get(key), dict):
                usage = usage[key]
                break
    metrics = extract_token_metrics(usage)
    if not any(value is not None for value in metrics.values()):
        return None
    sample_id = params.get("id") or params.get("responseId") or params.get("response_id") or message.get("id") or ""
    scope = params.get("threadId") or params.get("thread_id") or message.get("thread_id") or ""
    return {
        "metrics": metrics, "source": "app-server", "semantics": "cumulative",
        "sample_id": safe_text(str(sample_id or ""), 200),
        "scope": safe_text(str(scope or ""), 200),
        "method": "thread/tokenUsage/updated",
    }


def update_plan_from_stream(state: dict[str, Any], plan: Any) -> bool:
    if not isinstance(plan, list):
        return False
    plans = state.setdefault("plan", [])
    if not isinstance(plans, list):
        plans = []
    prior_ids_raw = state.get("_stream_plan_ids")
    prior_ids = [value for value in prior_ids_raw if isinstance(value, str)] if isinstance(prior_ids_raw, list) else []
    prior_set = set(prior_ids)
    preserved = [item for item in plans if not isinstance(item, dict) or item.get("id") not in prior_set]
    previous = {item.get("id"): item for item in plans if isinstance(item, dict) and isinstance(item.get("id"), str)}
    streamed: list[dict[str, Any]] = []
    new_ids: list[str] = []
    used_ids = {item.get("id") for item in preserved if isinstance(item, dict)}
    changed = len(prior_ids) != min(len(plan), 500)
    status_map = {"inprogress": "in_progress", "pending": "pending", "completed": "completed", "blocked": "blocked"}
    for index, raw in enumerate(plan[:500]):
        if not isinstance(raw, dict):
            continue
        title = safe_text(raw.get("step") or raw.get("title") or "", 240)
        if not title:
            continue
        supplied_id = safe_text(raw.get("id"), 160)
        seed = f"id:{supplied_id}" if supplied_id else f"slot:{index}"
        plan_id = "stream-" + hashlib.sha256(seed.encode()).hexdigest()[:12]
        if plan_id in used_ids:
            plan_id = "stream-" + hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12]
        used_ids.add(plan_id)
        new_ids.append(plan_id)
        status = status_map.get(normalized_key(str(raw.get("status"))), "pending")
        old = previous.get(plan_id)
        item = {"id": plan_id, "title": title, "status": status, "updated_at": old.get("updated_at") if isinstance(old, dict) else now_iso()}
        item_changed = not isinstance(old, dict) or old.get("title") != title or old.get("status") != status
        if item_changed:
            item["updated_at"] = now_iso()
            event_status = {"pending": "pending", "in_progress": "running", "completed": "success", "blocked": "failure"}[status]
            add_event(state, "plan", title, "", event_status, {"plan_id": plan_id, "plan_title": title, "plan_status": status})
            changed = True
        streamed.append(item)
    if prior_set - set(new_ids):
        changed = True
    state["plan"] = preserved + streamed
    state["_stream_plan_ids"] = new_ids
    return changed


INGEST_TRANSACTION_KEYS = (
    "events", "plan", "latest_files", "token_history", "token_usage", "aggregates",
    "_pending_observations", "_stream_plan_ids", "_actor_aliases", "_aggregate_agent_lanes",
    "_token_sample_ids", "_token_adapter_state",
)


def ingest_message(state: dict[str, Any], message: dict[str, Any], source: str) -> bool:
    """Apply one message atomically without copying immutable baselines or scan caches."""
    working = state.copy()
    for key in INGEST_TRANSACTION_KEYS:
        value = state.get(key)
        if isinstance(value, dict):
            working[key] = copy.deepcopy(value)
        elif isinstance(value, list):
            # Existing event/plan/history entries are append-only or replaced by
            # ingestion handlers; detaching the list is sufficient and avoids an
            # O(events * messages) deep copy during large JSONL batches.
            working[key] = list(value)
    changed = _ingest_message(working, message, source)
    if changed:
        state.clear()
        state.update(working)
    return changed


def _ingest_message(state: dict[str, Any], message: dict[str, Any], source: str) -> bool:
    if not isinstance(message, dict):
        return False
    raw_method = message.get("method") if isinstance(message.get("method"), str) else message.get("type") if isinstance(message.get("type"), str) else ""
    method = raw_method.replace(".", "/")
    params = message.get("params") if isinstance(message.get("params"), dict) else message
    if method in {"thread/tokenUsage/updated", "thread/token_usage/updated"}:
        if source != "app-server":
            return False
        sample = app_server_token_adapter(message, params)
        if sample is None:
            return False
        _, changed = record_token_sample(
            state, sample["metrics"], "app-server", "actual", "Official Token usage", sample["method"],
            semantics="cumulative", sample_id=sample["sample_id"], scope=sample["scope"],
        )
        return changed
    if method == "turn/plan/updated":
        return update_plan_from_stream(state, params.get("plan") or [])
    if method == "turn/diff/updated":
        diff = params.get("diff")
        if isinstance(diff, str):
            publish_changes(state, parse_unified_diff(diff), localized(state, "Codex diff updated", "Codex 差异已更新"), diff_quality="partial" if len(diff) > MAX_JSONL_BYTES else "exact")
            return True
        return False
    if "requestapproval" in normalized_key(method) or normalized_key(method) == "permissionrequest":
        add_event(state, "approval", localized(state, "Approval requested", "正在等待授权"), localized(state, "Reason omitted from the public trace.", "公开记录已省略授权原因。"), "pending")
        return True
    if method == "serverRequest/resolved":
        add_event(state, "approval", localized(state, "Approval resolved", "授权请求已处理"), "", "success")
        return True
    if method in {"error", "turn/error"}:
        add_event(state, "error", localized(state, "Codex error", "Codex 错误"), localized(state, "Error details omitted from the public trace.", "公开记录已省略错误详情。"), "failure")
        return True
    if method == "turn/started":
        turn = params.get("turn") if isinstance(params.get("turn"), dict) else params
        turn_id = safe_text(str(turn.get("id") or params.get("turnId") or "current"), 120)
        state.setdefault("_pending_observations", {})[f"turn:{turn_id}"] = {"at": now_iso()}
        add_event(state, "turn", localized(state, "Turn started", "本轮任务已开始"), "", "running", {"turn_id": turn_id})
        return True
    if method in {"turn/completed", "turn/failed"}:
        turn = params.get("turn") if isinstance(params.get("turn"), dict) else params
        raw_turn_id = turn.get("id") or params.get("turnId") or ""
        turn_id = safe_text(str(raw_turn_id or "current"), 120)
        pending = state.setdefault("_pending_observations", {}).pop(f"turn:{turn_id}", {})
        status = str(turn.get("status") or ("failed" if method == "turn/failed" else "completed"))
        add_event(state, "turn", localized(state, "Turn completed", "本轮任务已结束"), status, "success" if status == "completed" else "failure", {"turn_id": turn_id}, elapsed_ms(pending.get("at")))
        # Official codex exec JSONL reports aggregate usage at the top level of
        # turn.completed. Nested turn.usage objects are not an authenticated
        # usage boundary and must not be promoted to exact telemetry.
        usage_payload = message.get("usage") if isinstance(message.get("usage"), dict) else None
        if source == "codex-jsonl" and usage_payload is not None:
            supplied = extract_token_metrics(usage_payload)
            if any(value is not None for value in supplied.values()):
                scope = message.get("thread_id") or message.get("threadId") or ""
                record_token_sample(
                    state, supplied, "codex-jsonl", "actual", "Official Token usage", "turn.completed usage",
                    semantics="delta", sample_id=safe_text(str(raw_turn_id or ""), 200),
                    scope=safe_text(str(scope or ""), 200),
                )
        return True
    if method != "item/completed":
        return False
    item = params.get("item") if isinstance(params.get("item"), dict) else params
    if not isinstance(item, dict):
        return False
    item_type = normalized_key(str(item.get("type") or ""))
    status_raw = str(item.get("status") or "completed")
    status = "success" if status_raw in {"completed", "success", "succeeded"} else "failure"
    duration = item.get("durationMs") if item.get("durationMs") is not None else item.get("duration_ms")
    duration_ms = safe_integer(duration, maximum=7 * 24 * 60 * 60 * 1_000)
    if item_type == "commandexecution":
        command = item.get("command")
        exit_code = item.get("exitCode") if item.get("exitCode") is not None else item.get("exit_code")
        exit_code = safe_integer(exit_code, maximum=2**31 - 1)
        if exit_code is not None and exit_code != 0:
            status = "failure"
        command_text = safe_command_text(command if isinstance(command, (str, list)) else "", 1_000)
        add_event(state, "command", localized(state, "Command completed", "命令执行完成"), f"exit {exit_code}" if exit_code is not None else status_raw, status, {"command": command_text, "exit_code": exit_code}, duration_ms)
        return True
    if item_type == "filechange":
        combined: list[dict[str, Any]] = []
        has_diff = False
        partial_diff = False
        changes = item.get("changes") if isinstance(item.get("changes"), list) else []
        for change in changes[:MAX_PUBLIC_CHANGES]:
            if isinstance(change, dict) and isinstance(change.get("diff"), str):
                combined.extend(parse_unified_diff(change["diff"]))
                has_diff = True
                partial_diff = partial_diff or len(change["diff"]) > MAX_JSONL_BYTES
            elif isinstance(change, dict) and isinstance(change.get("path"), str):
                raw_status = normalized_key(str(change.get("kind") or change.get("status") or "modified"))
                combined.append({
                    "path": normalized_observed_path(change["path"]),
                    "status": {"add": "added", "added": "added", "delete": "deleted", "deleted": "deleted"}.get(raw_status, "modified"),
                    "added": 0, "deleted": 0, "binary": False,
                })
        if combined:
            quality = "partial" if partial_diff or len(combined) >= MAX_PUBLIC_CHANGES else "exact" if has_diff else "metadata"
            publish_changes(state, combined, localized(state, "Files changed", "文件已修改"), diff_quality=quality)
        else:
            add_event(state, "edit", localized(state, "Files changed", "文件已修改"), "", status)
        return True
    if item_type in {"mcptoolcall", "dynamictoolcall", "websearch", "imageview"}:
        tool = item.get("tool") or item.get("server") or item_type
        add_event(state, "tool", localized(state, "Tool completed", "工具调用完成"), safe_text(str(tool), 160), status, {"tool_name": safe_text(str(tool), 160)}, duration_ms)
        return True
    if item_type == "collabtoolcall":
        raw_agent = item.get("newThreadId") or item.get("agentId") or item.get("agent_id")
        actor = actor_for(state, raw_agent, item.get("agentType") or item.get("role"))
        add_event(state, "agent", localized(state, "Agent activity", "子 Agent 活动"), safe_text(str(item.get("agentStatus") or status_raw), 160), status, {"agent_id": safe_text(str(raw_agent or ""), 120)}, duration_ms, actor)
        return True
    if item_type == "contextcompaction":
        add_event(state, "context", localized(state, "Context compacted", "上下文已压缩"), "", "success")
        return True
    return False


def find_trace_root(cwd: str | None) -> Path | None:
    if not isinstance(cwd, str) or not cwd or len(cwd) > 16_384:
        return None
    try:
        current = Path(cwd).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    for candidate in (current, *current.parents):
        if (trace_dir(candidate) / STATE_NAME).exists():
            return candidate
    return None


def hook_result_status(response: Any) -> tuple[str, int | None]:
    if not isinstance(response, dict):
        return "success", None
    exit_code = response.get("exit_code") if response.get("exit_code") is not None else response.get("exitCode")
    failed = response.get("isError") is True or response.get("success") is False or (isinstance(exit_code, int) and exit_code != 0)
    return ("failure" if failed else "success"), exit_code if isinstance(exit_code, int) else None


def handle_hook_payload(root: Path, payload: dict[str, Any]) -> str | None:
    if not isinstance(payload, dict):
        return
    worker_ticket: str | None = None
    with state_lock(root):
        state = load_state(root)
        if state.get("status") != "active":
            return
        state.setdefault("observability", {})["hooks"] = True
        pending = state.setdefault("_pending_observations", {})
        event = payload.get("hook_event_name") if isinstance(payload.get("hook_event_name"), str) else ""
        payload_session = safe_text(payload.get("session_id"), 160)
        sessions = state.setdefault("_hook_sessions", {})
        if not isinstance(sessions, dict):
            sessions = {}
            state["_hook_sessions"] = sessions
        trace_id = str(state.get("trace_id") or "")
        if event != "SessionStart" and payload_session:
            binding = sessions.get(payload_session)
            if not isinstance(binding, dict) or binding.get("trace_id") != trace_id:
                return
        session_key = "s-" + hashlib.sha256(payload_session.encode()).hexdigest()[:16] if payload_session else "legacy"
        auto = state.get("_auto_snapshot") if isinstance(state.get("_auto_snapshot"), dict) else {}
        if event in {"Stop", "SessionEnd"} and auto.get("pending_generation") is not None:
            worker_ticket = schedule_automatic_snapshot(state, immediate=True)
        if len(pending) > 2_000 and event in {"PreToolUse", "PreCompact", "SubagentStart"}:
            return
        tool_id = safe_text(payload.get("tool_use_id"), 120)
        if event == "PreToolUse":
            if not tool_id:
                return
            pending[f"tool:{session_key}:{tool_id}"] = {"at": now_iso(), "tool": safe_text(payload.get("tool_name") or "tool", 160), "trace_id": trace_id}
        elif event == "PostToolUse":
            item = pending.pop(f"tool:{session_key}:{tool_id}", {})
            if not item or item.get("trace_id") != trace_id:
                return
            tool = safe_text(payload.get("tool_name") or item.get("tool") or "tool", 160)
            status, exit_code = hook_result_status(payload.get("tool_response"))
            duration = elapsed_ms(item.get("at"))
            actor = actor_for(state, payload.get("agent_id"), payload.get("agent_type"))
            add_event(state, "tool", localized(state, f"Tool completed: {tool}", f"工具调用完成：{tool}"), "", status, {"tool_name": tool, "tool_use_id": tool_id, "exit_code": exit_code}, duration, actor)
            if tool in {"apply_patch", "Edit", "Write"}:
                worker_ticket = schedule_automatic_snapshot(state) or worker_ticket
                add_event(state, "edit", localized(state, "Workspace edit observed", "已观察到工作区编辑"), localized(state, "An automatic debounced snapshot is queued.", "已安排自动合并快照。"), "success", actor=actor)
        elif event == "PermissionRequest":
            tool = safe_text(str(payload.get("tool_name") or "tool"), 160)
            add_event(state, "approval", localized(state, "Approval requested", "正在等待授权"), tool, "pending")
        elif event == "PreCompact":
            key = f"compact:{session_key}:{payload.get('turn_id') or 'current'}"
            pending[key] = {"at": now_iso(), "trace_id": trace_id}
            add_event(state, "context", localized(state, "Context compaction started", "开始压缩上下文"), safe_text(str(payload.get("trigger") or ""), 80), "running")
        elif event == "PostCompact":
            key = f"compact:{session_key}:{payload.get('turn_id') or 'current'}"
            item = pending.pop(key, {})
            if not item or item.get("trace_id") != trace_id:
                return
            add_event(state, "context", localized(state, "Context compacted", "上下文已压缩"), safe_text(str(payload.get("trigger") or ""), 80), "success", duration_ms=elapsed_ms(item.get("at")))
        elif event == "SubagentStart":
            agent_id = safe_text(str(payload.get("agent_id") or "agent"), 120)
            pending[f"agent:{session_key}:{agent_id}"] = {"at": now_iso(), "trace_id": trace_id}
            actor = actor_for(state, agent_id, payload.get("agent_type"))
            add_event(state, "agent", localized(state, "Subagent started", "子 Agent 已启动"), safe_text(str(payload.get("agent_type") or ""), 120), "running", {"agent_id": agent_id}, actor=actor)
        elif event == "SubagentStop":
            agent_id = safe_text(str(payload.get("agent_id") or "agent"), 120)
            item = pending.pop(f"agent:{session_key}:{agent_id}", {})
            if not item or item.get("trace_id") != trace_id:
                return
            actor = actor_for(state, agent_id, payload.get("agent_type"))
            add_event(state, "agent", localized(state, "Subagent completed", "子 Agent 已完成"), safe_text(str(payload.get("agent_type") or ""), 120), "success", {"agent_id": agent_id}, elapsed_ms(item.get("at")), actor)
        elif event == "SessionStart":
            if payload_session:
                if len(sessions) >= 100 and payload_session not in sessions:
                    return
                sessions[payload_session] = {"trace_id": trace_id, "started_at": now_iso()}
            add_event(state, "session", localized(state, "Codex session observed", "已连接 Codex 会话"), safe_text(str(payload.get("model") or ""), 120), "running")
        elif event == "SessionEnd":
            add_event(state, "session", localized(state, "Codex session ended", "Codex 会话已结束"), "", "info")
            if payload_session:
                sessions.pop(payload_session, None)
                prefix = f":{session_key}:"
                for key in list(pending):
                    if prefix in key:
                        pending.pop(key, None)
        elif event == "Stop":
            add_event(state, "turn", localized(state, "Turn completed", "本轮任务已结束"), "", "success")
        else:
            return
        save_state(root, state)
    return worker_ticket


def hooks_config() -> dict[str, Any]:
    script = Path(__file__).resolve()
    interpreter = str(Path(sys.executable).resolve())
    command = f"{shlex.quote(interpreter)} -B {shlex.quote(str(script))} hook"
    command_windows = f'"{interpreter}" -B "{script}" hook'

    def handler(timeout: int = 10) -> dict[str, Any]:
        return {"type": "command", "command": command, "commandWindows": command_windows, "timeout": timeout, "statusMessage": "Updating Codex Build Visualizer"}

    matchers = {
        "SessionStart": "startup|resume|clear|compact",
        "PreToolUse": ".*", "PermissionRequest": ".*", "PostToolUse": ".*",
        "PreCompact": "manual|auto", "PostCompact": "manual|auto",
        "SubagentStart": ".*", "SubagentStop": ".*",
    }
    events = ["SessionStart", "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact", "SubagentStart", "SubagentStop", "Stop", "SessionEnd"]
    hooks: dict[str, list[dict[str, Any]]] = {}
    for name in events:
        timeout = 3 if name == "SessionEnd" else 30 if name in {"PostToolUse", "Stop"} else 10
        group: dict[str, Any] = {"hooks": [handler(timeout)]}
        if name in matchers:
            group["matcher"] = matchers[name]
        hooks[name] = [group]
    return {"description": "Privacy-enhanced Codex Build Visualizer lifecycle capture.", "hooks": hooks}


def command_init(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    with state_lock(root):
        directory = trace_dir(root)
        archive_existing(directory)
        install_viewer(root)
        install_trace_gitignore(root)
        baseline, truncated = scan_workspace(root)
        git_info = git_baseline(root)
        state: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION, "trace_id": str(uuid.uuid4()),
            "generation_order": time.time_ns(),
            "title": safe_text(args.title, 240), "project_name": root.name,
            "lang": detect_language(args.title, args.lang), "privacy_mode": args.privacy,
            "started_at": now_iso(), "updated_at": now_iso(), "finished_at": None,
            "status": "active", "summary": "", "plan": [], "events": [],
            "latest_files": [], "token_usage": empty_token_usage(), "token_history": [],
            "aggregates": empty_aggregates(),
            "observability": {"hooks": False, "ingest_sources": []},
            "git_baseline": git_info, "baseline": baseline, "revision": 0,
            "snapshot_policy": {"mode": "auto", "debounce_ms": AUTO_SNAPSHOT_DEBOUNCE_MS},
            "_token_adapter_state": normalize_token_adapter_state({}),
            "_auto_snapshot": {}, "_scan_cache": copy.deepcopy(baseline), "_scan_generation": 0, "_next_event_seq": 1,
            "_hook_sessions": {}, "_actor_aliases": {}, "_aggregate_agent_lanes": [],
            "_stream_plan_ids": [], "_generated_paths": [],
        }
        detail = localized(state, f"Captured a privacy-enhanced baseline of {len(baseline)} files.", f"已建立隐私增强基线，共记录 {len(baseline)} 个文件。")
        if git_info.get("clean"):
            detail += localized(state, " Exact Git line diffs are available.", " 可使用精确 Git 行差异。")
        if truncated:
            detail += localized(state, " The scan reached its configured file limit.", " 扫描已达到配置的文件数量上限。")
        add_event(state, "session", localized(state, "Build trace started", "编码记录已开始"), detail, "running")
        save_state(root, state)
    print(trace_dir(root) / VIEWER_NAME)
    return 0


def command_plan(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    unchanged = False
    with state_lock(root):
        state = load_state(root)
        require_active(state)
        plans = state.setdefault("plan", [])
        plan_id = safe_text(args.id, 80)
        item = next((entry for entry in plans if entry.get("id") == plan_id), None)
        previous = dict(item) if item else None
        if item is None:
            item = {"id": plan_id}
            plans.append(item)
        item.update({"title": safe_text(args.title, 240), "status": args.status, "updated_at": now_iso()})
        unchanged = bool(previous and previous.get("title") == item["title"] and previous.get("status") == item["status"])
        if not unchanged:
            event_status = {"pending": "pending", "in_progress": "running", "completed": "success", "blocked": "failure"}[args.status]
            labels = {"pending": ("Planned", "已计划"), "in_progress": ("Started", "已开始"), "completed": ("Completed", "已完成"), "blocked": ("Blocked", "受阻")}
            add_event(state, "plan", f"{localized(state, *labels[args.status])}: {item['title']}", "", event_status, {"plan_id": item["id"], "plan_title": item["title"], "plan_status": item["status"]})
            save_state(root, state)
    print(f"Plan step unchanged: {args.title}" if unchanged else f"{args.status}: {args.title}")
    return 0


def command_event(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    with state_lock(root):
        state = load_state(root)
        require_active(state)
        add_event(state, args.kind, args.title, args.detail, args.status)
        save_state(root, state)
    print(f"Recorded: {safe_text(args.title, 240)}")
    return 0


def command_snapshot(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    with state_lock(root):
        state = load_state(root)
        require_active(state)
        cancel_automatic_snapshot(state)
        changes = snapshot_event(root, state, args.title, args.detail, force=args.full)
        state["_scan_generation"] = (safe_integer(state.get("_scan_generation"), maximum=10**12) or 0) + 1
        save_state(root, state)
    print(f"Snapshot recorded: {len(changes)} changed files")
    return 0


def explicit_api_token_metrics(payload: Any) -> dict[str, int | None]:
    sample = api_token_adapter(payload, explicit=True)
    return sample["metrics"] if sample is not None else {key: None for key in TOKEN_ALIASES}


def token_metrics_from_status(text: str) -> dict[str, int | None]:
    aliases = {
        "model_input_tokens": ("model input", "input", "prompt"),
        "cached_input_tokens": ("cached input", "cached prompt", "cached"),
        "model_output_tokens": ("model output", "output", "completion"),
        "reasoning_output_tokens": ("reasoning output", "reasoning"),
    }
    result: dict[str, int | None] = {key: None for key in aliases}
    for field, labels in aliases.items():
        for label in labels:
            match = re.search(rf"(?im)^\s*{re.escape(label)}(?:\s+tokens?)?\s*[:=]\s*([0-9][0-9,_ ]*)\s*$", text)
            if match:
                raw = re.sub(r"[^0-9]", "", match.group(1))
                result[field] = safe_integer(int(raw)) if raw else None
                break
    return result


def import_token_metrics(path: str, adapter: str) -> dict[str, Any]:
    limit = 4 * 1024 * 1024
    if path == "-":
        raw = binary_stdin().read(limit + 1)
        raw = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
        if len(raw) > limit:
            raise SystemExit(f"Token telemetry input exceeds the {limit}-byte limit.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit("Token telemetry input is not valid UTF-8.") from exc
    else:
        text = secure_read_text(Path(path).expanduser().resolve(), max_bytes=limit, single_link=False)
    payload: Any = None
    try:
        payload = json.loads(text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, RecursionError, ValueError):
        if adapter not in {"auto", "codex-status"}:
            raise SystemExit(f"The {adapter} adapter requires valid JSON telemetry.") from None
    sample: dict[str, Any] | None = None
    chosen = adapter
    if adapter == "auto":
        candidates: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            api_sample = api_token_adapter(payload)
            otel_sample = otel_token_adapter(payload)
            candidates.extend(item for item in (api_sample, otel_sample) if item is not None)
        else:
            status_metrics = token_metrics_from_status(text)
            if any(value is not None for value in status_metrics.values()):
                candidates.append({
                    "metrics": status_metrics, "source": "codex-status", "semantics": "snapshot",
                    "sample_id": "", "scope": "", "method": "Imported from Codex /status text",
                })
        if len(candidates) > 1:
            raise SystemExit("Automatic Token import is ambiguous; select --adapter api or --adapter otel explicitly.")
        if not candidates:
            raise SystemExit("Automatic Token import did not recognize an explicit API usage, OTel response.completed, or Codex /status shape.")
        sample = candidates[0]
        chosen = str(sample["source"])
    elif chosen == "codex-status":
        metrics = token_metrics_from_status(text)
        if any(value is not None for value in metrics.values()):
            sample = {
                "metrics": metrics, "source": "codex-status", "semantics": "snapshot",
                "sample_id": "", "scope": "", "method": "Imported from Codex /status text",
            }
    elif chosen == "api":
        sample = api_token_adapter(payload, explicit=True)
    else:
        sample = otel_token_adapter(payload)
    if sample is None or not any(value is not None for value in sample["metrics"].values()):
        raise SystemExit(f"No recognized Token metrics were found by the {chosen} adapter.")
    return sample


def command_tokens(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    supplied: dict[str, int | None] = {
        "model_input_tokens": args.model_input, "cached_input_tokens": args.cached_input,
        "model_output_tokens": args.model_output, "reasoning_output_tokens": args.reasoning_output,
        "user_visible_tokens": args.user_visible, "effective_user_tokens": args.effective_user,
        "candidate_context_tokens": args.candidate_context, "retained_context_tokens": args.retained_context,
        "saved_tokens": args.saved,
    }
    source = args.source
    quality = args.quality
    method = args.method
    semantics = args.semantics
    sample_id = args.sample_id or ""
    scope = args.scope or ""
    if args.input:
        if any(value is not None for value in supplied.values()):
            raise SystemExit("Do not combine --input with individual Token metric flags.")
        imported = import_token_metrics(args.input, args.adapter)
        supplied = imported["metrics"]
        source = imported["source"]
        quality = "actual"
        method = method or imported["method"]
        semantics = semantics or imported["semantics"]
        sample_id = sample_id or imported.get("sample_id", "")
        scope = scope or imported.get("scope", "")
    elif not source or not quality:
        raise SystemExit("Manual Token metrics require both --source and --quality.")
    semantics = semantics or ("cumulative" if source == "app-server" else "snapshot")
    with state_lock(root):
        state = load_state(root)
        require_active(state)
        install_viewer(root)
        snapshot, changed = record_token_sample(
            state, supplied, source, quality, args.label, method,
            semantics=semantics, sample_id=sample_id, scope=scope,
        )
        if changed:
            save_state(root, state)
    print(json.dumps(snapshot, ensure_ascii=False, indent=2))
    return 0


def command_run(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("No command supplied after '--'.")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 7 * 24 * 60 * 60:
        raise SystemExit("--timeout must be a finite number greater than zero and no more than seven days.")
    with state_lock(root):
        initial = load_state(root)
        require_active(initial)
        language = initial.get("lang")
        privacy = initial.get("privacy_mode", "standard")
        initial_trace_id = initial.get("trace_id")
    started = time.monotonic()
    return_code, timed_out, raw, launch_error = execute_streaming(command, root, args.timeout)
    duration_ms = round((time.monotonic() - started) * 1_000)
    with state_lock(root):
        state = load_state(root)
        if state.get("trace_id") != initial_trace_id or state.get("status") != "active":
            print("\n[visualizer] Command completed after the original trace closed; result was not attached.", file=sys.stderr)
            return return_code
        state["lang"] = language
        status = "success" if return_code == 0 else "failure"
        if timed_out:
            result = localized(state, "Timed out", "执行超时")
        else:
            result = localized(state, f"Exited with code {return_code}", f"退出码为 {return_code}")
        result += localized(state, f" after {duration_ms / 1000:.2f}s.", f"，耗时 {duration_ms / 1000:.2f} 秒。")
        if launch_error:
            result += f" {launch_error}"
        data: dict[str, Any] = {"command": safe_command_text(command, 1_000), "exit_code": return_code, "timed_out": timed_out}
        tests = parse_test_summary(raw) if args.kind == "test" else None
        if tests:
            data["tests"] = tests
            if int(tests.get("failed", 0)) > 0 or int(tests.get("errors", 0)) > 0:
                status = "failure"
        if args.include_output and raw and privacy == "demo":
            sanitized_output = redact_text(raw)
            excerpt = sanitized_output[-MAX_OUTPUT_EXCERPT:]
            if len(sanitized_output) > MAX_OUTPUT_EXCERPT:
                # Avoid publishing a leading token fragment created by the tail boundary.
                boundary = re.search(r"[\s\r\n]", excerpt)
                excerpt = ("…" + excerpt[boundary.end():]) if boundary else "…[leading fragment omitted]"
            data["output_excerpt"] = excerpt[:MAX_OUTPUT_EXCERPT]
        add_event(state, args.kind, args.label, result, status, data, duration_ms)
        save_state(root, state)
    print(f"\n[visualizer] {args.label}: {result}")
    return return_code


def command_finish(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    with state_lock(root):
        state = load_state(root)
        require_active(state)
        unresolved = [item for item in state.get("plan", []) if isinstance(item, dict) and item.get("status") in {"pending", "in_progress"}]
        blocked = [item for item in state.get("plan", []) if isinstance(item, dict) and item.get("status") == "blocked"]
        if unresolved:
            raise SystemExit(f"Cannot finish while {len(unresolved)} plan step(s) are unresolved.")
        if args.status == "completed" and blocked:
            raise SystemExit("A completed trace cannot contain blocked plan steps; finish as failed or complete them.")
        cancel_automatic_snapshot(state)
        snapshot_event(root, state, localized(state, "Final workspace snapshot", "最终工作区快照"), force=True)
        state["_scan_generation"] = (safe_integer(state.get("_scan_generation"), maximum=10**12) or 0) + 1
        state["status"] = args.status
        state["summary"] = safe_text(args.summary, 2_000)
        state["finished_at"] = now_iso()
        add_event(state, "finish", localized(state, "Build trace completed" if args.status == "completed" else "Build trace failed", "编码记录已完成" if args.status == "completed" else "编码记录失败"), state["summary"], "success" if args.status == "completed" else "failure")
        save_state(root, state)
    print(trace_dir(root) / VIEWER_NAME)
    return 0 if args.status == "completed" else 1


def command_status(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    with state_lock(root):
        state = load_state(root)
        visible = public_state(state)
        result = {
            "dashboard": str(trace_dir(root) / VIEWER_NAME), "status": state.get("status"),
            "title": visible.get("title"), "events": len(visible.get("events", [])),
            "plan": visible.get("plan", []), "token_usage": visible.get("token_usage", {}),
            "privacy_mode": state.get("privacy_mode"), "observability": visible.get("observability", {}),
            "git_diff_quality": "exact" if (state.get("git_baseline") or {}).get("clean") else "net",
            "revision": state.get("revision", 0),
        }
    print(json_dump(result, indent=2))
    return 0


def command_verify(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    result: dict[str, Any] = {
        "valid": False, "recoverable": False, "state_checksum": False,
        "journal_chain": False, "public_artifact": False,
        "privacy_risks": [],
    }
    with state_lock(root):
        state_path = trace_dir(root) / STATE_NAME
        journal_path = trace_dir(root) / JOURNAL_NAME
        state: dict[str, Any] | None = None
        if safe_file_metadata(state_path) is not None:
            try:
                parsed = json.loads(secure_read_text(state_path), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
                state = parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, RecursionError, ValueError):
                state = None
        recovered: dict[str, Any] | None = None
        if safe_file_metadata(journal_path) is not None:
            try:
                recovered = recover_journal(root)
                result["journal_chain"] = True
                result["recoverable"] = True
                if recovered.get("_journal_torn_tail") is True:
                    result["torn_tail_ignored"] = True
            except (SystemExit, RecursionError, ValueError):
                recovered = None
        if state is not None:
            integrity = state.get("integrity") if isinstance(state.get("integrity"), dict) else {}
            state_revision = safe_integer(state.get("revision"), maximum=10**12) or 0
            result["state_checksum"] = bool(
                integrity.get("algorithm") == "sha256-chain-v1"
                and isinstance(integrity.get("head"), str) and len(integrity.get("head")) == 64
                and safe_integer(integrity.get("journal_revision"), maximum=10**12) == state_revision
                and integrity.get("state_checksum") in {integrity_checksum(state), legacy_integrity_checksum(state)}
            )
            same_head = recovered is not None and integrity.get("head") == (recovered.get("integrity") or {}).get("head")
            same_revision = recovered is not None and state.get("revision") == recovered.get("revision")
            expected_public = public_state(copy.deepcopy(state))
            try:
                public_raw = secure_read_text(trace_dir(root) / PUBLIC_NAME)
                prefix = "window.CODEX_BUILD_TRACE="
                suffix = ";if(window.__codexTraceReceive){window.__codexTraceReceive(window.CODEX_BUILD_TRACE);}\n"
                supplied_public = json.loads(public_raw[len(prefix):-len(suffix)]) if public_raw.startswith(prefix) and public_raw.endswith(suffix) else None
                result["public_artifact"] = supplied_public == expected_public
            except (SystemExit, json.JSONDecodeError, RecursionError, ValueError):
                result["public_artifact"] = False
            result["privacy_risks"] = export_privacy_findings(public_state(copy.deepcopy(state)))
            private_valid = bool(result["state_checksum"] and result["journal_chain"] and same_head and same_revision)
            if args.repair_public and private_valid and not result["public_artifact"]:
                repair_public_artifacts(root, state)
                result["public_artifact"] = True
                result["repaired_public"] = True
            result["valid"] = bool(private_valid and result["public_artifact"])
    print(json_dump(result, indent=2))
    return 0 if result["valid"] else 1


def markdown_export(public: dict[str, Any]) -> str:
    def markdown_text(value: Any) -> str:
        text = safe_text(value, 4_000).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", " ").replace("\n", " ")
        text = re.sub(r"(?i)\b(https?|ftp|mailto|file|javascript|data):", r"\1&#58;", text)
        text = re.sub(r"(?i)\bwww\.", "www&#46;", text)
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~\-])", r"\\\1", text)

    events = public.get("events") or []
    latest = public.get("latest_files") or []
    runs = [event for event in events if event.get("kind") in {"command", "test", "build", "verify"}]
    usage = public.get("token_usage") or {}
    lines = [f"# {markdown_text(public.get('title') or 'Codex Build Trace')}", "", f"- Status: {markdown_text(public.get('status'))}", f"- Events: {len(events)}", f"- Changed files: {len(latest)}", f"- Checks: {sum(1 for item in runs if item.get('status') == 'success')}/{len(runs)}", f"- Privacy: {markdown_text(public.get('privacy_mode', 'standard'))}"]
    omitted = safe_integer((public.get("observability") or {}).get("events_dropped"))
    if omitted:
        lines.append(f"- Older events omitted: {omitted}")
    if usage.get("model_input_tokens") is not None:
        lines.append(f"- Model input Tokens: {usage['model_input_tokens']}")
    if usage.get("effective_user_tokens") is not None:
        lines.append(f"- Effective user Tokens: {usage['effective_user_tokens']} ({(usage.get('field_quality') or {}).get('effective_user_tokens', 'derived')})")
    lines.extend(["", "## Plan", ""])
    for item in public.get("plan") or []:
        lines.append(f"- [{ 'x' if item.get('status') == 'completed' else ' ' }] {markdown_text(item.get('title'))} — {markdown_text(item.get('status'))}")
    lines.extend(["", "## Timeline", ""])
    for event in events:
        lines.append(f"- {markdown_text(event.get('at'))} — **{markdown_text(event.get('title'))}** ({markdown_text(event.get('status'))})")
    history = public.get("history") if isinstance(public.get("history"), dict) else {}
    runs = history.get("runs") if isinstance(history.get("runs"), list) else []
    if runs:
        lines.extend(["", "## Prior run summaries", ""])
        for index, run in enumerate(runs, 1):
            metrics = run.get("metrics") if isinstance(run, dict) and isinstance(run.get("metrics"), dict) else {}
            lines.append(
                f"- Run {index}: {markdown_text(run.get('status'))}; checks {safe_integer((metrics.get('checks') or {}).get('passed')) or 0}/{safe_integer((metrics.get('checks') or {}).get('total')) or 0}; files {safe_integer(metrics.get('files_changed')) or 0}"
            )
    return "\n".join(lines) + "\n"


def export_privacy_findings(value: Any) -> list[str]:
    findings: set[str] = set()
    stack = [value]
    visited = 0
    while stack and visited < MAX_JSON_NODES:
        item = stack.pop()
        visited += 1
        if isinstance(item, dict):
            stack.extend(list(item.values())[:2_000])
        elif isinstance(item, list):
            stack.extend(item[:2_000])
        elif isinstance(item, str):
            if redact_text(item) != item:
                findings.add("known-sensitive-pattern")
            if re.search(r"(?is)<\s*/?\s*(?:script|img|iframe|object|embed|svg|style|link|meta)\b", item):
                findings.add("active-markup")
            if re.search(r"(?i)\b(?:javascript\s*:|data\s*:\s*text/html)", item):
                findings.add("active-url-scheme")
            if re.search(r"(?i)(?:^|[\s'\"])(?:/Users/|/home/|[A-Z]:\\Users\\)[^\s'\"]+", item):
                findings.add("user-home-path")
    return sorted(findings)


def export_public_state(state: dict[str, Any], *, force_strict: bool, fail_on_finding: bool) -> dict[str, Any]:
    candidate = copy.deepcopy(state)
    requested_mode = candidate.get("privacy_mode", "standard")
    if force_strict:
        candidate["privacy_mode"] = "strict"
    public = public_state(candidate)
    findings = export_privacy_findings(public)
    applied_fallback = False
    if findings and candidate.get("privacy_mode") != "strict":
        if fail_on_finding:
            raise SystemExit(f"Export privacy scan found {len(findings)} risk category/categories; rerun with --strict or use the default automatic fallback.")
        candidate["privacy_mode"] = "strict"
        public = public_state(candidate)
        applied_fallback = True
        findings = export_privacy_findings(public)
    if findings:
        raise SystemExit(f"Strict export privacy scan still found {len(findings)} risk category/categories; export was refused.")
    public["export_guard"] = {
        "scan": "passed", "requested_mode": requested_mode,
        "applied_mode": candidate.get("privacy_mode", "strict"),
        "strict_fallback": applied_fallback or force_strict,
    }
    return public


def command_export(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    with state_lock(root):
        state = load_state(root)
        public = export_public_state(state, force_strict=args.strict, fail_on_finding=args.privacy_check == "fail")
        if args.include_history:
            public["history"] = load_history(trace_dir(root))
            history_findings = export_privacy_findings(public)
            if history_findings:
                raise SystemExit("Export privacy scan found risky content in history summaries; export was refused.")
        extension = {"html": ".html", "markdown": ".md", "json": ".json"}[args.format]
        managed = trace_dir(root).resolve()
        if args.output:
            supplied = Path(args.output).expanduser()
            lexical = Path(os.path.abspath(supplied))
            try:
                lexical_relative = lexical.parent.relative_to(managed)
            except ValueError:
                lexical_relative = None
            if lexical_relative is not None:
                if not lexical_relative.parts or lexical_relative.parts[0] != "export":
                    raise SystemExit("Refusing to export over managed trace state; choose a path outside .codex-visualizer or inside its export directory.")
                # Keep managed components unresolved so the no-follow writer can
                # reject a planted export-directory symlink.
                destination = lexical
            else:
                parent = supplied.parent.resolve()
                destination = parent / supplied.name
        else:
            destination = trace_dir(root) / "export" / f"trace{extension}"
        try:
            managed_relative = destination.parent.resolve().relative_to(managed)
        except ValueError:
            managed_relative = None
        if managed_relative is not None and (not managed_relative.parts or managed_relative.parts[0] != "export"):
            raise SystemExit("Refusing to export over managed trace state; choose a path outside .codex-visualizer or inside its export directory.")
        private_parent = managed_relative is not None and bool(managed_relative.parts) and managed_relative.parts[0] == "export"
        if args.format == "json":
            content = json_dump(public, indent=2) + "\n"
        elif args.format == "markdown":
            content = markdown_export(public)
        else:
            viewer = (Path(__file__).resolve().parent.parent / "assets" / "viewer.html").read_text(encoding="utf-8")
            embedded: dict[str, Any] = {"standalone": True, "trace": copy.deepcopy(public)}
            if args.include_history:
                embedded["history"] = public.get("history", {})
                embedded["trace"].pop("history", None)
            payload = json_for_script(embedded)
            placeholder = '<script id="codexTracePayload" type="application/json">{}</script>'
            if viewer.count(placeholder) != 1 or viewer.count('<script src="events.js"></script>') != 1:
                raise SystemExit("Viewer standalone placeholders are missing or ambiguous.")
            content = viewer.replace(
                placeholder,
                f'<script id="codexTracePayload" type="application/json">{payload}</script>',
            ).replace('<script src="events.js"></script>', "")
        atomic_write(destination, content, private_parent=private_parent)
    print(destination)
    return 0


def command_hooks(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    if args.snapshot_debounce_ms is not None and not 100 <= args.snapshot_debounce_ms <= 10_000:
        raise SystemExit("--snapshot-debounce-ms must be from 100 through 10000.")
    generated = hooks_config()
    if not args.install and not args.uninstall:
        print(json_dump(generated, indent=2))
        return 0
    destination = root / ".codex" / "hooks.json"
    try:
        destination.lstat()
        exists = True
    except FileNotFoundError:
        exists = False
    if args.uninstall and not exists:
        try:
            with state_lock(root):
                state = load_state(root)
                if state.get("status") == "active":
                    state.setdefault("observability", {})["hooks"] = False
                    state.setdefault("observability", {})["hooks_ever_installed"] = True
                    cancel_automatic_snapshot(state)
                    save_state(root, state)
        except SystemExit:
            pass
        print(destination)
        return 0
    if exists:
        try:
            current = json.loads(secure_read_text(destination, max_bytes=4 * 1024 * 1024), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise SystemExit(f"Cannot merge invalid hooks file: {exc}") from exc
    else:
        current = {"description": "Project lifecycle hooks.", "hooks": {}}
    if not isinstance(current, dict) or not isinstance(current.get("hooks", {}), dict):
        raise SystemExit("Cannot merge hooks file because its root and hooks field must be objects.")
    current_hooks = current.setdefault("hooks", {})
    owned_commands = {
        hook.get("command")
        for groups in generated["hooks"].values()
        for group in groups if isinstance(group, dict)
        for hook in group.get("hooks", []) if isinstance(hook, dict)
    }
    owned_script = str(Path(__file__).resolve())

    def is_owned_hook(hook: Any) -> bool:
        if not isinstance(hook, dict) or not isinstance(hook.get("command"), str):
            return False
        command = hook["command"]
        if command in owned_commands:
            return True
        try:
            parts = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return False
        if len(parts) < 3 or parts[-1] != "hook" or parts[-2] != owned_script:
            return False
        launcher = parts[0]
        launcher_name = Path(launcher).name
        launcher_ok = Path(launcher).resolve() == Path(sys.executable).resolve() or re.fullmatch(
            r"(?i)(?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?", launcher_name,
        ) is not None
        options = parts[1:-2]
        options_ok = options in ([], ["-B"], ["-3", "-B"])
        return launcher_ok and options_ok

    if args.install:
        for event_name in list(current_hooks):
            groups = current_hooks.get(event_name)
            if not isinstance(groups, list):
                continue
            cleaned_groups = []
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                    cleaned_groups.append(group)
                    continue
                kept_hooks = [hook for hook in group["hooks"] if not is_owned_hook(hook)]
                if kept_hooks:
                    replacement = copy.deepcopy(group)
                    replacement["hooks"] = kept_hooks
                    cleaned_groups.append(replacement)
            if cleaned_groups:
                current_hooks[event_name] = cleaned_groups
            else:
                current_hooks.pop(event_name, None)

    if args.uninstall:
        for event_name in list(current_hooks):
            groups = current_hooks.get(event_name)
            if not isinstance(groups, list):
                continue
            kept_groups = []
            for group in groups:
                if not isinstance(group, dict):
                    kept_groups.append(group)
                    continue
                hooks = group.get("hooks")
                if not isinstance(hooks, list):
                    kept_groups.append(group)
                    continue
                kept_hooks = [hook for hook in hooks if not is_owned_hook(hook)]
                if kept_hooks:
                    replacement = copy.deepcopy(group)
                    replacement["hooks"] = kept_hooks
                    kept_groups.append(replacement)
            if kept_groups:
                current_hooks[event_name] = kept_groups
            else:
                current_hooks.pop(event_name, None)
    else:
        for event_name, groups in generated["hooks"].items():
            destination_groups = current_hooks.setdefault(event_name, [])
            for group in groups:
                destination_groups.append(group)
    atomic_write(destination, json_dump(current, indent=2) + "\n")
    try:
        with state_lock(root):
            state = load_state(root)
            if state.get("status") == "active":
                generated_paths = state.setdefault("_generated_paths", [])
                if ".codex/hooks.json" not in generated_paths:
                    generated_paths.append(".codex/hooks.json")
                state.setdefault("observability", {})["hooks"] = not args.uninstall
                state.setdefault("observability", {})["hooks_ever_installed"] = True
                if args.uninstall:
                    cancel_automatic_snapshot(state)
                else:
                    policy = state.setdefault("snapshot_policy", {})
                    policy["mode"] = "off" if args.no_auto_snapshot else "auto"
                    policy["debounce_ms"] = args.snapshot_debounce_ms or (
                        safe_integer(policy.get("debounce_ms"), maximum=10_000) or AUTO_SNAPSHOT_DEBOUNCE_MS
                    )
                save_state(root, state)
    except SystemExit:
        pass
    print(destination)
    return 0


def parse_untrusted_json_object(raw: bytes, *, limit: int) -> dict[str, Any] | None:
    if not raw or len(raw) > limit:
        return None
    try:
        text = raw.decode("utf-8")
        payload = json.loads(text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    stack: list[tuple[Any, int]] = [(payload, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return None
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return payload


def binary_stdin() -> Any:
    return getattr(sys.stdin, "buffer", sys.stdin)


def iter_jsonl_objects(handle: Any) -> Iterator[tuple[dict[str, Any], int]]:
    while True:
        raw = handle.readline(MAX_JSONL_BYTES + 1)
        if not raw:
            return
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        oversized = len(raw) > MAX_JSONL_BYTES
        if oversized and not raw.endswith(b"\n"):
            while raw and not raw.endswith(b"\n"):
                raw = handle.readline(MAX_JSONL_BYTES + 1)
                if isinstance(raw, str):
                    raw = raw.encode("utf-8", errors="replace")
        if oversized:
            continue
        payload = parse_untrusted_json_object(raw, limit=MAX_JSONL_BYTES)
        if payload is not None:
            yield payload, len(raw)


def spawn_autosnapshot_worker(root: Path, ticket: str) -> None:
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "_autosnapshot", "--root", str(root), "--ticket", ticket]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL, "close_fds": True, "cwd": str(root),
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(command, **kwargs)


def record_autosnapshot_failure(root: Path, ticket: str) -> None:
    """Release a failed worker ticket without disturbing a replacement worker."""
    try:
        with state_lock(root):
            state = load_state(root)
            auto = state.get("_auto_snapshot") if isinstance(state.get("_auto_snapshot"), dict) else {}
            if auto.get("ticket") != ticket:
                return
            cancel_automatic_snapshot(state)
            observability = state.setdefault("observability", {})
            observability["auto_snapshot_failures"] = (
                safe_integer(observability.get("auto_snapshot_failures"), maximum=10**12) or 0
            ) + 1
            save_state(root, state)
    except (SystemExit, OSError, TypeError, ValueError, OverflowError, RecursionError):
        return


def command_autosnapshot(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    expires = time.monotonic() + 10 * 60
    while time.monotonic() < expires:
        with state_lock(root):
            state = load_state(root)
            if state.get("status") != "active":
                return 0
            auto = state.get("_auto_snapshot") if isinstance(state.get("_auto_snapshot"), dict) else {}
            if auto.get("ticket") != args.ticket or auto.get("pending_generation") is None:
                return 0
            due_at = safe_integer(auto.get("due_at_ms"), maximum=10**15)
            if due_at is None:
                cancel_automatic_snapshot(state)
                state.setdefault("observability", {})["auto_snapshot_failures"] = (
                    safe_integer(state.setdefault("observability", {}).get("auto_snapshot_failures"), maximum=10**12) or 0
                ) + 1
                save_state(root, state)
                return 0
            current_ms = round(time.time() * 1_000)
            started_now = safe_integer(auto.get("worker_started_at_ms"), maximum=10**15) is None
            if started_now:
                auto["worker_started_at_ms"] = current_ms
            wait_seconds = max(0.0, (due_at - current_ms) / 1_000)
            if wait_seconds <= 0:
                auto["heartbeat_at_ms"] = current_ms
                auto["lease_until_ms"] = current_ms + AUTO_SNAPSHOT_LEASE_MS
                save_state(root, state)
                trace_id = str(state.get("trace_id") or "")
                edit_generation = safe_integer(auto.get("pending_generation"), maximum=10**12) or 0
                scan_generation = safe_integer(state.get("_scan_generation"), maximum=10**12) or 0
                scan_state = copy.deepcopy(state)
            else:
                if started_now:
                    auto["heartbeat_at_ms"] = current_ms
                    auto["lease_until_ms"] = current_ms + AUTO_SNAPSHOT_LEASE_MS
                    save_state(root, state)
                scan_state = None
        if scan_state is None:
            time.sleep(min(wait_seconds, 0.5))
            continue
        try:
            changes, truncated, quality = prepare_snapshot(root, scan_state)
        except (SystemExit, OSError, TypeError, ValueError, OverflowError, RecursionError):
            with state_lock(root):
                failed = load_state(root)
                failed_auto = failed.get("_auto_snapshot") if isinstance(failed.get("_auto_snapshot"), dict) else {}
                if failed.get("trace_id") == trace_id and failed_auto.get("ticket") == args.ticket:
                    cancel_automatic_snapshot(failed)
                    failed.setdefault("observability", {})["auto_snapshot_failures"] = (
                        safe_integer(failed.setdefault("observability", {}).get("auto_snapshot_failures"), maximum=10**12) or 0
                    ) + 1
                    save_state(root, failed)
            return 0
        with state_lock(root):
            current = load_state(root)
            current_auto = current.get("_auto_snapshot") if isinstance(current.get("_auto_snapshot"), dict) else {}
            if current.get("status") != "active" or current.get("trace_id") != trace_id or current_auto.get("ticket") != args.ticket:
                return 0
            current_generation = safe_integer(current_auto.get("pending_generation"), maximum=10**12) or 0
            current_scan_generation = safe_integer(current.get("_scan_generation"), maximum=10**12) or 0
            if current_generation != edit_generation or current_scan_generation != scan_generation:
                now_ms = round(time.time() * 1_000)
                current_auto["heartbeat_at_ms"] = now_ms
                current_auto["lease_until_ms"] = now_ms + AUTO_SNAPSHOT_LEASE_MS
                save_state(root, current)
                continue
            current["_scan_cache"] = copy.deepcopy(scan_state.get("_scan_cache", {}))
            if scan_state.get("_scan_cache_dirty"):
                current["_scan_cache_dirty"] = True
            scan_observability = scan_state.get("observability") if isinstance(scan_state.get("observability"), dict) else {}
            if isinstance(scan_observability.get("last_scan"), dict):
                current.setdefault("observability", {})["last_scan"] = copy.deepcopy(scan_observability["last_scan"])
            publish_prepared_snapshot(
                current, changes, truncated, quality,
                localized(current, "Automatic edit snapshot", "自动编辑快照"),
                localized(current, "Debounced workspace changes were measured.", "已测量合并后的工作区变化。"),
            )
            current_auto = current.setdefault("_auto_snapshot", {})
            current_auto["last_completed_generation"] = edit_generation
            current_auto["last_completed_at"] = now_iso()
            current_auto.pop("ticket", None)
            current_auto.pop("pending_generation", None)
            current_auto.pop("due_at_ms", None)
            current["_scan_generation"] = current_scan_generation + 1
            observability = current.setdefault("observability", {})
            observability["automatic_snapshots"] = (safe_integer(observability.get("automatic_snapshots"), maximum=10**12) or 0) + 1
            save_state(root, current)
            return 0
    record_autosnapshot_failure(root, args.ticket)
    return 0


def command_hook(args: argparse.Namespace) -> int:
    del args
    handle = binary_stdin()
    raw = handle.read(min(MAX_JSONL_BYTES, 1024 * 1024) + 1)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    payload = parse_untrusted_json_object(raw, limit=min(MAX_JSONL_BYTES, 1024 * 1024))
    if payload is None:
        print("{}")
        return 0
    root = find_trace_root(payload.get("cwd"))
    if root is not None:
        try:
            ticket = handle_hook_payload(root, payload)
            if ticket:
                try:
                    spawn_autosnapshot_worker(root, ticket)
                except (OSError, subprocess.SubprocessError):
                    record_autosnapshot_failure(root, ticket)
        except (SystemExit, OSError, TypeError, ValueError, OverflowError, RecursionError):
            pass
    print("{}")
    return 0


def command_ingest(args: argparse.Namespace) -> int:
    root = root_path(args.root)
    try:
        handle = binary_stdin() if args.file == "-" else Path(args.file).expanduser().open("rb")
    except OSError as exc:
        raise SystemExit(f"Cannot open ingestion file: {safe_text(exc, 1_000)}") from None
    count = 0
    retained = 0
    dropped = 0
    stale = False
    with state_lock(root):
        initial = load_state(root)
        require_active(initial)
        trace_id = initial.get("trace_id")

    def commit_batch(batch: list[dict[str, Any]]) -> None:
        nonlocal count, retained, dropped, stale
        if not batch or stale:
            return
        with state_lock(root):
            state = load_state(root)
            if state.get("trace_id") != trace_id or state.get("status") != "active":
                stale = True
                return
            changed = 0
            for message in batch:
                try:
                    if ingest_message(state, message, args.source):
                        changed += 1
                except (SystemExit, OSError, TypeError, ValueError, OverflowError, RecursionError):
                    continue
            if changed:
                sources = state.setdefault("observability", {}).setdefault("ingest_sources", [])
                if args.source not in sources:
                    sources.append(args.source)
                save_state(root, state)
                count += changed
            retained = len(state.get("events", []))
            dropped = int((state.get("observability") or {}).get("events_dropped", 0))

    try:
        batch: list[dict[str, Any]] = []
        batch_bytes = 0
        for message, raw_bytes in iter_jsonl_objects(handle):
            if batch and (len(batch) >= INGEST_BATCH_SIZE or batch_bytes + raw_bytes > MAX_INGEST_BATCH_BYTES):
                commit_batch(batch)
                batch = []
                batch_bytes = 0
                if stale:
                    break
            batch.append(message)
            batch_bytes += raw_bytes
        commit_batch(batch)
    finally:
        if args.file != "-":
            handle.close()
    suffix = f"; retained timeline: {retained}, older events omitted: {dropped}" if dropped else f"; retained timeline: {retained}"
    print(f"Ingested {count} observable events{suffix}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record observable coding work as a local replay dashboard.")
    subparsers = parser.add_subparsers(dest="operation", required=True)

    init = subparsers.add_parser("init", help="Start a new build trace")
    init.add_argument("--root", required=True)
    init.add_argument("--title", required=True)
    init.add_argument("--lang", choices=("auto", "en", "zh"), default="auto")
    init.add_argument("--privacy", choices=("strict", "standard", "demo"), default="standard")
    init.set_defaults(handler=command_init)

    plan = subparsers.add_parser("plan", help="Add or update a plan step")
    plan.add_argument("--root", required=True)
    plan.add_argument("--id", required=True)
    plan.add_argument("--title", required=True)
    plan.add_argument("--status", required=True, choices=("pending", "in_progress", "completed", "blocked"))
    plan.set_defaults(handler=command_plan)

    event = subparsers.add_parser("event", help="Record a factual milestone")
    event.add_argument("--root", required=True)
    event.add_argument("--kind", default="note")
    event.add_argument("--title", required=True)
    event.add_argument("--detail", default="")
    event.add_argument("--status", choices=("info", "pending", "running", "success", "failure", "warning"), default="info")
    event.set_defaults(handler=command_event)

    snapshot = subparsers.add_parser("snapshot", help="Record file changes from baseline")
    snapshot.add_argument("--root", required=True)
    snapshot.add_argument("--title", default="Workspace updated")
    snapshot.add_argument("--detail", default="")
    snapshot.add_argument("--full", action="store_true", help="Bypass the incremental fingerprint cache")
    snapshot.set_defaults(handler=command_snapshot)

    tokens = subparsers.add_parser("tokens", help="Record Token usage and context metrics")
    tokens.add_argument("--root", required=True)
    tokens.add_argument("--label", default="Token usage updated")
    tokens.add_argument("--source", choices=("app-server", "otel", "codex-status", "api", "estimate", "manual"))
    tokens.add_argument("--quality", choices=("actual", "estimated", "mixed"))
    tokens.add_argument("--method", default="")
    tokens.add_argument("--input", help="Import bounded API, OTel, or Codex /status Token telemetry from a file or '-' for stdin")
    tokens.add_argument("--adapter", choices=("auto", "api", "otel", "codex-status"), default="auto")
    tokens.add_argument("--semantics", choices=("snapshot", "cumulative", "delta"), help="Interpret the sample as a snapshot, cumulative counter, or per-event delta")
    tokens.add_argument("--sample-id", help="Stable response or event ID used for private deduplication")
    tokens.add_argument("--scope", help="Session or stream scope for cumulative counters")
    tokens.add_argument("--model-input", type=int)
    tokens.add_argument("--cached-input", type=int)
    tokens.add_argument("--model-output", type=int)
    tokens.add_argument("--reasoning-output", type=int)
    tokens.add_argument("--user-visible", type=int)
    tokens.add_argument("--effective-user", type=int)
    tokens.add_argument("--candidate-context", type=int)
    tokens.add_argument("--retained-context", type=int)
    tokens.add_argument("--saved", type=int)
    tokens.set_defaults(handler=command_tokens)

    run = subparsers.add_parser("run", help="Run and record a command without a shell")
    run.add_argument("--root", required=True)
    run.add_argument("--kind", choices=("command", "test", "build", "verify"), default="command")
    run.add_argument("--label", required=True)
    run.add_argument("--timeout", type=float, default=900)
    run.add_argument("--include-output", action="store_true", help="Publish a sanitized excerpt in demo privacy mode")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(handler=command_run)

    finish = subparsers.add_parser("finish", help="Close the trace")
    finish.add_argument("--root", required=True)
    finish.add_argument("--status", choices=("completed", "failed"), default="completed")
    finish.add_argument("--summary", required=True)
    finish.set_defaults(handler=command_finish)

    status = subparsers.add_parser("status", help="Print trace status as JSON")
    status.add_argument("--root", required=True)
    status.set_defaults(handler=command_status)

    verify = subparsers.add_parser("verify", help="Verify state, journal, public artifact, and privacy indicators")
    verify.add_argument("--root", required=True)
    verify.add_argument("--repair-public", action="store_true", help="Regenerate public artifacts only after private integrity verifies")
    verify.set_defaults(handler=command_verify)

    export = subparsers.add_parser("export", help="Export a privacy-filtered standalone trace")
    export.add_argument("--root", required=True)
    export.add_argument("--format", choices=("html", "markdown", "json"), default="html")
    export.add_argument("--output")
    export.add_argument("--strict", action="store_true", help="Force an anonymized strict export without changing the live trace")
    export.add_argument("--privacy-check", choices=("auto", "fail"), default="auto", help="Fall back to strict or fail when the pre-export scanner finds risky content")
    export.add_argument("--include-history", action="store_true", help="Include privacy-minimized prior-run summaries")
    export.set_defaults(handler=command_export)

    hooks = subparsers.add_parser("hooks", help="Print or install optional Codex lifecycle hooks")
    hooks.add_argument("--root", required=True)
    hook_action = hooks.add_mutually_exclusive_group()
    hook_action.add_argument("--install", action="store_true")
    hook_action.add_argument("--uninstall", action="store_true")
    auto_snapshot = hooks.add_mutually_exclusive_group()
    auto_snapshot.add_argument("--auto-snapshot", action="store_true", help="Enable automatic debounced snapshots (default on install)")
    auto_snapshot.add_argument("--no-auto-snapshot", action="store_true", help="Disable automatic snapshots while keeping lifecycle hooks")
    hooks.add_argument("--snapshot-debounce-ms", type=int)
    hooks.set_defaults(handler=command_hooks)

    hook = subparsers.add_parser("hook", help="Internal lifecycle adapter")
    hook.set_defaults(handler=command_hook)

    autosnapshot = subparsers.add_parser("_autosnapshot", help=argparse.SUPPRESS)
    autosnapshot.add_argument("--root", required=True)
    autosnapshot.add_argument("--ticket", required=True)
    autosnapshot.set_defaults(handler=command_autosnapshot)

    ingest = subparsers.add_parser("ingest", help="Ingest App Server or codex exec JSONL events")
    ingest.add_argument("--root", required=True)
    ingest.add_argument("--source", choices=("app-server", "codex-jsonl"), required=True)
    ingest.add_argument("--file", default="-", help="JSONL file or '-' for stdin")
    ingest.set_defaults(handler=command_ingest)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
