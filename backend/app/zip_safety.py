"""
Safe ZIP extraction.

Every uploaded archive is untrusted input. This module enforces hard limits
before anything is written to disk, and re-validates the resolved path of
every member so nothing can escape the target workspace directory.
"""
from __future__ import annotations

import os
import zipfile
import io
from dataclasses import dataclass

MAX_UPLOAD_BYTES = 25 * 1024 * 1024        # 25 MB compressed
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024    # 100 MB uncompressed
MAX_MEMBERS = 5000
MAX_TEXT_FILE_BYTES = int(1.5 * 1024 * 1024)
COPY_CHUNK_BYTES = 1024 * 1024


class ZipSafetyError(ValueError):
    """Raised whenever an archive fails a safety check. Message is safe to show the user."""


@dataclass
class ExtractionResult:
    files_extracted: int
    total_bytes: int
    skipped_members: list
    nested_archives: list[str] | None = None


def _limit_from_env(name: str, default: int) -> int:
    """Read a positive byte/member limit without allowing an unsafe value."""
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _is_within_directory(directory: str, target: str) -> bool:
    directory = os.path.realpath(directory)
    target = os.path.realpath(target)
    return os.path.commonpath([directory]) == os.path.commonpath([directory, target])


def _reject_member_path(name: str) -> str | None:
    if name.startswith("/") or name.startswith("\\"):
        return "absolute path"
    if len(name) >= 2 and name[1] == ":":  # Windows drive letter, e.g. C:
        return "windows drive path"
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if any(part == ".." for part in parts):
        return "path traversal"
    return None


def safe_extract_zip(zip_bytes: bytes, destination_dir: str) -> ExtractionResult:
    upload_limit = _limit_from_env("CLANKER_MAX_UPLOAD_BYTES", MAX_UPLOAD_BYTES)
    extracted_limit = _limit_from_env("CLANKER_MAX_EXTRACTED_BYTES", MAX_EXTRACTED_BYTES)
    member_limit = _limit_from_env("CLANKER_MAX_MEMBERS", MAX_MEMBERS)
    if len(zip_bytes) > upload_limit:
        raise ZipSafetyError(
            f"Archive is too large ({len(zip_bytes) // (1024*1024)} MB). "
            f"The limit is {upload_limit // (1024*1024)} MB."
        )

    os.makedirs(destination_dir, exist_ok=True)
    skipped: list[str] = []
    nested_archives: list[str] = []
    seen_paths: set[str] = set()
    total_bytes = 0
    files_extracted = 0

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ZipSafetyError("This does not look like a valid ZIP archive.")

    with zf:
        infolist = zf.infolist()
        if len(infolist) > member_limit:
            raise ZipSafetyError(
                f"Archive contains too many files ({len(infolist)}). "
                f"The limit is {member_limit}."
            )

        for info in infolist:
            name = info.filename
            if name.endswith("/"):
                continue  # directory entry

            reason = _reject_member_path(name)
            if reason:
                skipped.append(f"{name} (rejected: {reason})")
                continue

            normalized_name = name.replace("\\", "/")
            if normalized_name in seen_paths:
                raise ZipSafetyError(f"Archive contains a duplicate path: {name}")
            seen_paths.add(normalized_name)

            # Reject symlinks: the upper 16 bits of external_attr hold the
            # unix file mode when created on a POSIX system.
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            is_symlink = bool(unix_mode) and (unix_mode & 0xF000) == 0xA000
            if is_symlink:
                skipped.append(f"{name} (rejected: symlink)")
                continue

            target_path = os.path.join(destination_dir, name)
            if not _is_within_directory(destination_dir, target_path):
                skipped.append(f"{name} (rejected: escapes workspace)")
                continue

            total_bytes += info.file_size
            if total_bytes > extracted_limit:
                raise ZipSafetyError(
                    f"Extracted contents exceed the {extracted_limit // (1024*1024)} MB limit."
                )

            if normalized_name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar")):
                # Keep the archive as source material, but never recursively
                # unpack an attacker-controlled nested archive.
                nested_archives.append(name)

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            written = 0
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    written += len(chunk)
                    # The central-directory size is untrusted. Enforce the
                    # limit against bytes actually decompressed as well.
                    if written > info.file_size or total_bytes - info.file_size + written > extracted_limit:
                        raise ZipSafetyError("Archive decompression exceeded the configured limit.")
                    dst.write(chunk)
            files_extracted += 1

    if files_extracted == 0:
        raise ZipSafetyError("The archive did not contain any usable files.")

    return ExtractionResult(
        files_extracted=files_extracted,
        total_bytes=total_bytes,
        skipped_members=skipped,
        nested_archives=nested_archives,
    )
