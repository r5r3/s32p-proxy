"""Direct POSIX access to a bucket's backend data directory.

The point of this suite is interop: tests assert that what one side does
on disk is observable on the other side. `BackendFs` is the disk side —
plain `pathlib` calls scoped to one bucket's `data_path`.

Single-uid mode (today): all calls run as the test runner. Multi-uid mode
(future): we add a `BackendFs(uid=N)` variant that shells out via
`sudo -u <user>` so each interop test can pick which POSIX user touches
the file. The S3 side observes whatever ACL/permission consequence falls
out — that's the test.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class BackendFs:
    """All paths are relative to `root` (the bucket's `data_path`)."""

    root: Path

    def _abs(self, key: str) -> Path:
        # No `os.path.join` of absolute keys — guard against accidental escape.
        if key.startswith("/"):
            raise ValueError(f"key must be relative, got {key!r}")
        return self.root / key

    # ----- writes -----

    def write(self, key: str, data: bytes, *, mkdirs: bool = True) -> Path:
        """Create file at root/key with given bytes. Parent dirs auto-created."""
        path = self._abs(key)
        if mkdirs:
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def mkdir(self, key: str, *, parents: bool = True, mode: int = 0o755) -> Path:
        path = self._abs(key)
        path.mkdir(parents=parents, exist_ok=True, mode=mode)
        return path

    def symlink(self, target: str | Path, link_name: str, *, mkdirs: bool = True) -> Path:
        """Create root/link_name → target. `target` is taken verbatim — pass
        an absolute path or a path relative to link_name's parent dir."""
        link = self._abs(link_name)
        if mkdirs:
            link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
        return link

    def rename(self, src_key: str, dst_key: str, *, mkdirs: bool = True) -> None:
        src = self._abs(src_key)
        dst = self._abs(dst_key)
        if mkdirs:
            dst.parent.mkdir(parents=True, exist_ok=True)
        os.rename(src, dst)

    def chmod(self, key: str, mode: int) -> None:
        self._abs(key).chmod(mode)

    # ----- reads / queries -----

    def read(self, key: str) -> bytes:
        return self._abs(key).read_bytes()

    def exists(self, key: str, *, follow: bool = True) -> bool:
        path = self._abs(key)
        if follow:
            return path.exists()
        return path.is_symlink() or path.exists()

    def stat(self, key: str, *, follow: bool = True) -> os.stat_result:
        path = self._abs(key)
        return path.stat() if follow else path.lstat()

    def listdir(self, prefix: str = "") -> list[str]:
        """Sorted basenames at root/prefix (one level, no recursion)."""
        target = self._abs(prefix) if prefix else self.root
        return sorted(p.name for p in target.iterdir())

    # ----- deletes -----

    def rm(self, key: str) -> None:
        self._abs(key).unlink()

    def rmdir(self, key: str) -> None:
        self._abs(key).rmdir()

    def rmtree(self, key: str = "") -> None:
        """Recursively delete root/key (or the entire bucket dir if key=='')."""
        target = self._abs(key) if key else self.root
        if not target.exists():
            return
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
