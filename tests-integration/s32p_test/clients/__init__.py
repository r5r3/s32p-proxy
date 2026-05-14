"""Client matrix.

Adding a new S3 client = drop a module in here that subclasses S3Client and
imports cleanly. This package's `discover()` walks the registry built up by
S3Client.__init_subclass__ and returns the active set, filtered by the
--clients pytest CLI option.
"""

from __future__ import annotations

import importlib
import pkgutil

from .base import S3Client

# Eagerly import every sibling module so that S3Client subclasses register
# themselves via __init_subclass__. New adapters become visible by file
# presence alone — no central list to maintain.
for _mod in pkgutil.iter_modules(__path__):
    if _mod.name in {"base", "capabilities"}:
        continue
    importlib.import_module(f"{__name__}.{_mod.name}")


def discover(only: list[str] | None = None) -> list[type[S3Client]]:
    """Return registered client classes, optionally filtered by name."""
    classes = list(S3Client.registry.values())
    if only:
        wanted = set(only)
        classes = [c for c in classes if c.name in wanted]
        missing = wanted - {c.name for c in classes}
        if missing:
            raise ValueError(f"unknown client(s): {sorted(missing)}")
    return classes


__all__ = ["S3Client", "discover"]
