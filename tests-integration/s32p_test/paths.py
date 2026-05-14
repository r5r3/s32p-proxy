"""Locate the workspace root and built binaries.

Single-uid mode (the default) just needs the three binaries built into
target/<profile>/. Override the profile via S32P_CARGO_PROFILE=release if
you want to test optimized builds. Override the repo root via
S32P_REPO_ROOT for out-of-tree test runs.
"""

from __future__ import annotations

import os
from pathlib import Path


def _find_repo_root() -> Path:
    """Walk up from this file until we hit the workspace Cargo.toml."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cargo = parent / "Cargo.toml"
        if cargo.exists() and "[workspace]" in cargo.read_text():
            return parent
    raise RuntimeError(f"workspace root not found above {here}")


REPO_ROOT: Path = Path(os.environ.get("S32P_REPO_ROOT") or _find_repo_root())


def _profile_dir() -> Path:
    profile = os.environ.get("S32P_CARGO_PROFILE", "debug")
    return REPO_ROOT / "target" / profile


def _required_binary(name: str) -> Path:
    p = _profile_dir() / name
    if not p.exists():
        raise FileNotFoundError(
            f"{name} not found at {p}\n"
            f"Build it with: cargo build --bin {name}\n"
            f"Or set S32P_CARGO_PROFILE=release to use target/release/."
        )
    return p


def proxy_binary() -> Path:
    return _required_binary("s32p-proxy")


def gateway_binary() -> Path:
    return _required_binary("s32p-gateway")


def restricted_exec_binary() -> Path:
    return _required_binary("restricted-exec")


def s32p_ctl_binary() -> Path:
    return _required_binary("s32p-ctl")
