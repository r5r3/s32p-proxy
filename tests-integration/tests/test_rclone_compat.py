"""Compatibility checks driven by rclone.

Four complementary probes:

  * `test info --check-streaming` — proves the gateway accepts an
    unsized PUT (routed into the MPU assembly path).
  * `test info --check-control` — proves a control-character probe
    completes end-to-end (without asserting individual chars).
  * `test makefiles` + `copy` + `check --download` — generates a random
    file tree locally, uploads it, then re-downloads every file and
    compares bytes. The only end-to-end "did the bytes survive the
    round trip?" test in the suite.
  * `backend features` — snapshots rclone's view of which S3
    capabilities the proxy advertises and pins a few load-bearing
    fields (BucketBased, Move, Copy) so a regression that flips one
    is caught here.

Why this complements the mount tests:

  * Mount tests prove the gateway works for the *common* FUSE-mediated
    request shapes that mount-s3 / rclone-mount happen to emit.
  * `rclone test info` deliberately probes corner cases — unsized PUT,
    legitimate-but-unusual key characters — that the mount path won't
    hit at all.
  * The makefiles round-trip exercises a real workload shape (many
    files, varied sizes, nested dirs) end-to-end with byte-level
    verification — the mount tests assert per-file content but not at
    tree scale, and they trust the FUSE-cached read instead of
    re-fetching.

Each test is bucket-scoped: rclone writes test objects under a
dedicated sub-prefix and removes them at exit, so the backing dir is
left as we found it.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from s32p_test.rclone import REMOTE_NAME, is_available, write_rclone_config


pytestmark = pytest.mark.skipif(
    not is_available(),
    reason="rclone not installed",
)


# Sub-prefix `rclone test info` writes its probe objects under. Keeps the
# debris confined so a future test that asserts on the bucket's top-level
# listing isn't surprised by a `_test_info_*` key left over from an
# aborted run.
_INFO_PREFIX = "compat-info"

# The round-trip test uploads its random tree at the *bucket root* — not
# under a sub-prefix. Reason: the gateway's HEAD on a key that happens to
# exist as a POSIX directory returns 200 (the directory is real on disk),
# and rclone interprets that 200 as "destination is a file, refuse to
# treat it as a Fs". The per-test `bucket` fixture wipes contents between
# tests, so using the bucket root doesn't leak debris.


@pytest.fixture
def rclone_config(tmp_path, endpoint) -> Path:
    """Write a per-test rclone.conf and return its path.

    The test runner's real `~/.config/rclone` is never consulted because
    every rclone invocation in this file passes `--config <path>` and
    points `HOME` away from the user's home dir.
    """
    path = tmp_path / "rclone.conf"
    write_rclone_config(
        path,
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
    )
    return path


@pytest.fixture
def rclone_config_markers(tmp_path, endpoint) -> Path:
    """Same as `rclone_config`, but with `directory_markers = true`.

    Opting into directory markers is the only way to make rclone's S3
    backend advertise `CanHaveEmptyDirectories=true` and round-trip an
    empty directory through `mkdir` / `lsd`. Kept as a separate fixture
    so the default-config tests above stay representative of "user
    pointed rclone at our proxy with no extras".
    """
    path = tmp_path / "rclone.conf"
    write_rclone_config(
        path,
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        directory_markers=True,
    )
    return path


def _rclone_env(config_dir: Path) -> dict[str, str]:
    """Minimal env for rclone subprocesses.

    Forwards `PATH` (fusermount lookup, plus rclone's own subprocess
    invocations) and overrides `HOME` so a misbehaving plugin can't read
    the test runner's home dir. Everything else — including AWS_* — is
    dropped so the rclone.conf is the single source of credentials.
    """
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(config_dir),
    }


def _run_rclone(
    argv: list[str], *, config: Path, timeout: float = 60.0,
) -> subprocess.CompletedProcess:
    """Run rclone, attach the config flag, capture output, fail with the
    full stderr on non-zero exit. Returns the CompletedProcess so tests
    can also inspect stdout when they care.
    """
    full = ["rclone", *argv, "--config", str(config)]
    proc = subprocess.run(
        full, capture_output=True, text=True,
        timeout=timeout, env=_rclone_env(config.parent), check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"rclone {argv[0]} exited {proc.returncode}\n"
            f"--- argv ---\n{' '.join(full)}\n"
            f"--- stdout ---\n{proc.stdout}\n"
            f"--- stderr ---\n{proc.stderr}\n"
        )
    return proc


def _run_test_info(config: Path, target: str, *extra: str) -> dict:
    """Run `rclone test info --write-json` and return the parsed report.

    `rclone test info` writes a flat JSON object with keys derived from
    its exported Go struct fields (CamelCase): `Remote`, `CanStream`,
    `MaxFileLength`, `ControlCharacters`, … Fields not exercised in
    this run come back as `null`.
    """
    out = config.parent / "info.json"
    _run_rclone(
        ["test", "info", "--write-json", str(out), target, *extra],
        config=config,
    )
    report = json.loads(out.read_text())
    if not isinstance(report, dict):
        raise AssertionError(
            f"expected JSON object, got {type(report).__name__}: {report}"
        )
    return report


def test_rclone_test_info_streaming(rclone_config, bucket):
    """`--check-streaming`: rclone PUTs an object whose
    `Content-Length` is unknown ahead of time, which our gateway
    handles by routing into the multipart-upload assembly path
    (`CreateMultipartUpload` → `UploadPart` chain → `Complete`). The
    report's stream-capability flag must come back true; a false here
    means the gateway rejected the unsized PUT — a regression in
    `handle_put_object` body handling.
    """
    target = f"{REMOTE_NAME}:{bucket}/{_INFO_PREFIX}"
    report = _run_test_info(rclone_config, target, "--check-streaming")
    assert report.get("CanStream") is True, (
        f"rclone reports no streaming support:\n{report}"
    )


def test_rclone_test_info_control_characters(rclone_config, bucket):
    """`--check-control`: rclone writes objects whose keys contain each
    control character (0x01..0x1F, 0x7F) and reports which round-trip.

    We don't assert *all* control chars work — S3 has its own
    restrictions and some are legitimately rejected at the wire (most
    obviously NUL and forward-slash). What we do assert is that the
    probe got far enough to fill in a `controlCharacters` map: an
    empty/missing field means rclone bailed out before testing any of
    them, which would indicate a basic auth / routing failure rather
    than a per-character problem.
    """
    target = f"{REMOTE_NAME}:{bucket}/{_INFO_PREFIX}"
    report = _run_test_info(rclone_config, target, "--check-control")
    controls = report.get("ControlCharacters")
    assert isinstance(controls, dict) and controls, (
        f"rclone did not produce a ControlCharacters report:\n{report}"
    )


# ---------------------------------------------------------------- round-trip


def test_rclone_roundtrip_makefiles_copy_check(rclone_config, tmp_path, bucket):
    """End-to-end byte-integrity check.

    1. `rclone test makefiles` generates a deterministic random tree
       (seeded; nested 3 deep; mix of file sizes up to 64 KiB).
    2. `rclone copy` uploads the tree to a per-test sub-prefix.
    3. `rclone check --download` re-downloads every file from the
       bucket and byte-compares against the local original.

    `--download` is load-bearing: the gateway derives ETags from the
    inode number rather than MD5 (see README), so the default
    checksum-based `check` would mismatch even on a perfect upload.
    `--download` ignores ETags and compares the bytes themselves.

    Why this exists: the per-file mount tests assert content for *one*
    file at a time and go through FUSE's read cache. This is the only
    test in the suite that uploads many files in one shot, then proves
    each one survived the round trip byte-for-byte. A corruption
    introduced by a partial-write bug in a less-trafficked size class
    or filename would show up here first.
    """
    src = tmp_path / "src-tree"
    src.mkdir()
    _run_rclone(
        ["test", "makefiles", str(src),
         "--files", "30",
         "--max-depth", "3",
         "--files-per-directory", "6",
         "--min-file-size", "1",
         "--max-file-size", "65536",
         # Fixed seed → reproducible tree; a flake here points at a
         # gateway race, not at random-tree variation.
         "--seed", "42"],
        config=rclone_config,
    )

    target = f"{REMOTE_NAME}:{bucket}"
    _run_rclone(["copy", str(src), target], config=rclone_config, timeout=120.0)
    _run_rclone(
        ["check", "--download", str(src), target],
        config=rclone_config,
        timeout=120.0,
    )


# ---------------------------------------------------------------- backend features


def test_rclone_backend_features_match_s3(rclone_config, bucket):
    """Snapshot rclone's view of the proxy's S3 capabilities.

    `rclone backend features` returns a JSON object describing what
    rclone thinks the backend supports (it's based on the backend's
    `Fs.Features()` return value, not on probing). For an S3-compatible
    remote rclone always sets the same shape — what we pin here are
    the load-bearing flags that downstream rclone commands key off:

      * `BucketBased` — must be true; if it ever flipped to false,
        rclone would start treating paths as filesystem-style and emit
        completely different request shapes.
      * `Copy` — must be true; the gateway implements CopyObject and
        rclone uses it for `rclone copyto` / cross-bucket sync.
        `Move` is *not* in this list: AWS S3 has no native rename op,
        so rclone leaves `Move=false` for the generic-S3 provider and
        implements move as Copy+Delete at a higher layer.
      * `CanHaveEmptyDirectories` — must be false; S3 has no real
        directories, and a true here would cause rclone to issue
        `Mkdir` calls that the proxy would reject.

    If a future rclone version renames or drops one of these fields,
    this test fails loudly — that's the signal to look at the upgrade
    notes and decide what behavior we actually want.
    """
    target = f"{REMOTE_NAME}:{bucket}"
    proc = _run_rclone(["backend", "features", target], config=rclone_config)
    report = json.loads(proc.stdout)

    # `backend features` wraps the actual Features map under a top-level
    # "Features" key alongside Hashes/Precision/etc.
    features = report.get("Features")
    assert isinstance(features, dict) and features, (
        f"no Features block in backend features output:\n{report}"
    )

    # Print whole report on failure (assert message is rendered untruncated
    # only at the top of the assertion's expr, so pre-format here).
    pretty = json.dumps(features, indent=2, sort_keys=True)
    assert features.get("BucketBased") is True, pretty
    assert features.get("Copy") is True, pretty
    assert features.get("CanHaveEmptyDirectories") is False, pretty


# ---------------------------------------------------------------- directory markers


def test_rclone_directory_markers_round_trip(rclone_config_markers, bucket):
    """End-to-end check of the directory-marker convention.

    With `directory_markers = true` in the rclone config, rclone:

      1. Advertises `CanHaveEmptyDirectories = true` in `backend
         features` (the only condition under which the S3 backend
         flips that flag — see `backend/s3/s3.go`).
      2. Creates an empty directory by PUTting a zero-byte object whose
         key ends in `"/"` (`dirname/`).
      3. Lists that marker back as an empty directory in `lsd`.

    The test asserts all three: the feature flag, that `rclone mkdir`
    succeeds end-to-end against our gateway (i.e. the gateway accepts
    the `PUT key/` request), and that `rclone lsd` then surfaces the
    directory.

    Why bother: even though our default tests pin
    `CanHaveEmptyDirectories=false`, the marker convention is the
    rclone-side mechanism that *would* let a user with empty-dir
    semantics survive a round trip through the proxy. If the gateway
    ever silently stops accepting trailing-slash keys, or LIST stops
    returning them, this test catches it.
    """
    target_root = f"{REMOTE_NAME}:{bucket}"

    # (1) feature flag flips
    proc = _run_rclone(
        ["backend", "features", target_root], config=rclone_config_markers,
    )
    features = json.loads(proc.stdout).get("Features", {})
    pretty = json.dumps(features, indent=2, sort_keys=True)
    assert features.get("CanHaveEmptyDirectories") is True, pretty

    # (2) mkdir an empty directory — rclone PUTs `empty-dir/` as zero bytes.
    _run_rclone(
        ["mkdir", f"{target_root}/empty-dir"], config=rclone_config_markers,
    )

    # (3) lsd surfaces it. `--max-depth 1` keeps the output tight; the
    # directory shows up as a single line with a "-1" object count.
    proc = _run_rclone(
        ["lsd", "--max-depth", "1", target_root],
        config=rclone_config_markers,
    )
    assert "empty-dir" in proc.stdout, (
        f"rclone lsd did not surface the empty dir marker:\n"
        f"--- stdout ---\n{proc.stdout}\n"
    )
