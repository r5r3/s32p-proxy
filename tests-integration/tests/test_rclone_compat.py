"""Compatibility check via `rclone test info`.

Drives rclone's own backend-probe command against the proxy. This
exercises a different surface than the mount tests: instead of running
ops through FUSE, `rclone test info` issues PUT/GET/DELETE with
edge-case shapes (streaming uploads with indeterminate size, control
characters in object keys, …) and reports which ones round-trip
cleanly. The test consumes the JSON report and asserts the gateway
clears the bar for "things any real S3-compatible deployment
supports": streaming uploads (MPU under the hood) and a populated
control-character probe.

Why this complements the mount tests:

  * Mount tests prove the gateway works for the *common* FUSE-mediated
    request shapes that mount-s3 / rclone-mount happen to emit.
  * `rclone test info` deliberately probes corner cases — unsized PUT,
    legitimate-but-unusual key characters — that the mount path won't
    hit at all.

The check is bucket-scoped: rclone writes test objects under a
dedicated `compat-info/` prefix and removes them at exit, so the
backing dir is left as we found it.
"""

from __future__ import annotations

import json
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


def _run_test_info(config: Path, target: str, *extra: str) -> dict:
    """Run `rclone test info --write-json` and return the parsed report.

    `rclone test info` writes a flat JSON object with keys derived from
    its exported Go struct fields (CamelCase): `Remote`, `CanStream`,
    `MaxFileLength`, `ControlCharacters`, … Fields not exercised in
    this run come back as `null`.

    60-second ceiling — against a loopback proxy each probe completes
    in a few seconds; a hang past 60s means we're holding something on
    the gateway side, not that rclone is slow.
    """
    out = config.parent / "info.json"
    argv = [
        "rclone", "test", "info",
        "--config", str(config),
        "--write-json", str(out),
        target,
        *extra,
    ]
    env = {
        # rclone reads `PATH` for fusermount lookup (not used here, but
        # cheap to forward) and `HOME` for its default config-dir
        # discovery (we override with --config, but pointing HOME at the
        # tmpdir prevents a misbehaving plugin from reading the test
        # runner's home dir). Everything else — and notably AWS_* env
        # the runner may have set — is dropped so the rclone.conf is the
        # single source of credentials for this run.
        "PATH": __import__("os").environ.get("PATH", ""),
        "HOME": str(config.parent),
    }
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=60, env=env, check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"rclone test info exited {proc.returncode}\n"
            f"--- argv ---\n{' '.join(argv)}\n"
            f"--- stdout ---\n{proc.stdout}\n"
            f"--- stderr ---\n{proc.stderr}\n"
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
