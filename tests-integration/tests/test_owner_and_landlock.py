"""Owner DisplayName resolution + the C5 (symlink → /etc/passwd) leak guard.

These cover the NSS lookup proxy machinery:

* `lookup_username_blocking` no longer runs inside the worker; the gateway
  asks the proxy over an abstract UDS (`@s32p-nss-<pid>`) for the username.
  The proxy is unrestricted and resolves `getpwuid_r` for us.
* Because the worker no longer reads `/etc/passwd` directly, the proxy
  drops `--allow-nss` from the worker's Landlock policy. A tenant who
  plants `<bucket>/leak -> /etc/passwd` no longer reads its contents via
  S3 GET — Landlock denies the resolved-path access.

The lookup tests bypass the harness's matrix because `ListResult` doesn't
carry Owner. We use `boto3_raw` and read the raw `ListObjectsV2`/
`GetObjectAcl` responses, which both surface DisplayName.
"""

from __future__ import annotations

import os
import pwd

import pytest
from botocore.exceptions import ClientError


@pytest.fixture
def own_username() -> str:
    """Username that owns the bucket data dir (= the test runner)."""
    return pwd.getpwuid(os.geteuid()).pw_name


def test_owner_display_name_resolved(bucket, bucket_fs, boto3_raw, own_username):
    """A file owned by the test runner lists with the runner's username
    as DisplayName. Proves the proxy NSS lookup is wired and the gateway
    consults it (instead of falling back to numeric uid). The list-V2
    response carries Owner only when `FetchOwner=True` is requested."""
    bucket_fs.write("hello.txt", b"hi")

    resp = boto3_raw.list_objects_v2(Bucket=bucket, FetchOwner=True)
    assert resp.get("KeyCount", 0) == 1, resp
    owner = resp["Contents"][0]["Owner"]
    assert owner["DisplayName"] == own_username, owner
    # ID is the numeric uid as string — independent of NSS resolution.
    assert owner["ID"] == str(os.geteuid()), owner


def test_owner_display_name_unknown_uid_fallback(bucket, bucket_fs, boto3_raw):
    """A file whose uid does not exist on the host falls back to the
    numeric uid as DisplayName. Today we can't chown to an arbitrary uid
    without root, so we only assert the *resolved* case happens for our
    own uid and skip the negative case when not root. The cache layer
    handles None responses uniformly (see `nss_client::cache_insert`
    with the numeric fallback in `owner_info`); this test would chown to
    a nonexistent uid and verify the numeric DisplayName, but does so
    only when the test runner is root."""
    if os.geteuid() != 0:
        pytest.skip("chown to arbitrary uid requires root")

    bucket_fs.write("ghost-owned.txt", b".")
    bogus_uid = 4_000_123_456
    os.chown(str(bucket_fs.root / "ghost-owned.txt"), bogus_uid, -1)

    resp = boto3_raw.list_objects_v2(Bucket=bucket, FetchOwner=True)
    owner = resp["Contents"][0]["Owner"]
    assert owner["ID"] == str(bogus_uid)
    assert owner["DisplayName"] == str(bogus_uid), owner


def test_symlink_to_etc_passwd_denied(bucket, bucket_fs, boto3_raw):
    """C5 regression guard: a tenant-planted symlink whose target lives
    outside the worker's Landlock allow list must NOT be readable via
    S3 GET. /etc/passwd was reachable before because `--allow-nss`
    exposed it; dropping that flag (now that the worker no longer needs
    NSS access) means the kernel refuses the resolved-path read.

    Acceptable outcomes:
      * GET returns 403/AccessDenied or 404 (kernel denied the open;
        gateway surfaces it as one of these).
    Unacceptable outcome:
      * GET returns 200 with /etc/passwd contents — that is the leak we
        just closed."""
    # Sanity: target exists and is world-readable, so any leak would
    # otherwise surface a real password file. If the test box doesn't
    # have /etc/passwd, the leak doesn't apply.
    if not os.path.exists("/etc/passwd"):
        pytest.skip("/etc/passwd missing on this host")

    bucket_fs.symlink("/etc/passwd", "leak")

    with pytest.raises(ClientError) as exc:
        boto3_raw.get_object(Bucket=bucket, Key="leak")
    status = exc.value.response["ResponseMetadata"]["HTTPStatusCode"]
    assert status in (403, 404), f"expected 403 or 404, got {status}"

    # Additionally: the host's /etc/passwd content must not have leaked
    # via the error body. A defense in depth check — even if some future
    # bug returned a non-error status, the body should not contain a
    # root: line.
    try:
        body = exc.value.response.get("Error", {}).get("Message", "")
    except Exception:
        body = ""
    assert "root:" not in body, "error body unexpectedly contains /etc/passwd content"
