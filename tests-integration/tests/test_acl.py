"""ACL evaluation.

Contract (see `crates/s32p-directory/src/directory/{yaml,openbao}.rs`
`effective_access` and `crates/s32p-proxy/src/main.rs` `bucket_access_for_caller`):

    Effective access for a caller is the *max* of all matching ACL entries
    (read_write beats read_only). Principals can be access_key or group_name
    (POSIX group resolved at runtime via `posix_groups::groups_for_user`).

These tests cover the externally observable consequences:

- read_only grant: GET works, PUT/DELETE are denied with 403 AccessDenied.
  Enforced at the proxy layer via `needs_write(method)` + the bucket's
  effective access level (s32p-proxy main.rs).
- No grant: every op denied (403 or 404 — depends on whether the proxy
  hides non-granted buckets entirely or returns AccessDenied).
- Group-name principal: a user in the group has the granted access even
  with no access-key grant.
- max-of-principals: read_only via access_key + read_write via group →
  effective is read_write; the user can PUT.
- ListBuckets is filtered: a caller only sees buckets where they have at
  least one matching grant.

ACL test buckets are pre-declared in conftest (`acl_scenarios`); names are
stable as `acl-<scenario>`.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error


# ----------------------------------------------------------------- helpers


def _denied(exc: S3Error) -> bool:
    """Either 403 AccessDenied or 404 NoSuchBucket counts as "denied" —
    the proxy may filter the bucket out of the user's view (404) or
    return an explicit AccessDenied (403). Both prove the caller can't
    reach the bucket."""
    return exc.status in (403, 404)


# ----------------------------------------------------------------- read_only


def test_readonly_grant_allows_get(client, acl_bucket):
    """GET on a read_only-granted bucket must succeed. Object is
    pre-populated via POSIX (the read_only ACL would block PUT)."""
    bucket, fs = acl_bucket("readonly")
    fs.write("ro-key", b"populated via posix\n")

    got = client.get_object(bucket, "ro-key")
    assert got.body == b"populated via posix\n"


def test_readonly_grant_blocks_put(client, acl_bucket):
    """PUT on a read_only-granted bucket must be rejected with 403
    AccessDenied. The S3 contract says writes require write permission."""
    bucket, _ = acl_bucket("readonly")

    with pytest.raises(S3Error) as exc:
        client.put_object(bucket, "rejected-key", b"should not land")
    assert exc.value.status == 403, f"expected 403, got {exc.value!r}"


def test_readonly_grant_blocks_delete(client, acl_bucket):
    """DELETE on a read_only-granted bucket must be rejected. Pre-populate
    via POSIX so there's actually something to attempt to delete — then
    confirm it survives."""
    bucket, fs = acl_bucket("readonly")
    fs.write("dont-delete", b"survives\n")

    with pytest.raises(S3Error) as exc:
        client.delete_object(bucket, "dont-delete")
    assert exc.value.status == 403, f"expected 403, got {exc.value!r}"

    # File must still be on disk.
    assert fs.exists("dont-delete")


# ----------------------------------------------------------------- no grant


def test_no_grant_blocks_get(client, acl_bucket):
    """The primary user has no grant on `acl-noaccess` (only secondary
    does). GET must fail. Accepts 403 or 404 — the exact code depends on
    whether the proxy filters out non-granted buckets entirely or surfaces
    AccessDenied."""
    bucket, _ = acl_bucket("noaccess")

    with pytest.raises(S3Error) as exc:
        client.get_object(bucket, "anything")
    assert _denied(exc.value), f"expected 403 or 404, got {exc.value!r}"


def test_no_grant_blocks_put(client, acl_bucket):
    """No grant must also block writes."""
    bucket, _ = acl_bucket("noaccess")

    with pytest.raises(S3Error) as exc:
        client.put_object(bucket, "anything", b"should not land")
    assert _denied(exc.value), f"expected 403 or 404, got {exc.value!r}"


def test_secondary_can_access_own_bucket(
    client_factory, secondary_creds, acl_bucket
):
    """Positive control for the no-grant tests: the secondary user, who
    *does* have read_write on `acl-noaccess`, can PUT and GET there."""
    bucket, _ = acl_bucket("noaccess")
    secondary = client_factory(secondary_creds)

    secondary.put_object(bucket, "by-secondary", b"hello from secondary\n")
    got = secondary.get_object(bucket, "by-secondary")
    assert got.body == b"hello from secondary\n"


# ----------------------------------------------------------------- group grant


def test_group_grant_alone_allows_access(client, acl_bucket):
    """`acl-group-rw` grants read_write to the test runner's primary
    POSIX group. The primary user has no access_key grant — access must
    come purely from group membership."""
    bucket, _ = acl_bucket("group-rw")

    client.put_object(bucket, "via-group", b"granted by group\n")
    got = client.get_object(bucket, "via-group")
    assert got.body == b"granted by group\n"


# ----------------------------------------------------------------- max-of-principals


def test_max_of_principals_promotes_to_read_write(client, acl_bucket):
    """`acl-max-merge` has TWO matching grants for the primary user:
    read_only via access_key AND read_write via group. The effective
    access must be the max → read_write. The PUT proves it: with
    read_only enforced, a regression that broke the merge would 403."""
    bucket, _ = acl_bucket("max-merge")

    client.put_object(bucket, "merged", b"max-of-principals\n")
    got = client.get_object(bucket, "merged")
    assert got.body == b"max-of-principals\n"


# ----------------------------------------------------------------- list_buckets


def test_list_buckets_includes_granted_excludes_non_granted(client):
    """ListBuckets is filtered by visibility: the primary sees the pool
    buckets and every ACL bucket where they match a grant, but NOT
    acl-noaccess (only secondary has a grant there)."""
    listed = set(client.list_buckets())

    # Must include: the pool + every bucket where primary has any grant.
    expected_present = {
        "acl-readonly", "acl-rw", "acl-group-rw", "acl-max-merge",
    } | {f"test-bucket-{i:03d}" for i in range(8)}
    missing = expected_present - listed
    assert not missing, f"missing from primary's ListBuckets: {missing}"

    # Must NOT include: bucket where only secondary has a grant.
    assert "acl-noaccess" not in listed, (
        f"acl-noaccess leaked into primary's ListBuckets: {listed}"
    )


def test_list_buckets_for_secondary_user_sees_only_their_grants(
    client_factory, secondary_creds
):
    """Secondary has exactly one grant — on acl-noaccess. They should
    see that bucket and nothing else."""
    secondary = client_factory(secondary_creds)
    listed = set(secondary.list_buckets())

    assert "acl-noaccess" in listed, (
        f"secondary's only granted bucket missing: {listed}"
    )
    # Secondary has no grants on the pool nor on the other ACL buckets.
    forbidden = {f"test-bucket-{i:03d}" for i in range(8)} | {
        "acl-readonly", "acl-rw", "acl-group-rw", "acl-max-merge",
    }
    leaked = forbidden & listed
    assert not leaked, f"secondary saw buckets they shouldn't: {leaked}"


def test_list_buckets_for_tertiary_user_is_empty(
    client_factory, tertiary_creds
):
    """Tertiary has zero grants on every bucket — ListBuckets must be
    empty (or contain no test fixture buckets, in case the deployment
    has unrelated buckets visible)."""
    tertiary = client_factory(tertiary_creds)
    listed = set(tertiary.list_buckets())

    fixture_buckets = (
        {f"test-bucket-{i:03d}" for i in range(8)}
        | {"acl-readonly", "acl-rw", "acl-noaccess",
           "acl-group-rw", "acl-max-merge"}
    )
    leaked = listed & fixture_buckets
    assert not leaked, f"tertiary saw fixture buckets with no grant: {leaked}"
