"""Bulk DeleteObjects (`POST /?delete`) coverage.

S3's bulk delete is its own code path on the gateway side
(`crates/s32p-gateway/src/main.rs::handle_delete_objects`) — it parses
the XML body, delete-walks each key, and assembles a result document.
The single-key DELETE test in test_get_put_delete.py doesn't exercise
any of that.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error
from s32p_test.clients.capabilities import Capability


pytestmark = pytest.mark.requires_capability(Capability.DELETE_OBJECTS)


def test_delete_objects_bulk(client, bucket):
    """3 keys deleted in one request; all are reported as deleted and
    HEAD on each returns 404."""
    keys = [f"bulk-{i}.txt" for i in range(3)]
    for k in keys:
        client.put_object(bucket, k, b".")

    deleted = client.delete_objects(bucket, keys)
    assert sorted(deleted) == sorted(keys), (
        f"not all keys reported as deleted: requested {keys}, got {deleted}"
    )

    for k in keys:
        with pytest.raises(S3Error) as exc:
            client.head_object(bucket, k)
        assert exc.value.status == 404, f"{k} still present after bulk delete"
