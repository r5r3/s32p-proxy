"""Top-level pytest configuration for the s32p integration suite.

Adds CLI options (`--clients`, `--mode`, `--proxy-url`, `--addressing`) and
defines the parametrized `client` fixture that drives every test through
each registered S3 client adapter.

The proxy is spawned once per session (`proxy_harness`); the test user
and a fixed pool of buckets are seeded once and reused. Per-test
isolation is provided by the `bucket` fixture, which leases one bucket
from the pool and wipes its data dir before yielding.
"""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from s32p_test.backend_fs import BackendFs
from s32p_test.clients import S3Client, discover
from s32p_test.clients.base import Endpoint
from s32p_test.clients.capabilities import Capability
from s32p_test.directory import Bucket, Grant, User
from s32p_test.proxy import ProxyHarness


# Fixed test credentials. Stable across runs so an interrupted test leaves
# behind a reproducible footprint; the session_dir is fresh per run anyway.
TEST_ACCESS_KEY = "TESTACCESSKEY123"
TEST_SECRET_KEY = "TESTSECRETKEY456"  # noqa: S105 (test fixture, not a real secret)
BUCKET_POOL_SIZE = 8

# Additional credentials for ACL coverage. All three users share the test
# runner's uid/gid (single-uid mode) — ACL evaluation operates on the
# access key + group membership, not the uid. Matters for tests that
# need to compare what different access keys can see/do.
SECONDARY_ACCESS_KEY = "SECONDARYACCESSKEY222"
SECONDARY_SECRET_KEY = "SECONDARYSECRETKEY333"  # noqa: S105
TERTIARY_ACCESS_KEY = "TERTIARYACCESSKEY444"
TERTIARY_SECRET_KEY = "TERTIARYSECRETKEY555"  # noqa: S105


@dataclass(frozen=True, slots=True)
class UserCreds:
    access_key: str
    secret_key: str

# nip.io is wildcard DNS that resolves "<anything>.<ip>.nip.io" to <ip>.
# We use it for virtual-hosted-style tests so boto3 can issue requests
# like `https://<bucket>.127.0.0.1.nip.io:<port>/key` while the proxy
# still listens on plain loopback. Requires DNS at test time; gated
# behind --addressing including virtual.
VIRTUAL_HOSTED_SUFFIX = "127.0.0.1.nip.io"


# ----------------------------------------------------------------- CLI options


def pytest_addoption(parser):
    g = parser.getgroup("s32p", "s32p integration test options")
    g.addoption(
        "--clients",
        action="store",
        default=os.environ.get("S32P_CLIENTS", ""),
        help="Comma-separated client names to include (default: all registered).",
    )
    g.addoption(
        "--mode",
        action="store",
        default=os.environ.get("S32P_MODE", "single-uid"),
        choices=("single-uid", "multi-uid"),
        help="single-uid: proxy spawns workers as the test runner's uid (no sudo). "
             "multi-uid: requires root/CAP_SETUID and two test uids.",
    )
    g.addoption(
        "--proxy-url",
        action="store",
        default=os.environ.get("S32P_PROXY_URL"),
        help="Skip spawning a local proxy and target this URL instead "
             "(useful for hitting a dev instance).",
    )
    g.addoption(
        "--addressing",
        action="store",
        default="path",
        choices=("path", "virtual", "both"),
        help="Bucket addressing style. 'both' parametrizes each test over both.",
    )


# ----------------------------------------------------------------- mode/marker glue


def pytest_collection_modifyitems(config, items):
    mode = config.getoption("--mode")
    skip_multi = pytest.mark.skip(reason="needs --mode=multi-uid")
    skip_single = pytest.mark.skip(reason="needs --mode=single-uid")
    for item in items:
        if "multi_uid_only" in item.keywords and mode != "multi-uid":
            item.add_marker(skip_multi)
        if "single_uid_only" in item.keywords and mode != "single-uid":
            item.add_marker(skip_single)


# ----------------------------------------------------------------- failure log capture

# Bytes of the proxy log to attach to a failed test. 32 KiB is enough to
# cover a few worker spawns and a typical request/response cycle without
# drowning the report.
_PROXY_LOG_TAIL_BYTES = 32 * 1024


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """When a test fails, attach the tail of the proxy log to its report.

    The proxy is shared across the whole session, so this is a *tail*, not
    a per-test slice — but it's still the single most useful artifact for
    diagnosing harness/gateway failures. Stored as a `sections` entry so
    pytest renders it with `-ra` / `--tb=short`.
    """
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call" or not rep.failed:
        return
    harness = getattr(item.session, "_s32p_harness", None)
    if harness is None:
        return
    try:
        log_bytes = harness.log_path.read_bytes()
    except OSError:
        return
    tail = log_bytes[-_PROXY_LOG_TAIL_BYTES:].decode("utf-8", "replace")
    rep.sections.append((f"proxy log tail ({harness.log_path})", tail))


# ----------------------------------------------------------------- client matrix


def _selected_clients(config) -> list[type[S3Client]]:
    raw = config.getoption("--clients")
    only = [s.strip() for s in raw.split(",") if s.strip()] or None
    return discover(only)


def pytest_generate_tests(metafunc):
    """Parametrize any test that takes `client` (or `client_factory`) over
    the registered matrix.

    We do this in pytest_generate_tests (not as a parametrized fixture)
    because it gives us nice ids and lets us combine cleanly with
    --addressing=both. `client_factory` is included so ACL tests that only
    construct alternate-credential clients still get the same matrix.
    """
    if not (set(metafunc.fixturenames) & {"client", "client_factory"}):
        return

    classes = _selected_clients(metafunc.config)
    addressing_opt = metafunc.config.getoption("--addressing")
    addressings = ["path", "virtual"] if addressing_opt == "both" else [addressing_opt]

    params = []
    ids = []
    for cls in classes:
        for addr in addressings:
            if addr == "virtual" and Capability.VIRTUAL_HOSTED not in cls.capabilities:
                continue
            if addr == "path" and Capability.PATH_STYLE not in cls.capabilities:
                continue
            params.append((cls, addr))
            ids.append(f"{cls.name}-{addr}")

    metafunc.parametrize(("_client_cls", "_client_addressing"), params, ids=ids)


@pytest.fixture
def client(_client_cls, _client_addressing, endpoint, request):
    """Per-test client instance, parametrized over (adapter, addressing)."""
    inst = _client_cls(endpoint, addressing=_client_addressing)
    # Capability skip: a test marked with @pytest.mark.requires_capability(X)
    # is skipped for clients that don't advertise X.
    for marker in request.node.iter_markers("requires_capability"):
        cap: Capability = marker.args[0]
        if not inst.supports(cap):
            pytest.skip(f"{inst.name} lacks capability {cap.name}")
    return inst


# ----------------------------------------------------------------- harness fixtures


def _allocate_fake_gids(real_gid: int, n: int) -> list[int]:
    """Pick `n` synthetic gids that don't resolve to any real group.

    Used so test users can have empty group memberships. Walks upward from
    a high offset, skipping anything that turns out to map to a real group
    via getgrgid. Raises if it can't find enough free slots within a few
    thousand candidates (would mean the system has wildly populated gids,
    in which case the test author should pick a different range).
    """
    found: list[int] = []
    candidate = real_gid + 1_000_000
    tried = 0
    while len(found) < n:
        if tried > 5000:
            raise RuntimeError(
                f"could not find {n} unused gids near {real_gid + 1_000_000}; "
                "system has unusually high gid usage"
            )
        try:
            grp.getgrgid(candidate)
        except KeyError:
            found.append(candidate)
        candidate += 1
        tried += 1
    return found


def _virtual_hosted_dns_works(suffix: str) -> bool:
    """Probe whether wildcard DNS for a virtual-hosted suffix resolves.

    The probed name is `s32p-dns-probe.<suffix>` — a label that does not
    actually need to exist server-side, only to resolve via wildcard DNS
    (e.g. nip.io). We accept any successful resolution to a 127.0.0.0/8
    address; an unrelated A record would mean DNS is being intercepted
    and tests would fail in confusing ways.
    """
    try:
        infos = socket.getaddrinfo(f"s32p-dns-probe.{suffix}", None)
    except OSError:
        return False
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET and sockaddr[0].startswith("127."):
            return True
    return False


@pytest.fixture(scope="session")
def proxy_harness(tmp_path_factory, request) -> ProxyHarness:
    """Session-scoped: spawn one proxy, seed the directory, tear down at end.

    With --proxy-url, skip spawning entirely — the test runner targets the
    given URL and the test user is expected to exist already (set
    S32P_ACCESS_KEY/S32P_SECRET_KEY/S32P_TEST_BUCKETS).
    """
    if request.config.getoption("--proxy-url"):
        pytest.skip("--proxy-url path uses `endpoint` directly, no harness")

    session_dir = tmp_path_factory.mktemp("s32p")
    me = pwd.getpwuid(os.getuid())

    # Activate virtual-hosted-style addressing only when --addressing asks
    # for it — otherwise a path-only run would acquire a DNS dependency it
    # doesn't need.
    addressing_opt = request.config.getoption("--addressing")
    needs_virtual = addressing_opt in ("virtual", "both")
    if needs_virtual and not _virtual_hosted_dns_works(VIRTUAL_HOSTED_SUFFIX):
        pytest.skip(
            f"virtual addressing requested but wildcard DNS for "
            f"{VIRTUAL_HOSTED_SUFFIX} does not resolve to loopback "
            "(likely no internet / blocked DNS); rerun with --addressing=path"
        )
    suffixes = (VIRTUAL_HOSTED_SUFFIX,) if needs_virtual else ()

    primary_group = grp.getgrgid(me.pw_gid).gr_name

    # Synthetic identities for SECONDARY/TERTIARY. They must NOT inherit the
    # test runner's group memberships, otherwise group-based ACL grants
    # would match them too and the per-access-key visibility tests can't
    # tell access-key grants apart from group grants. The directory crate
    # calls getgrouplist(username, primary_gid) — a fake username plus a
    # fake gid that resolves to no group makes the resulting set empty.
    # uids stay in a high range too because the worker manager uses
    # user.uid in staged_root paths (and historically in the UDS path; that
    # collision is now fixed by per-worker random suffixes, but distinct
    # uids still keep posix_root staging dirs cleanly separated).
    fake_gids = _allocate_fake_gids(me.pw_gid, n=2)
    secondary_uid = me.pw_uid + 1_000_000
    tertiary_uid = me.pw_uid + 2_000_000

    harness = ProxyHarness(session_dir=session_dir, virtual_hosted_suffixes=suffixes)
    user_specs = (
        # access_key,           secret_key,           username,         uid,           gid
        (TEST_ACCESS_KEY,      TEST_SECRET_KEY,      me.pw_name,       me.pw_uid,     me.pw_gid),
        (SECONDARY_ACCESS_KEY, SECONDARY_SECRET_KEY, "s32p-secondary", secondary_uid, fake_gids[0]),
        (TERTIARY_ACCESS_KEY,  TERTIARY_SECRET_KEY,  "s32p-tertiary",  tertiary_uid,  fake_gids[1]),
    )
    for ak, sk, name, uid, gid in user_specs:
        harness.directory.add_user(User(
            access_key=ak,
            secret_key=sk,
            username=name,
            uid=uid,
            gid=gid,
        ))
    # Pre-declare a pool of buckets. The bucket fixture leases one per test.
    bucket_data_root = session_dir / "buckets"
    for i in range(BUCKET_POOL_SIZE):
        name = f"test-bucket-{i:03d}"
        harness.directory.add_bucket(Bucket(
            name=name,
            data_path=bucket_data_root / name,
            grants=(Grant("ak", TEST_ACCESS_KEY, "read_write"),),
            bucket_id=f"bkt-{name}",
        ))

    # ACL test buckets. These are separate from the pool because each one
    # has a fixed grant configuration that the test relies on; the pool
    # buckets are all read_write to TEST and would defeat the purpose.
    # The YAML directory has no hot reload, so all ACL scenarios must be
    # declared before harness.start() — keep this list in sync with the
    # constants used by tests/test_acl.py.
    acl_scenarios = (
        # name, grants
        ("acl-readonly",  (Grant("ak", TEST_ACCESS_KEY, "read_only"),)),
        ("acl-rw",        (Grant("ak", TEST_ACCESS_KEY, "read_write"),)),
        # Only the secondary user has a grant; primary must be denied.
        ("acl-noaccess",  (Grant("ak", SECONDARY_ACCESS_KEY, "read_write"),)),
        # Group grant only — primary user has access via group membership.
        ("acl-group-rw",  (Grant("group", primary_group, "read_write"),)),
        # max-of-principals: read_only via access key + read_write via group
        # → effective is read_write. The test asserts the primary user can PUT.
        ("acl-max-merge", (
            Grant("ak", TEST_ACCESS_KEY, "read_only"),
            Grant("group", primary_group, "read_write"),
        )),
    )
    for name, grants in acl_scenarios:
        harness.directory.add_bucket(Bucket(
            name=name,
            data_path=bucket_data_root / name,
            grants=grants,
            bucket_id=f"bkt-{name}",
        ))

    harness.start()
    # Stash on session so pytest_runtest_makereport can attach the proxy
    # log tail to any failed test report without needing the fixture.
    request.session._s32p_harness = harness
    try:
        yield harness
    finally:
        harness.stop()


@pytest.fixture(scope="session")
def endpoint(request, proxy_harness) -> Endpoint:
    """Endpoint to drive S3 clients against. Source: spawned proxy or
    --proxy-url. The proxy_harness fixture handles the skip-when-external
    branch."""
    url = request.config.getoption("--proxy-url")
    if url:
        return Endpoint(
            base_url=url,
            region=os.environ.get("S32P_REGION", "us-east-1"),
            access_key=os.environ["S32P_ACCESS_KEY"],
            secret_key=os.environ["S32P_SECRET_KEY"],
            virtual_hosted_suffix=os.environ.get("S32P_VHOST_SUFFIX"),
        )
    return Endpoint(
        base_url=proxy_harness.base_url,
        region=proxy_harness.region,
        access_key=TEST_ACCESS_KEY,
        secret_key=TEST_SECRET_KEY,
        virtual_hosted_suffix=(
            proxy_harness.virtual_hosted_suffixes[0]
            if proxy_harness.virtual_hosted_suffixes
            else None
        ),
    )


# Lease counter for bucket fixture. xdist note: this module-global is
# intentional — under xdist each worker is its own Python process, so it
# gets its own counter, its own proxy_harness, its own session_dir, its
# own listen port, and its own bucket pool. Don't "fix" this with
# multiprocessing locks or a shared file: there is nothing shared to
# coordinate.
#
# Constraint: BUCKET_POOL_SIZE must be >= the number of *concurrent* bucket
# leases per test (today: 1, enforced by pytest's per-name fixture caching
# — `bucket` and `bucket_fs` share one `_leased_bucket` instance). If a
# future test introduces a second-bucket factory fixture, raise the pool
# size accordingly: the modulo in `_leased_bucket` would otherwise let two
# concurrent leases collide on the same data dir.
_bucket_counter = 0


def _wipe_bucket_contents(data_dir: Path) -> None:
    """Empty a bucket's data dir (preserve the dir itself)."""
    if not data_dir.exists():
        data_dir.mkdir(parents=True)
        return
    for child in data_dir.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            # Restore mode in case a prior test chmod'd it 0o000 — unlink
            # only needs write on the parent, but symlinks et al. don't
            # need any mode change. Best-effort.
            try:
                child.chmod(0o644)
            except (OSError, NotImplementedError):
                pass
            child.unlink()


@pytest.fixture
def _leased_bucket(proxy_harness) -> tuple[str, BackendFs]:
    """Lease one bucket from the pool, wipe its *contents*, return (name, fs).

    The data dir itself is preserved (it was created at session start by
    `add_bucket`); only the children are removed so the next test starts
    with an empty bucket. Cleanup-before-yield (not after) lets a failed
    test leave debris on disk for inspection while still giving the next
    test a clean slate. Tests should depend on `bucket` and/or `bucket_fs`
    rather than this fixture directly.
    """
    global _bucket_counter
    idx = _bucket_counter % BUCKET_POOL_SIZE
    _bucket_counter += 1
    name = f"test-bucket-{idx:03d}"

    data_dir = proxy_harness.session_dir / "buckets" / name
    _wipe_bucket_contents(data_dir)
    return name, BackendFs(root=data_dir)


@pytest.fixture
def bucket(_leased_bucket) -> str:
    """The S3 bucket name for this test."""
    return _leased_bucket[0]


@pytest.fixture
def bucket_fs(_leased_bucket) -> BackendFs:
    """Direct POSIX access to the same bucket's backing data dir.

    Use for interop tests that need to write/read/symlink/chmod on disk and
    then assert what S3 sees (or vice versa). Both `bucket` and `bucket_fs`
    refer to the *same* lease in a given test — pytest shares the
    `_leased_bucket` instance across them.
    """
    return _leased_bucket[1]


# ----------------------------------------------------------------- ACL fixtures


@pytest.fixture(scope="session")
def primary_creds() -> UserCreds:
    """Same identity boto3/aws-cli use by default (TEST_*)."""
    return UserCreds(TEST_ACCESS_KEY, TEST_SECRET_KEY)


@pytest.fixture(scope="session")
def secondary_creds() -> UserCreds:
    """A second access key for the same uid — used by ACL tests that
    need a non-primary identity (e.g. acl-noaccess from primary's POV)."""
    return UserCreds(SECONDARY_ACCESS_KEY, SECONDARY_SECRET_KEY)


@pytest.fixture(scope="session")
def tertiary_creds() -> UserCreds:
    """A third access key with no grants on any bucket — useful for
    asserting "totally unknown user" behavior."""
    return UserCreds(TERTIARY_ACCESS_KEY, TERTIARY_SECRET_KEY)


@pytest.fixture
def client_factory(_client_cls, _client_addressing, endpoint, request):
    """Build a client that shares the matrix's adapter+addressing but
    uses caller-supplied credentials. Honors `requires_capability` markers
    the same way the regular `client` fixture does — so an ACL test marked
    `requires_capability(X)` skips clients lacking X even when they're
    constructed via this factory.
    """
    def make(creds: UserCreds) -> S3Client:
        ep = Endpoint(
            base_url=endpoint.base_url,
            region=endpoint.region,
            access_key=creds.access_key,
            secret_key=creds.secret_key,
            virtual_hosted_suffix=endpoint.virtual_hosted_suffix,
        )
        inst = _client_cls(ep, addressing=_client_addressing)
        for marker in request.node.iter_markers("requires_capability"):
            cap: Capability = marker.args[0]
            if not inst.supports(cap):
                pytest.skip(f"{inst.name} lacks capability {cap.name}")
        return inst
    return make


@pytest.fixture
def acl_bucket(proxy_harness):
    """Factory for the pre-declared ACL test buckets.

    Usage: `name, fs = acl_bucket("readonly")` — returns the canonical
    bucket name (`acl-readonly` etc.) and a BackendFs scoped to its data
    dir. Contents are wiped before yielding (same cleanup-before-yield
    pattern as the regular bucket pool). The grants are fixed at session
    start; see `acl_scenarios` in proxy_harness.
    """
    def lease(scenario: str) -> tuple[str, BackendFs]:
        name = f"acl-{scenario}"
        data_dir = proxy_harness.session_dir / "buckets" / name
        _wipe_bucket_contents(data_dir)
        return name, BackendFs(root=data_dir)
    return lease
