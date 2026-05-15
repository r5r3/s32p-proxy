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

import os
import pwd
import shutil
import socket
import uuid
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
    """Parametrize any test that takes `client` over the registered matrix.

    We do this in pytest_generate_tests (not as a parametrized fixture)
    because it gives us nice ids and lets us combine cleanly with
    --addressing=both.
    """
    if "client" not in metafunc.fixturenames:
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

    harness = ProxyHarness(session_dir=session_dir, virtual_hosted_suffixes=suffixes)
    harness.directory.add_user(User(
        access_key=TEST_ACCESS_KEY,
        secret_key=TEST_SECRET_KEY,
        username=me.pw_name,
        uid=me.pw_uid,
        gid=me.pw_gid,
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
    if data_dir.exists():
        for child in data_dir.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                # Restore mode in case a prior test chmod'd it 0o000 — unlink
                # only needs write on the parent, but symlinks et al. don't
                # need any mode change. Try mode-restore best-effort.
                try:
                    child.chmod(0o644)
                except (OSError, NotImplementedError):
                    pass
                child.unlink()
    else:
        data_dir.mkdir(parents=True)

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
