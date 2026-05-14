"""Top-level pytest configuration for the s32p integration suite.

Adds CLI options (`--clients`, `--mode`, `--proxy-url`, `--addressing`) and
defines the parametrized `client` fixture that drives every test through
each registered S3 client adapter.

Heavyweight fixtures (proxy spawn, directory backend, bucket lifecycle)
are stubbed here as `pytest.fixture` placeholders that raise NotImplementedError —
the harness behind them is the next chunk of work, intentionally not in
this sketch. Tests that don't need those fixtures (e.g. construction-only
sanity checks) work today; the get/put/delete test below requires a
running proxy and will skip until the harness lands.
"""

from __future__ import annotations

import os

import pytest

from s32p_test.clients import S3Client, discover
from s32p_test.clients.base import Endpoint
from s32p_test.clients.capabilities import Capability


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


# ----------------------------------------------------------------- harness stubs
# Replace these with the real ProxyHarness / BackendFs / directory builder.


@pytest.fixture(scope="session")
def endpoint(request) -> Endpoint:
    """Return an Endpoint pointing at a running proxy.

    Today: if --proxy-url is given, use it. Otherwise skip — the local
    spawn-the-proxy harness is not implemented yet.
    """
    url = request.config.getoption("--proxy-url")
    if not url:
        pytest.skip("no running proxy; pass --proxy-url or wait for ProxyHarness")
    return Endpoint(
        base_url=url,
        region=os.environ.get("S32P_REGION", "us-east-1"),
        access_key=os.environ["S32P_ACCESS_KEY"],
        secret_key=os.environ["S32P_SECRET_KEY"],
        virtual_hosted_suffix=os.environ.get("S32P_VHOST_SUFFIX"),
    )


@pytest.fixture
def bucket(endpoint, request) -> str:
    """Yield a fresh, empty bucket for the test.

    Today: returns a name from the env (S32P_TEST_BUCKET) for ad-hoc runs.
    Real impl: ProvisionedBucket fixture that mints a bucket via s32p-ctl,
    creates the data path, and tears down on test exit.
    """
    name = os.environ.get("S32P_TEST_BUCKET")
    if not name:
        pytest.skip("no bucket fixture yet; set S32P_TEST_BUCKET for ad-hoc runs")
    return name
