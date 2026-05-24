# s32p integration tests

Real-binary integration tests for `s32p-proxy`. The harness spawns the actual
`s32p-proxy` + `s32p-gateway` + `restricted-exec` binaries, seeds directory
state via `s32p-ctl`, and drives them through a matrix of S3 clients.

Two things this suite is built for:

1. **Multi-client matrix.** Every test runs once per registered S3 client
   (today: `boto3`, `aws-cli`). Adding a client = one file in
   `s32p_test/clients/`. Tests do not import any SDK — they go through the
   abstract `S3Client` interface.
2. **POSIX <-> S3 interop.** Tests can write to a bucket's backing data
   directory directly (via `bucket_fs`) and assert what S3 sees, or vice
   versa. The bidirectional contract — files written from one side must be
   visible byte-identically from the other — is the unique value of this
   suite versus a generic S3 conformance run.

## Quick start

```bash
pixi run test               # build binaries + run full suite
pixi run test-fast          # skip slow / lustre / openbao / multi-uid
pixi run test --clients=boto3      # filter clients
pixi run test -k symlink           # standard pytest -k expr
pixi run test --addressing=both    # path-style and virtual-hosted
```

`pixi run test` shells out to `cargo build` from the repo root before pytest;
a no-op rebuild is fast enough that the dependency is always on.

## Test modes

| Knob | Default | Effect |
|---|---|---|
| `--mode=single-uid` | yes | Workers run as the test runner's uid. No sudo. CI-friendly. |
| `--mode=multi-uid` | — | Requires root + a second test uid; exercises real uid switching via `restricted-exec --user`. Not yet wired into a fixture. |
| `--clients=A,B` | all registered | Only run the listed adapters. |
| `--addressing=path|virtual|both` | `path` | Bucket addressing style. `both` parametrizes each test over both. |
| `--proxy-url=URL` | — | Skip spawning a local proxy; target this URL. Requires env `S32P_ACCESS_KEY`, `S32P_SECRET_KEY`, optional `S32P_REGION`, `S32P_VHOST_SUFFIX`. |
| `S32P_CARGO_PROFILE=release` | `debug` | Look for binaries under `target/release/` instead. |
| `S32P_REPO_ROOT=/path` | derived | Override workspace root discovery. |

## Layout

```
tests-integration/
├── pixi.toml                       # env + tasks
├── pixi.lock
├── pytest.ini                      # marker registry + defaults
├── conftest.py                     # CLI options, matrix, harness fixtures
│
├── s32p_test/                      # the harness package
│   ├── paths.py                    # locate the four required binaries
│   ├── proxy.py                    # ProxyHarness — config gen, spawn, teardown
│   ├── directory.py                # Yaml/OpenBaoDirectory — wrap `s32p-ctl --backend …`
│   ├── openbao.py                  # OpenBaoServer — ephemeral `bao server -dev`
│   ├── backend_fs.py               # BackendFs — direct POSIX ops on a bucket
│   └── clients/
│       ├── base.py                 # S3Client ABC + dataclasses + S3Error
│       ├── capabilities.py         # Capability enum
│       ├── boto3_client.py
│       └── aws_cli_client.py
│
└── tests/
    ├── test_get_put_delete.py      # smoke round-trip + metadata xfail
    ├── test_openbao.py             # OpenBao directory backend smoke (auto-spawned bao)
    ├── test_mountpoint.py          # FUSE mount tests (mount-s3 + rclone)
    └── interop/                    # POSIX <-> S3 contracts
        ├── test_basic.py           # write/read both ways, rename, listing
        ├── test_symlinks.py        # live + broken symlink behavior
        └── test_advanced.py        # reserved .s32p-mpu, no LIST-GC, perms, copy
```

`test_mountpoint.py` parametrizes its data-plane tests over both FUSE
mount clients (mount-s3 and rclone) via the `mount_backend` fixture, so
each generic test (write/read/list/delete/roundtrip/read-only) runs
once per backend. Client-specific tests — the mount-s3 directory-bucket
personality marker, `--incremental-upload`, the `If-None-Match`
collision path, and the `RenameObject` walk — stay pinned to mount-s3
with `@pytest.mark.parametrize("mount_backend", ["mount-s3"],
indirect=True)`. Per-backend availability is checked inside the `mount`
fixture, so a one-binary-missing host still runs the other half of the
matrix instead of skipping the whole file.

## Adding a test

```python
def test_something(client, bucket, bucket_fs):
    client.put_object(bucket, "key", b"data")          # via S3
    assert bucket_fs.read("key") == b"data"            # via POSIX
```

Three fixtures cover most cases:

- `client` — abstract `S3Client`, parametrized over the matrix. Capability-gated tests use `@pytest.mark.requires_capability(Capability.X)` to skip clients that lack `X`.
- `bucket` — string, the S3 bucket name for this test. Pre-cleaned data dir before yield (debris from a failed test stays for inspection).
- `bucket_fs` — `BackendFs` scoped to the same bucket's `data_path`. Methods: `write/read/mkdir/rename/symlink/chmod/listdir/rm/rmtree/exists/stat`. Both `bucket` and `bucket_fs` refer to the same lease.

## Adding a client adapter

1. Drop `s32p_test/clients/<name>_client.py`.
2. Subclass `S3Client`, set `name` (used in test ids and `--clients` filter), set `capabilities` (which capability flags this client honestly supports).
3. Implement the abstract methods (`list_buckets`, `head_bucket`, `put_object`, `get_object`, `head_object`, `delete_object`, `list_objects`); override the capability-gated methods you advertise.
4. Map errors onto `S3Error(code, status, message)`. Botocore exceptions, stderr regex, parsed JSON — whatever your client emits.

The auto-discovery in `clients/__init__.py` will pick the file up on next collection. No central registry to edit.

## Markers

Defined in `pytest.ini`:

| Marker | Meaning |
|---|---|
| `slow` | Takes >5s; excluded from `pixi run test-fast`. |
| `requires_lustre` | Needs Lustre + gateway built with `--features lustre`. |
| `requires_openbao` | Covers the OpenBao directory backend. Auto-spawns its own `bao server -dev`; needs the `bao` binary on PATH (`S32P_BAO_BIN` to override), else skips. |
| `requires_root` | Needs to run as root (CAP_SETUID for `restricted-exec --user`). |
| `multi_uid_only` | Skipped unless `--mode=multi-uid`. |
| `single_uid_only` | Skipped unless `--mode=single-uid`. |
| `requires_capability(cap)` | Per-client skip when the adapter doesn't advertise `cap`. |

## Pixi tasks

| Task | What it does |
|---|---|
| `pixi run build` | `cargo build` for `s32p-proxy`, `s32p-gateway`, `s32p-ctl`, `restricted-exec` (cwd is repo root). |
| `pixi run test` | `build` + full pytest. |
| `pixi run test-fast` | `build` + pytest minus slow/lustre/openbao/multi-uid. |
| `pixi run test-multi-uid` | `build` + `pytest --mode=multi-uid`. |
| `pixi run test-openbao` | `build` + `pytest -m requires_openbao`. |
| `pixi run lint` | `ruff check . && mypy s32p_test` (in `dev` env: `pixi run -e dev lint`). |
| `pixi run format` | `ruff format .`. |

## Harness internals (cliff notes)

`ProxyHarness` (in `s32p_test/proxy.py`) per session:

- Writes a fresh `s32p-proxy.yaml` to a per-session tempdir.
- Picks a free TCP port for the listen address (`bind` to port 0, read assigned, close).
- Uses UDS for the worker upstream (`<session>/uds/<uid>-<instance>/<profile>.sock`) — no port collisions.
- Routes `read/write/multipart/other` to the gateway profile, `versioning/object_lock` to `aws_compat` (AWS-shaped feature-disabled responses per op, falling back to 501 where AWS has no equivalent), and `bucket_admin` to `not_implemented` (matches production intent — bucket admin is `s32p-ctl`-only).
- Disables landlock and `pass_user_flag_if_root` for single-uid mode.
- Pre-declares 8 buckets at session start; the `bucket` fixture leases one per test.
- Captures stdout+stderr to `<session>/proxy.log` and dumps the tail in any startup-failure exception.

Under xdist (`pytest -n N`), each worker is a separate Python process, so each gets its own `ProxyHarness`, session_dir, port, and bucket pool — the suite is parallel-safe by construction.

### Directory backends

Most of the suite drives the **YAML** backend (`YamlDirectory`, the default
when `ProxyHarness.auth_config` is unset). `tests/test_openbao.py` covers the
**OpenBao** backend instead: it spins up an ephemeral `bao server -dev`
(`OpenBaoServer`), runs `s32p-ctl … setup` to bootstrap the proxy/admin
AppRoles, seeds users/buckets through an `OpenBaoDirectory` authed as the
admin AppRole, and points the proxy at the proxy AppRole via
`ProxyHarness(auth_config={"backend": "openbao", …})`. This exercises both the
`s32p-ctl` KV write path and the proxy's runtime KV read path; it skips when
`bao` isn't installed. Both backends share the same `s32p-ctl` command surface
(`_CtlDirectory`), so seeding is identical — only the backend-selection flags
and bootstrap differ.
