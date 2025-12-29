# s3-proxy-manager

`s3-proxy-manager` is a **Rust-based S3-compatible proxy + worker manager** built on **Cloudflare Pingora**.

It accepts S3 client requests, maps S3 identities (SigV4 access keys) to **Unix users**, and routes traffic to **per-access-key worker processes** (currently: **VersityGW**) that expose a **shared POSIX filesystem** with kernel-enforced permissions.

A central design goal is to preserve Unix security semantics:

> **All filesystem access happens inside a process already running as the target Unix user.**

The proxy itself does not perform filesystem I/O.

---

## Goals

- Provide an **S3-compatible endpoint** backed by a POSIX filesystem
- Enforce **per-user isolation using Unix UIDs/GIDs** (kernel-level security)
- Support **standard S3 clients** (AWS CLI, MinIO client / SDKs)
- Start workers **on demand**, then reuse them (per access key + profile)
- Prevent easy **DoS via worker spawn storms**
- Keep proxy logic (auth/routing/management) separate from the storage worker

---

## Repository layout

This repository is a Rust workspace with multiple crates:

- `s3pm-proxy`: the Pingora-based proxy binary
- `s3pm-directory`: shared Directory API + YAML/OpenBao backends + shared YAML file format
- `s3pm-admin`: management library (OpenBao write access, import/export, etc.)
- `s3pm-ctl`: CLI wrapper around `s3pm-admin` (operator tooling)

---

## Architecture

```
    ┌──────────────┐
    │  S3 Clients  │  (aws cli, mcli, SDKs)
    └──────┬───────┘
           │  HTTP(S)
           ▼
┌──────────────────────────────────────────┐
│              s3-proxy-manager            │
│            (Pingora HTTP proxy)          │
│                                          │
│  • parses Authorization → access key     │
│  • maps access key → unix user           │
│  • looks up user + ACLs via Directory    │
│    (YAML file or OpenBao)                │
│  • local ListBuckets response            │
│  • classifies requests (query+path)      │
│  • routes by "request class" via YAML    │
│    (proxy to profile or local response)  │
│  • gates worker spawn with SigV4         │
│    header-only validation                │
│  • reverse proxies to per-user worker    │
│  • optional response header rewriting    │
└───────────────────┬──────────────────────┘
                    │ internal HTTP (loopback)
                    ▼
┌────────────────────────────────┐
│      Per-access-key workers    │
│ (e.g. VersityGW, unmodified)   │
│                                │
│  • runs as unix user           │
│  • validates SigV4 again       │
│  • uses a staged posix_root    │
└───────────────┬────────────────┘
                │ POSIX syscalls
                ▼
┌──────────────────────────────────────────┐
│   Shared POSIX FS (real bucket data)     │
│                                          │
│  Each worker starts with a fresh temp    │
│  directory as its posix_root.            │
│  Symlinks to all accessible buckets      │
│  are created in that temp root before    │
│  the worker starts. The worker follows   │
│  those links.                            │
└──────────────────────────────────────────┘
```

---

## Current Status (December 2025)

### Implemented

#### Proxy / request flow

- **Pingora proxy-mode HTTP server**
  - Reverse proxies to locally spawned workers over loopback
  - Preserves SigV4-critical headers (notably the original `Host`)
  - Has a `response_filter` hook for response header rewriting

- **Request classification** (`src/classifier.rs`)
  - Classifies requests by parsing path + query parameters
  - Currently focuses on **multipart uploads** and **versioning** detection

- **Config-driven routing** (`etc/s3-proxy-manager.yaml`)
  - Routes based on classifier class keys:
    - `multipart`
    - `versioning`
    - `other`
  - Each class maps to:
    - `not_implemented` (local response)
    - `proxy` (selects a worker profile)

#### Directory backends (users, buckets, ACLs)

A “Directory” provides:

- `user_by_access_key(access_key)` → unix identity + secret key
- `buckets_for_access_key(access_key)` → list of visible buckets with effective access

Backends:

- **YAML**: load once at startup into HashMaps
- **OpenBao**: AppRole login + KV v2 reads, using **indices** for efficient lookup

Notes:

- **Multiple access keys may map to the same Unix user** (same `username/uid/gid`).
- Workers are keyed by **(access_key, worker_profile)** (not just uid), because the staged bucket set is per access key.

#### Bucket ACL model

Buckets have an ACL list. Each ACL entry grants an access level to a principal:

- `access_key` principal (direct grant)
- `group_name` principal (POSIX group name grant)

Effective access for a caller is the max of all matching entries (e.g. `read_write` beats `read_only`).

Group membership is resolved from the OS at runtime (username → gids → group names).

#### Local responses (no proxying)

- Shared response helpers in `src/responses.rs`
  - S3 REST-XML errors (e.g. `AccessDenied`, `SignatureDoesNotMatch`, `NotImplemented`)
  - A `ListBuckets` XML body builder and response helper
  - General `respond_bytes()` helper for header/body responses

Implemented local operations:

- **ListBuckets** (`GET /`) is answered locally (after SigV4 validation).

#### SigV4 validation behavior

- **DoS mitigation via “spawn gating”**
  - If a worker is **not running**, the proxy performs **SigV4 header-only verification**
    using `aws-sigv4` and the client-provided `x-amz-content-sha256`
  - Only if the signature is valid will the proxy start the worker
  - Once a worker is already running, the proxy does **not** fully validate SigV4;
    it only extracts the access key for routing and forwards the request to the worker

- Workers (VersityGW) still validate SigV4 again (cannot be disabled).

#### Worker lifecycle management (`src/worker_manager.rs`)

- Workers are keyed by **(access_key, worker_profile)**
  - supports multiple access keys mapped to the same unix user but different bucket ACLs
  - allows routing different command classes to different worker profiles per access key
- Workers are started via a configurable launcher (default: `restricted-exec`)
  - If running as root and `pass_user_flag_if_root=true`, the proxy passes `--user <username>`
- Loopback bind: `127.0.0.1:<port>`
- Readiness probing: connect loop until port is reachable
- Idle shutdown after `idle_timeout_secs`
- Sweeper removes dead/idle workers periodically (`sweep_interval_secs`)
- **Staged posix_root**
  - On each worker start, the proxy creates a **fresh temp directory** under `workers.runtime_root`
  - Creates symlinks for all buckets visible to the access key:
    - `<temp>/<bucket_name>` → `<bucket.data_path>`
  - Passes that temp directory as `{{posix_root}}` to the worker
  - When the worker stops, the temp directory is removed

Worker args/env templates support placeholders such as:
- `{{bind_addr}}`, `{{port}}`, `{{posix_root}}`, `{{access_key}}`, `{{secret_key}}`, etc.

---

## Configuration

Primary configuration: `etc/s3-proxy-manager.yaml`

Key sections:

- `server.listen` / `server.public_scheme`
- `auth.*` (directory backend selection and credentials)
- `workers.runtime_root` (base dir for per-worker temp roots)
- `workers.launcher.*`
- `workers.lifecycle.*`
- `workers.profiles.*` (worker templates)
- `routing.class_map.*` (routes classifier classes to actions)

### Directory backend selection

Choose a directory backend via `auth.backend`:

- `yaml` — load a local directory file
- `openbao` — use OpenBao (Vault-compatible API) with AppRole + KV v2 + indices

#### YAML backend config

```yaml
auth:
  backend: "yaml"
  yaml:
    path: "/etc/s3pm/directory.yaml"
```

#### OpenBao backend config (AppRole)

```yaml
auth:
  backend: "openbao"
  openbao:
    address: "http://127.0.0.1:8200"
    approle_mount: "approle"
    role_id_file: "/etc/s3pm/role_id"
    secret_id_file: "/etc/s3pm/secret_id"
    kv_mount: "secret"
    prefix: "s3pm"
```

### YAML directory file format

Example `/etc/s3pm/directory.yaml`:

```yaml
version: 1

users:
  - access_key: "AKIA_ALICE_1"
    secret_key: "alice_secret"
    username: "alice"
    uid: 1001
    gid: 1001

  # Second access key mapping to the same unix user:
  - access_key: "AKIA_ALICE_2"
    secret_key: "alice_secret_2"
    username: "alice"
    uid: 1001
    gid: 1001

buckets:
  - id: "bkt-alice-photos"
    name: "photos"
    data_path: "/srv/s3/alice/photos"
    acl:
      - principal: { type: "access_key", access_key: "AKIA_ALICE_1" }
        access: "read_write"
      - principal: { type: "access_key", access_key: "AKIA_ALICE_2" }
        access: "read_write"

  - id: "bkt-team"
    name: "team"
    data_path: "/srv/s3/team"
    acl:
      - principal: { type: "group_name", name: "s3-team" }
        access: "read_write"
      - principal: { type: "access_key", access_key: "AKIA_ALICE_1" }
        access: "read_only"
```

### OpenBao KV layout (conceptual)

Under `auth.openbao.kv_mount` + `auth.openbao.prefix`, the directory uses KV v2 documents:

- `prefix/users/<access_key>` → `UserDoc`
- `prefix/buckets/<bucket_id>` → `BucketDoc`
- `prefix/index/access_key/<access_key>` → `{ bucket_ids: [...] }`
- `prefix/index/group/<group_name>` → `{ bucket_ids: [...] }`

The indices make `buckets_for_access_key()` efficient:
- read index for the access key
- resolve group names for the unix user
- read index for each group name
- load bucket docs and evaluate ACLs (authoritative)

---

## Administration CLI (`s3pm-ctl`)

This repo includes an operator CLI, **`s3pm-ctl`**, built on top of the `s3pm-admin` library.

It supports:

- setting up OpenBao (KV layout + policies + AppRoles)
- adding/removing/listing users
- adding/removing/listing buckets
- changing bucket ACLs
- importing YAML â OpenBao
- exporting OpenBao â YAML

> Tip: run `s3pm-ctl --help` (and `s3pm-ctl <command> --help`) to see the exact flags supported by your current build.

### OpenBao setup

The setup command creates **two AppRoles**:

- `s3pm-proxy`: **read-only** (used by the proxy)
- `s3pm-admin`: **read-write** (used by operator tooling)

Typical flow:

```bash
# using a root token (or other high-privilege token) just for setup
s3pm-ctl openbao setup \
  --address http://127.0.0.1:8200 \
  --root-token "$OPENBAO_TOKEN" \
  --approle-mount approle \
  --kv-mount secret \
  --prefix s3pm
```

The command prints the generated **Role ID** and **Secret ID** for both roles.
Store the proxy credentials as files referenced by `s3pm-proxy` config:

- `auth.openbao.role_id_file`
- `auth.openbao.secret_id_file`

### Users

```bash
# add/update a user mapping
s3pm-ctl user add \
  --access-key AKIA_ALICE_1 \
  --secret-key alice_secret \
  --username alice \
  --uid 1001 --gid 1001

# list users
s3pm-ctl user ls

# remove a user mapping (optionally scrub ACL references)
s3pm-ctl user rm --access-key AKIA_ALICE_1
```

### Buckets

```bash
# add a bucket (requires id/name/path + initial ACL)
s3pm-ctl bucket add \
  --id bkt-alice-photos \
  --name photos \
  --data-path /srv/s3/alice/photos

# list buckets
s3pm-ctl bucket ls

# remove a bucket by id
s3pm-ctl bucket rm --id bkt-alice-photos
```

### Bucket ACLs (permissions)

ACL principals are:

- `access_key:<AKIA...>`
- `group_name:<posix-group>`

```bash
# set / replace the ACL (example syntax; use --help for your exact flags)
s3pm-ctl bucket acl set \
  --id bkt-team \
  --grant group_name:s3-team=read_write \
  --grant access_key:AKIA_ALICE_1=read_only
```

The proxy computes effective access as the maximum of all matching ACL entries.

### Import / Export (YAML to/from OpenBao)

```bash
# import YAML into OpenBao (optionally replace existing data)
s3pm-ctl import-yaml --file /etc/s3pm/directory.yaml --replace

# export OpenBao directory to YAML
s3pm-ctl export-yaml --file /etc/s3pm/directory.yaml
```

---

## Building

```bash
cargo build
```

---

## Running (development)

```bash
RUST_LOG=s3_proxy_manager=debug cargo run -p s3pm-proxy
```

The proxy binds to the address configured in `etc/s3-proxy-manager.yaml`, default:

```
http://localhost:9000
```

Workers are launched on-demand and bind to loopback (`127.0.0.1:<port>`).

---

## Testing with MinIO Client (`mcli`)

```bash
mcli alias set S3PM http://localhost:9000 TESTACCESSKEY123 TESTSECRETKEY456
mcli ls --debug S3PM
```

Notes:

- For the first request when no worker exists, the proxy validates SigV4 (header-only) before spawning.
- VersityGW validates SigV4 again.

---

## Security Notes

- Run the proxy as **root** if you want the launcher to actually switch users (`restricted-exec --user`).
- If the proxy is not root, workers start as the proxy’s user (development convenience).
- Workers should never run as root in production.
- Keep worker listeners loopback-only (or move to Unix domain sockets later).

ACL notes:

- `read_only` vs `read_write` is computed by the proxy for staging and (optionally) future proxy-side enforcement.
- Actual filesystem enforcement is still done by the kernel permissions of the target user and the bucket data path.

---

## Known limitations / TODO

- **Multipart uploads** are detected and currently return `NotImplemented`
  - Only after request validation (SigV4) to avoid turning invalid requests into “useful” responses
- **Versioning-related** requests are detected and currently return `NotImplemented`
- More S3 API coverage still needed (ListObjectsV2, GET/PUT object streaming, etc.)
- More production hardening:
  - rate limiting / max concurrent starts
  - negative caching for repeated invalid requests
  - structured metrics
- OpenBao provisioning tooling (managing bucket docs + indices) not included here

---

## License

TBD

---

## Acknowledgements

- Cloudflare Pingora
- AWS SigV4 specification
- MinIO client ecosystem
- VersityGW

---

## Project Direction

`s3-proxy-manager` is the **control plane**:
authentication/routing/worker lifecycle for per-access-key S3 access to a shared filesystem.

VersityGW remains the storage-facing component and performs the authoritative SigV4 validation.
