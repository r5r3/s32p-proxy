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
- `s3pm-support`: shared support library (common config/types/errors/helpers used across crates)
- `s3pm-gateway`: the per-access-key worker gateway binary (launched by the proxy; it runs as alternative to VersityGW)

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
│  • classifies requests (query+path)      │
│  • routes by "request class" via YAML    │
│    (proxy to profile or local response)  │
│  • gates worker spawn with SigV4         │
│    header-only validation                │
│  • reverse proxies to per-user worker    │
│  • optional response header rewriting    │
└───────────────────┬──────────────────────┘
                    │ internal HTTP (loopback) or
                    │ HTTP over Unix domain sockets (UDS)
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

## Current Status (January 2026)

### Implemented

#### Proxy / request flow

- **Pingora proxy-mode HTTP server**
  - Reverse proxies to locally spawned workers over loopback or Unix domain sockets (UDS)
  - Preserves SigV4-critical headers (notably the original `Host`)
  - Has a `response_filter` hook for response header rewriting

- **Request classification** (`crates/s3pm-support/src/classifier.rs`)
  - Shared by proxy + gateway (single source of truth for routing decisions)
  - Parses path + query parameters (and selected headers where needed, e.g. `x-amz-copy-source`)
  - Produces a high-level operation class key:
    - `read` (e.g. `GetObject`, `HeadObject`, `ListObjectsV2`, `ListBuckets`, `GetBucketLocation`, `HeadBucket`)
    - `write` (e.g. `PutObject`, `CopyObject`, `DeleteObject`, `DeleteObjects`)
    - `multipart` (initiate/upload-part/list-parts/complete/abort + list uploads)
    - `versioning` (detected, but not implemented yet)
    - `object_lock` (detected, but not implemented yet)
    - `bucket_admin` (CreateBucket/DeleteBucket; detected, but not implemented yet)
    - `other`

- **Config-driven routing** (`etc/s3-proxy-manager.yaml`)
  - Routes based on the classifier class keys above.
  - Each class maps to one action:
    - `proxy` (selects a worker profile)
    - `not_implemented` (local S3 NotImplemented response, but only after SigV4 validation)
  - If a specific class key is not configured, the proxy falls back to the `other` route.

#### Gateway (`s3pm-gateway`)

Experimental alternative to `versitygw`. Implements a growing subset of the S3 REST API directly on top of a POSIX filesystem.

Implemented operations:

- **Read**
  - `GetObject`
  - `HeadObject`
  - `HeadBucket`
  - `ListBuckets`
  - `GetBucketLocation`
  - `ListObjectsV2`
- **Write**
  - `PutObject` (streaming upload)
  - `CopyObject` (server-side copy; size-limited by configuration)
  - `DeleteObject`
  - `DeleteObjects` (`POST /?delete`)
- **Multipart**
  - `CreateMultipartUpload` (`POST ?uploads`)
  - `UploadPart` (`PUT ?partNumber=N&uploadId=...`)
  - `ListParts` (`GET ?uploadId=...`)
  - `ListMultipartUploads` (`GET /bucket?uploads`)
  - `CompleteMultipartUpload` (`POST ?uploadId=...`)
  - `AbortMultipartUpload` (`DELETE ?uploadId=...`)

Notes / behavior:

- Supports single-range `Range: bytes=...` (returns `206 Partial Content`; invalid ranges return `416 InvalidRange`).
- Rejects most query parameters for now (including presigned URLs), except those required for:
  - `?location`, `?list-type=2`, and the multipart query parameters (`?uploads`, `?uploadId=...`, `?partNumber=...`)
- `ListObjectsV2` supports Lustre Lazy Size on MDS (LSOM) when built with the Lustre feature.
- When built with `--features lustre`, the gateway creates new files with Lustre striping via `llapi_file_create()`.
  - Config: `S3PM_LUSTRE_MAX_STRIPE_COUNT` (default: `4`) caps the stripe count.
  - **Serial uploads** (`PutObject`, `CopyObject`, and any temp/staging files):
    - `stripe_size = S3PM_CHUNK_SIZE_MB`
    - `stripe_count = ceil(file_size / stripe_size)`, capped by `S3PM_LUSTRE_MAX_STRIPE_COUNT`
  - **Multipart uploads**:
    - `direct.bin`: `stripe_size = min(stripe_size_serial, part_size)`, `stripe_count = S3PM_LUSTRE_MAX_STRIPE_COUNT`
    - individual part files are striped like serial uploads.
- `ETag` for final objects is generated from the inode number.

#### Multipart upload (`s3pm-gateway`) — server-side assembly algorithm

Multipart uploads are implemented in `crates/s3pm-gateway/src/multipart.rs`.

The design goal is to **avoid creating a full extra copy of the object on the server** during completion. The gateway does this by writing parts into an **assembly file** that can be **renamed into place** as the final object.

### On-disk layout (per bucket)

For a bucket with root `<bucket_root>`, the gateway reserves a hidden directory (default name: `.s3pm-mpu`):

- `<bucket_root>/.s3pm-mpu/uploads/<upload_id>/meta.json`  
  JSON metadata for the upload (bucket/key, state, and a map of uploaded parts).
- `<bucket_root>/.s3pm-mpu/uploads/<upload_id>/lock`  
  A file used with `flock(LOCK_EX)` to serialize metadata updates and completion.
- `<bucket_root>/.s3pm-mpu/uploads/<upload_id>/direct.bin`  
  The **assembly file** (random-access writes at part offsets).
- `<bucket_root>/.s3pm-mpu/uploads/<upload_id>/parts/part-00001.bin` (etc.)  
  Fallback storage for parts that cannot safely be placed into `direct.bin`.

The gateway also prevents clients from reading/writing/deleting objects *inside* the reserved multipart directory by treating that first path segment as “reserved”.

### Part upload placement

When a part arrives (`PUT ?partNumber=N&uploadId=...`), the gateway decides where to store it:

1. It reads and updates `meta.json` under an exclusive lock (short critical section).
2. It tries to determine a stable **assumed part size**:
   - If part **#1** is uploaded and no size is known yet, its length becomes the assumed part size.
   - If no assumed size exists and the gateway sees **two parts with the same size**, it promotes that size to the assumed part size.
3. If an assumed part size is known and the part is **not larger** than it, the gateway computes the direct placement offset:

   `offset = (partNumber - 1) * assumed_part_size`

   and writes the request body **directly into `direct.bin` at that offset** (random-access file write).
4. Otherwise, it writes the part as an individual file under `parts/` and records that in metadata.

Metadata records, per part:
- size
- an upload-time ETag (stable, client-visible; completion does not validate ETags)
- timestamp
- storage kind: `{ direct: off }` or `{ file: name }`

### Completion: assembling without a full server-side copy

On `CompleteMultipartUpload` (`POST ?uploadId=...`), the gateway:

1. Reads the XML body (requested part numbers).
2. Takes an **exclusive lock** for the entire completion to prevent concurrent `UploadPart` and to make the final rename deterministic.
3. Validates the request:
   - Parts must be **contiguous** starting at 1 (`1..=lastPart`).
   - Every requested part must exist in `meta.json`.

Then it chooses one of two assembly paths:

#### Fast path (rename `direct.bin` into place)

This path is taken when the upload matches the classic “fixed-size parts + last part shorter or equal” layout:

- `assumed_part_size` is known
- parts `1..last-1` are **exactly** `assumed_part_size`
- any parts already stored as `direct` are at the expected offsets

Fast-path algorithm:

1. Compute final object size:

   `final_size = (lastPart - 1) * assumed_part_size + size(lastPart)`
2. Ensure all missing parts are present in `direct.bin`:
   - For parts stored as separate files, copy them **into `direct.bin` at their final offsets** (range copy).
3. `ftruncate(direct.bin, final_size)`
4. **Rename** `direct.bin` → `<final_object_path>`

If the rename fails with cross-device (`EXDEV`), the gateway performs a **single** copy of the already-assembled `direct.bin` into a temp file next to the destination and renames that temp file into place. Importantly, it still avoids “assemble → copy again” behavior.

✅ **Why this avoids a full copy:** in the common case (same filesystem), completion becomes a metadata operation (`rename`) after assembling into `direct.bin`. There is no “write whole object into a second file” step.

#### Fallback path (sequential staging file)

If the fixed-size/offset conditions don’t hold, the gateway assembles sequentially:

1. Create a staging output file:
   - If the upload directory is on a different filesystem than the destination, the staging file is created **next to the destination** (to avoid an extra copy later).
2. Copy parts in order into the staging file:
   - For `direct` parts: copy the required range out of `direct.bin`.
   - For `file` parts: copy the entire part file.
3. Rename staging file → final object path.

Finally, on success the gateway marks the upload as completed, returns the completion XML + ETag, and removes the upload directory.

### Practical highlights

- The gateway’s “happy path” is optimized for **large objects**: parts are placed directly into their final offsets, and completion is typically a truncate + rename.
- The implementation is careful to avoid data corruption:
  - Direct placement is only used when offsets can be computed safely (no overlap risk).
  - Metadata updates are protected by `flock` and written atomically (`meta.json.tmp` → rename).

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
  - General `respond_bytes()` helper for header/body responses

#### SigV4 validation behavior

- **DoS mitigation via “spawn gating”**
  - If a worker is **not running**, the proxy performs **SigV4 header-only verification**
    using `aws-sigv4` and the client-provided `x-amz-content-sha256`
  - Only if the signature is valid will the proxy start the worker
  - Once a worker is already running, the proxy does **not** fully validate SigV4;
    it only extracts the access key for routing and forwards the request to the worker

- Workers (VersityGW or s3pm-gateway) still validate SigV4 again (cannot be disabled).

#### Worker lifecycle management (`src/worker_manager.rs`)

- Workers are keyed by **(access_key, worker_profile)**
  - supports multiple access keys mapped to the same unix user but different bucket ACLs
  - allows routing different command classes to different worker profiles per access key
- Workers are started via a configurable launcher (default: `restricted-exec`)
  - If running as root and `pass_user_flag_if_root=true`, the proxy passes `--user <username>`
- Upstream bind (per worker):
  - TCP loopback: `127.0.0.1:<port>`
  - Unix domain socket: `/run/s3pm/<uid>/worker.sock` (example; configurable)
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

`s3pm-ctl` manages the Directory state (users, buckets, ACLs) for both supported backends:
- `--backend openbao` (default): OpenBao/Vault KV v2 + indices
- `--backend yaml`: local directory.yaml file

All commands work with both backends. The backend is selected via `--backend`.

### Backend selection

#### YAML backend
For YAML, you must provide the directory file path:

```bash
s3pm-ctl --backend yaml --yaml-path /etc/s3pm/directory.yaml <COMMAND...>
```

#### OpenBao backend
For OpenBao, provide `--address` (or `VAULT_ADDR`) plus authentication:
- Setup typically uses a root/admin token (`--token` or `VAULT_TOKEN`)
- Normal operations typically use AppRole (`--role-id(-file)` + `--secret-id(-file)`)

Common OpenBao flags:
- `--address http://127.0.0.1:8200` (or `VAULT_ADDR`)
- `--kv-mount secret` (default: `secret`)
- `--prefix s3pm` (default: `s3pm`)
- `--approle-mount approle` (default: `approle`)
- `--token ...` (or `VAULT_TOKEN`)
- `--role-id ...` / `--role-id-file ...`
- `--secret-id ...` / `--secret-id-file ...`

Example:

```bash
s3pm-ctl --backend openbao \
  --address http://127.0.0.1:8200 \
  --kv-mount secret \
  --prefix s3pm \
  --approle-mount approle \
  --role-id-file /etc/s3pm/admin_role_id \
  --secret-id-file /etc/s3pm/admin_secret_id \
  <COMMAND...>
```

### Setup

#### OpenBao setup
Creates/updates:
- enables AppRole auth method at `--approle-mount` (default: `approle`)
- creates policies + roles:
  - `s3pm-proxy` (read-only)
  - `s3pm-admin` (read-write)

You must provide a bootstrap token (`--token` or `VAULT_TOKEN`):

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=... # root/admin token for setup only

s3pm-ctl --backend openbao setup \
  --proxy-role-id-file  /etc/s3pm/proxy_role_id \
  --proxy-secret-id-file /etc/s3pm/proxy_secret_id \
  --admin-role-id-file  /etc/s3pm/admin_role_id \
  --admin-secret-id-file /etc/s3pm/admin_secret_id
```

The secret files are written with permissions 0600 on Unix.

#### YAML setup
Creates an empty directory file skeleton:

```bash
s3pm-ctl --backend yaml --yaml-path /etc/s3pm/directory.yaml setup
```

### Users

Commands:
- `user add`
- `user rm`
- `user ls`

Add a user:

```bash
s3pm-ctl ... user add \
  --access-key AKIA_ALICE_1 \
  --secret-key alice_secret \
  --username alice \
  --uid 1001 \
  --gid 1001
```

Remove a user (optionally scrubs their `access_key` from bucket ACLs):

```bash
s3pm-ctl ... user rm --access-key AKIA_ALICE_1 --cleanup-acls true
```

List users:

```bash
s3pm-ctl ... user ls
```

### Buckets

Commands:
- `bucket add`
- `bucket rm`
- `bucket ls`
- `bucket acl-set`

Add a bucket:

```bash
s3pm-ctl ... bucket add \
  --name photos \
  --data-path /srv/s3/alice/photos \
  --grant ak:AKIA_ALICE_1:read_write
```

`--grant` is repeatable and supports:
- `ak:<ACCESS_KEY>:read_only|read_write`
- `group:<GROUP_NAME>:read_only|read_write`

Optional: provide a stable bucket id (otherwise a UUID is generated):

```bash
s3pm-ctl ... bucket add \
  --bucket-id bkt-alice-photos \
  --name photos \
  --data-path /srv/s3/alice/photos \
  --grant ak:AKIA_ALICE_1:read_write
```

Remove a bucket:

```bash
s3pm-ctl ... bucket rm --bucket-id bkt-alice-photos
```

List buckets:

```bash
s3pm-ctl ... bucket ls
```

Replace a bucket ACL:

```bash
s3pm-ctl ... bucket acl-set \
  --bucket-id bkt-team \
  --grant group:s3-team:read_write \
  --grant ak:AKIA_ALICE_1:read_only
```

### Import / Export

Due to the usage of [`io_uring`](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io), 
you need RHEL 9.3, or another Linux distribution with a compatible kernel. 
On RHEL, it is necessary to enable the `io_uring` kernel module:

```bash
sysctl -w kernel.io_uring_disabled=0
```

Import a directory YAML into the selected backend:

```bash
s3pm-ctl ... import-yaml --yaml /path/to/directory.yaml --replace true
```

- openbao: `--replace` purges the directory subtrees under the configured prefix before import.
- yaml: `--replace` overwrites the destination file; `--replace false` merges by `users.access_key` and `buckets.id`.

Export backend state to a directory YAML:

```bash
s3pm-ctl ... export-yaml --yaml /path/to/directory.yaml
```

## Building

```bash
cargo build
```

---

## Running (development)

```bash
RUST_LOG=s3_proxy_manager=debug,pingora=info,pingora_proxy=info cargo run --bin s3pm-proxy
```

The proxy binds to the address configured in `etc/s3-proxy-manager.yaml`, default:

```
http://localhost:9000
```

Workers are launched on-demand and bind to loopback (`127.0.0.1:<port>`) or a per-UID Unix socket.

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
- Keep worker listeners loopback-only or use Unix domain sockets (recommended for local-only traffic).

ACL notes:

- `read_only` vs `read_write` is computed by the proxy for staging and (optionally) future proxy-side enforcement.
- Actual filesystem enforcement is still done by the kernel permissions of the target user and the bucket data path.

---

## Known limitations / TODO

- **Versioning-related** requests are detected and currently return `NotImplemented`
- **Object Lock–related** requests are detected and currently return `NotImplemented`
- Multipart notes / current constraints:
  - `CompleteMultipartUpload` currently requires **contiguous part numbers starting at 1**.
  - Completion does not validate client-provided part ETags (the gateway uses a stable, upload-time ETag per part).
  - Multipart copy / UploadPartCopy is not implemented.
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

VersityGW or `s3pm-gateway` are the storage-facing components and performs the authoritative SigV4 validation.
