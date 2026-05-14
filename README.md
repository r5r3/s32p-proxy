# s32p: S3 to POSIX proxy and gateway

`s32p-proxy` is a **Rust-based S3-compatible proxy + gateway manager** built on **Cloudflare Pingora**.

---

⚠️ **EARLY DEVELOPMENT WARNING** ⚠️

This project is in an **early development stage** and is **not ready for production use**. All aspects of the implementation may change significantly in future versions. Use only for testing and development purposes.

---

It accepts S3 client requests, maps S3 identities (SigV4 access keys) to **Unix users**, and routes traffic to **per-access-key worker processes** (currently: **VersityGW**, or experimental alternative **s32p-gateway**) that expose a **shared POSIX filesystem** with kernel-enforced permissions.

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

- `s32p-proxy`: the Pingora-based proxy binary
- `s32p-directory`: shared Directory API + YAML/OpenBao backends + shared YAML file format
- `s32p-admin`: management library (OpenBao write access, import/export, etc.)
- `s32p-ctl`: CLI wrapper around `s32p-admin` (operator tooling)
- `s32p-support`: shared support library (common config/types/errors/helpers used across crates)
- `s32p-gateway`: the per-access-key worker gateway binary (launched by the proxy; it runs as alternative to VersityGW)

---

## Architecture

```
    ┌──────────────┐
    │  S3 Clients  │  (aws cli, mcli, SDKs)
    └──────┬───────┘
           │  HTTP(S)
           ▼
┌───────────────────────────────────────────┐
│                 s32p-proxy                │
│            (Pingora HTTP proxy)           │
│                                           │
│  • parses Authorization → access key      │
│  • maps access key → unix user            │
│  • looks up user + ACLs via Directory     │
│    (YAML file or OpenBao)                 │
│  • classifies requests (query+path)       │
│  • routes by "request class" via YAML     │
│    (proxy to profile or local response)   │
│  • gates worker spawn with SigV4          │
│    verification (auth header or presign)  │
│  • reverse proxies to per-user worker     │
│  • optional response header rewriting     │
└───────────────────┬───────────────────────┘
                    │ internal HTTP (loopback) or
                    │ HTTP over Unix domain sockets (UDS)
                    ▼
      ┌────────────────────────────────┐
      │      Per-access-key workers    │
      │        (e.g. s32p-gateway      │
      │           or VersityGW)        │
      │                                │
      │  • runs as unix user           │
      │  • validates SigV4 again       │
      │  • uses a staged posix_root    │
      └───────────────┬────────────────┘
                      │ POSIX syscalls
                      ▼
┌───────────────────────────────────────────┐
│   Shared POSIX FS (real bucket data)      │
│                                           │
│  Each worker starts with a fresh temp     │
│  directory as its posix_root.             │
│  Symlinks to all accessible buckets       │ 
│  are created in that temp root before     │ 
│  the worker starts. The worker follows    │
│  those links.                             │
└───────────────────────────────────────────┘
```

---

## Current Status

### Proxy / request flow

- **Pingora proxy-mode HTTP server**
  - Reverse proxies to locally spawned workers over loopback or Unix domain sockets (UDS)
  - Preserves SigV4-critical headers (notably the original `Host`)
  - Has a `response_filter` hook for response header rewriting

- **Request classification** (`crates/s32p-support/src/classifier.rs`)
  - Shared by proxy + gateway (single source of truth for routing decisions)
  - Parses path + query parameters (and selected headers where needed, e.g. `x-amz-copy-source`)
  - Produces a high-level operation class key:
    - `read` (e.g. `GetObject`, `HeadObject`, `ListObjectsV1`/`V2`, `ListBuckets`, `GetBucketLocation`, `HeadBucket`, `GetObjectAcl`, `GetBucketAcl`)
    - `write` (e.g. `PutObject`, `CopyObject`, `DeleteObject`, `DeleteObjects`, `RenameObject`, `PutObjectAcl`, `PutBucketAcl`)
    - `multipart` (initiate/upload-part/list-parts/complete/abort + list uploads)
    - `versioning` (detected, but not implemented yet)
    - `object_lock` (detected, but not implemented yet)
    - `bucket_admin` (`CreateBucket`/`DeleteBucket`; detected and routed to NotImplemented — bucket lifecycle is operator-only via `s32p-ctl`)
    - `other`

- **Config-driven routing** (`etc/s32p-proxy.yaml`)
  - Routes based on the classifier class keys above.
  - Each class maps to one action:
    - `proxy` (selects a worker profile)
    - `not_implemented` (local S3 NotImplemented response, but only after SigV4 validation)
  - If a specific class key is not configured, the proxy falls back to the `other` route.

### Gateway (`s32p-gateway`)

Experimental alternative to `versitygw`. Implements a growing subset of the S3 REST API directly on top of a POSIX filesystem.

#### Implemented operations:

- **Read**
  - `GetObject`
  - `HeadObject`
  - `HeadBucket`
  - `ListBuckets`
  - `GetBucketLocation`
  - `ListObjectsV1` (`GET /{bucket}`, legacy form) and `ListObjectsV2` (`GET /{bucket}?list-type=2`)
- **Write**
  - `PutObject` (streaming upload)
  - `CopyObject` (server-side copy; size-limited by configuration)
  - `DeleteObject`
  - `DeleteObjects` (`POST /?delete`)
  - `RenameObject` (`PUT ?renameObject` with `x-amz-rename-source`; same-bucket only)
- **Multipart**
  - `CreateMultipartUpload` (`POST ?uploads`)
  - `UploadPart` (`PUT ?partNumber=N&uploadId=...`)
  - `ListParts` (`GET ?uploadId=...`)
  - `ListMultipartUploads` (`GET /bucket?uploads`)
  - `CompleteMultipartUpload` (`POST ?uploadId=...`)
  - `AbortMultipartUpload` (`DELETE ?uploadId=...`)
- **ACL**
  - `GetObjectAcl`, `GetBucketAcl` (`GET ?acl`)
  - `PutObjectAcl`, `PutBucketAcl` (`PUT ?acl`) — accepted as a no-op when the requested ACL matches the current POSIX state; mismatches are rejected. The directory ACLs in `s32p-ctl` remain authoritative.

#### Notes / behavior:

- Supports single-range `Range: bytes=...` (returns `206 Partial Content`; invalid ranges return `416 InvalidRange`).
- Rejects most query parameters for now, except those required for:
  - `?location`, `?list-type=2`, `?delete`, `?acl`, `?renameObject`, and the multipart query parameters (`?uploads`, `?uploadId=...`, `?partNumber=...`)
- **SigV4 presigned URL query parameters** (`X-Amz-*`) are supported and do **not** count as "effective" query parameters for routing/handling. A small fixed set of other keys is also treated as non-effective: `x-id`, `content-type`, `cache-control`, `content-encoding`, `content-disposition`, `expires`, `x-amz-storage-class`.
- `ListObjectsV2` supports Lustre Lazy Size on MDS (LSOM) when built with the Lustre feature.
- When built with `--features lustre`, the gateway creates new files with Lustre striping via `llapi_file_create()`.
  - Config: `S32P_LUSTRE_MAX_STRIPE_COUNT` (default: `4`) caps the stripe count.
  - **Serial uploads** (`PutObject`, `CopyObject`, and any temp/staging files):
    - `stripe_size = S32P_CHUNK_SIZE_MB × 1 MiB` (env var is in MiB; default `4` → 4 MiB)
    - `stripe_count = ceil(file_size / stripe_size)`, capped by `S32P_LUSTRE_MAX_STRIPE_COUNT`
  - **Multipart uploads**:
    - `direct.bin`: `stripe_size = min(stripe_size_serial, part_size)`, `stripe_count = S32P_LUSTRE_MAX_STRIPE_COUNT`
    - individual part files are striped like serial uploads.
- `ETag` for final objects is generated from the inode number.
- **No object-level metadata storage.** `s32p-gateway` does not persist `x-amz-meta-*` headers or a client-supplied `Content-Type`; PUT silently drops them and HEAD/GET return only what can be derived from the file (size, inode-as-ETag, mtime). This is by design — the bidirectional POSIX interop story (a POSIX user creates a file under `bucket.data_path` and an S3 client reads it intact) breaks if metadata lives in xattrs or sidecars, since POSIX-created files would then be "incomplete" and `mv`/`cp` could orphan sidecars. Same principle as `PutObjectAcl` being a no-op when the requested ACL matches current POSIX state.

### Multipart upload (`s32p-gateway`) — server-side assembly algorithm

Multipart uploads are implemented in `crates/s32p-gateway/src/multipart.rs`.

The design goal is to **avoid creating a full extra copy of the object on the server** during completion. The gateway does this by writing parts into an **assembly file** that can be **renamed into place** as the final object.

#### On-disk layout (per bucket)

For a bucket with root `<bucket_root>`, the gateway reserves a hidden directory (default name: `.s32p-mpu`):

- `<bucket_root>/.s32p-mpu/uploads/<upload_id>/meta.json`  
  JSON metadata for the upload (bucket/key, state, and a map of uploaded parts).
- `<bucket_root>/.s32p-mpu/uploads/<upload_id>/lock`  
  A file used with `flock(LOCK_EX)` to serialize metadata updates and completion.
- `<bucket_root>/.s32p-mpu/uploads/<upload_id>/direct.bin`  
  The **assembly file** (random-access writes at part offsets).
- `<bucket_root>/.s32p-mpu/uploads/<upload_id>/parts/part-00001.bin` (etc.)  
  Fallback storage for parts that cannot safely be placed into `direct.bin`.

The gateway also prevents clients from reading/writing/deleting objects *inside* the reserved multipart directory by treating that first path segment as “reserved”.

#### Part upload placement

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

#### Completion: assembling without a full server-side copy

On `CompleteMultipartUpload` (`POST ?uploadId=...`), the gateway:

1. Reads the XML body (requested part numbers).
2. Takes an **exclusive lock** for the entire completion to prevent concurrent `UploadPart` and to make the final rename deterministic.
3. Validates the request:
   - Parts must be **contiguous** starting at 1 (`1..=lastPart`).
   - Every requested part must exist in `meta.json`.

Then it chooses one of two assembly paths:

##### Fast path (rename `direct.bin` into place)

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

##### Fallback path (sequential staging file)

If the fixed-size/offset conditions don’t hold, the gateway assembles sequentially:

1. Create a staging output file:
   - If the upload directory is on a different filesystem than the destination, the staging file is created **next to the destination** (to avoid an extra copy later).
2. Copy parts in order into the staging file:
   - For `direct` parts: copy the required range out of `direct.bin`.
   - For `file` parts: copy the entire part file.
3. Rename staging file → final object path.

Finally, on success the gateway marks the upload as completed, returns the completion XML + ETag, and removes the upload directory.

#### Practical highlights

- The gateway’s “happy path” is optimized for **large objects**: parts are placed directly into their final offsets, and completion is typically a truncate + rename.
- The implementation is careful to avoid data corruption:
  - Direct placement is only used when offsets can be computed safely (no overlap risk).
  - Metadata updates are protected by `flock` and written atomically (`meta.json.tmp` → rename).

### Directory backends (users, buckets, ACLs)

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

- Shared S3 REST-XML helpers live in `crates/s32p-support/src/s3resp.rs` and `crates/s32p-support/src/s3xml.rs` (errors like `AccessDenied`, `SignatureDoesNotMatch`, `NotImplemented`, plus body builders); proxy-side glue (`respond_bytes()` and friends) is in `crates/s32p-proxy/src/responses.rs`.

### SigV4 validation behavior

- **DoS mitigation via “spawn gating”**
  - If a worker is **not running**, the proxy performs **SigV4 verification without reading the body**:
    - Standard SigV4 auth header (`Authorization`, `x-amz-content-sha256`)
    - SigV4 **presigned URLs** (query signature; typically `UNSIGNED-PAYLOAD`)
  - Only if the signature is valid will the proxy start the worker
  - Once a worker is already running, the proxy does **not** fully validate SigV4;
    it only extracts the access key for routing and forwards the request to the worker

- Workers (VersityGW or s32p-gateway) still validate SigV4 again (cannot be disabled).

### Worker lifecycle management (`src/worker_manager.rs`)

- Workers are keyed by **(access_key, worker_profile)**
  - supports multiple access keys mapped to the same unix user but different bucket ACLs
  - allows routing different command classes to different worker profiles per access key
- Workers are started via a configurable launcher (default: `restricted-exec`)
  - If running as root and `pass_user_flag_if_root=true`, the proxy passes `--user <username>`
  - When `workers.launcher.landlock` is enabled (default `true`), the proxy also passes `--rw <posix_root>`, `--rw <bucket.data_path>` for each accessible bucket, `--resolve-libs`, and `--allow-nss` so the launcher confines the worker to those paths.
- Upstream bind (per worker):
  - TCP loopback: `127.0.0.1:<port>`
  - Unix domain socket: `<uds_run_dir>/<uid>-<instance_id>/<profile>.sock`
    - `<uds_run_dir>` defaults to `/run/s32p` (root) or `$XDG_RUNTIME_DIR/s32p` (non-root); override per profile via `workers.profiles.<name>.upstream.uds_run_dir`.
    - `<instance_id>` is a per-proxy-process random suffix so multiple proxy instances on one host don't collide.
    - One socket file per worker profile under the per-uid run dir.
- Readiness probing: connect loop until port is reachable
- Idle shutdown after `idle_timeout_secs`
- Sweeper removes dead/idle workers periodically (`sweep_interval_secs`)
- **Staged posix_root**
  - On each worker start, the proxy creates a **fresh temp directory** under `workers.posix_root`
  - Creates symlinks for all buckets visible to the access key:
    - `<temp>/<bucket_name>` → `<bucket.data_path>`
  - Passes that temp directory as `{{posix_root}}` to the worker
  - When the worker stops, the temp directory is removed

Worker `args` / `env` templates are expanded per spawn by `worker_manager.rs::render_template`. Unknown tokens cause a hard error. Available tokens:

| Token | Value |
|---|---|
| `{{username}}` | Unix username of the target user |
| `{{uid}}` | numeric UID |
| `{{gid}}` | numeric GID |
| `{{access_key}}` | the SigV4 access key for this worker |
| `{{secret_key}}` | matching secret key |
| `{{posix_root}}` | the staged temp dir with bucket symlinks |
| `{{bind_addr}}` | endpoint string (`host:port` for TCP, path for UDS) |
| `{{bind_uds}}` | alias of `{{bind_addr}}` (use whichever reads better in your config) |
| `{{region}}` | from `server.region` |
| `{{virtual_hosted_suffixes}}` | comma-joined `server.virtual_hosted_suffixes` |
| `{{log_level}}` | from `server.log_level` |

Separately, `{{install_bin_dir}}` is a *config-load-time* placeholder resolved only inside `workers.launcher.path` and `workers.profiles.*.exec` (not in `args`/`env`). It expands to the directory containing the running `s32p-proxy` executable (e.g. `target/debug` in dev, `/usr/local/bin` after install).

---

## Configuration

Primary configuration: `etc/s32p-proxy.yaml`

Key sections:

- `server.listen` / `server.public_scheme` (both required)
- `server.region` (required; used as the SigV4 region and exposed to workers via `{{region}}`)
- `server.log_level` (logging configuration, supports RUST_LOG format)
- `server.virtual_hosted_suffixes` (virtual-hosted-style bucket detection)
- `server.tls_cert_path` / `server.tls_key_path` (optional; enables HTTPS on the listen address)
- `server.shutdown_grace_period_secs` (graceful-shutdown timeout, default 10s)
- `auth.*` (directory backend selection and credentials)
- `workers.posix_root` (base dir for per-worker temp roots)
- `workers.launcher.*` (includes `path`, `pass_user_flag_if_root`, `landlock`)
- `workers.lifecycle.*` (`idle_timeout_secs`, `sweep_interval_secs`)
- `workers.profiles.*` (worker templates: `exec`, `args`, `env`, `upstream`)
- `routing.class_map.*` (routes classifier classes to actions)

### Virtual-hosted-style bucket support

The proxy automatically detects and supports both **path-style** and **virtual-hosted-style** bucket addressing:

- **Path-style**: `https://s3.example.com/bucket/key` (bucket in path)
- **Virtual-hosted-style**: `https://bucket.s3.example.com/key` (bucket in host)

Configure domain suffixes for virtual-hosted-style detection via `server.virtual_hosted_suffixes`:

```yaml
server:
  virtual_hosted_suffixes:
    - "127.0.0.1.nip.io"
    - "s3.example.com"
    - "s3.localhost"
```

When a request's `Host` header ends with a configured suffix, the proxy extracts the bucket name from the host and the key from the path. Port numbers are handled correctly (e.g., `bucket.suffix:9000`).

Workers receive the suffixes via the `S32P_VIRTUAL_HOSTED_SUFFIXES` environment variable or `{{virtual_hosted_suffixes}}` template:

```yaml
workers:
  profiles:
    s32p-gateway:
      env:
        S32P_VIRTUAL_HOSTED_SUFFIXES: "{{virtual_hosted_suffixes}}"
```

### Directory backend selection

Choose a directory backend via `auth.backend`:

- `yaml` — load a local directory file
- `openbao` — use OpenBao (Vault-compatible API) with AppRole + KV v2 + indices

#### YAML backend config

```yaml
auth:
  backend: "yaml"
  yaml:
    path: "/etc/s32p/directory.yaml"
```

#### OpenBao backend config (AppRole)

```yaml
auth:
  backend: "openbao"
  openbao:
    address: "http://127.0.0.1:8200"
    approle_mount: "approle"
    role_id_file: "/etc/s32p/role_id"
    secret_id_file: "/etc/s32p/secret_id"
    kv_mount: "secret"
    prefix: "s32p"
```

### YAML directory file format

Example `/etc/s32p/directory.yaml`:

```yaml
version: 1

users:
  - access_key: "alice_key_1"
    secret_key: "alice_secret"
    username: "alice"
    uid: 1001
    gid: 1001

  # Second access key mapping to the same unix user:
  - access_key: "alice_key_2"
    secret_key: "alice_secret_2"
    username: "alice"
    uid: 1001
    gid: 1001

buckets:
  - id: "bkt-alice-photos"
    name: "photos"
    data_path: "/srv/s3/alice/photos"
    acl:
      - principal: { type: "access_key", access_key: "alice_key_1" }
        access: "read_write"
      - principal: { type: "access_key", access_key: "alice_key_2" }
        access: "read_write"

  - id: "bkt-team"
    name: "team"
    data_path: "/srv/s3/team"
    acl:
      - principal: { type: "group_name", name: "s3-team" }
        access: "read_write"
      - principal: { type: "access_key", access_key: "alice_key_1" }
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

## Administration CLI (`s32p-ctl`)

`s32p-ctl` manages the Directory state (users, buckets, ACLs) for both supported backends:
- `--backend openbao` (default): OpenBao/Vault KV v2 + indices
- `--backend yaml`: local directory.yaml file

All commands work with both backends. The backend is selected via `--backend`.

### Backend selection

#### YAML backend
For YAML, you must provide the directory file path:

```bash
s32p-ctl --backend yaml --yaml-path /etc/s32p/directory.yaml <COMMAND...>
```

#### OpenBao backend
For OpenBao, provide `--address` (or `VAULT_ADDR`) plus authentication:
- Setup typically uses a root/admin token (`--token` or `VAULT_TOKEN`)
- Normal operations typically use AppRole (`--role-id(-file)` + `--secret-id(-file)`)

Common OpenBao flags:
- `--address http://127.0.0.1:8200` (or `VAULT_ADDR`)
- `--kv-mount secret` (default: `secret`)
- `--prefix s32p` (default: `s32p`)
- `--approle-mount approle` (default: `approle`)
- `--token ...` (or `VAULT_TOKEN`)
- `--role-id ...` / `--role-id-file ...`
- `--secret-id ...` / `--secret-id-file ...`

Example:

```bash
s32p-ctl --backend openbao \
  --address http://127.0.0.1:8200 \
  --kv-mount secret \
  --prefix s32p \
  --approle-mount approle \
  --role-id-file /etc/s32p/admin_role_id \
  --secret-id-file /etc/s32p/admin_secret_id \
  <COMMAND...>
```

### Setup

#### OpenBao setup
Setup is idempotent and verifying — re-runs are safe and abort hard rather than overwrite incompatible state. It creates/updates:
- mounts KV v2 at `--kv-mount` (default: `secret`) if missing; if a mount already exists at that path, it is verified to be `type=kv` with `options.version=2` and reused — any other engine type or KV v1 aborts setup
- enables AppRole auth method at `--approle-mount` (default: `approle`)
- creates policies + roles, scoped to `<kv-mount>/data/<prefix>/*` and `<kv-mount>/metadata/<prefix>/*`:
  - `s32p-proxy` (read-only)
  - `s32p-admin` (read-write)
- reads the role IDs and generates a fresh secret ID per role; if the corresponding `--*-id-file` flags are given, the four IDs are written there with mode 0600 (Unix)

The bootstrap token (`--token` or `VAULT_TOKEN`) must be allowed to write `sys/mounts/<kv-mount>`, `sys/auth/<approle-mount>`, `sys/policies/acl/*` and `auth/<approle-mount>/role/*`. A root token covers all of these; restricted bootstrap tokens need the corresponding capabilities.

To keep the token out of your shell history and out of `ps`/`/proc/<pid>/cmdline`, prompt for it without echo:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
read -rs VAULT_TOKEN && export VAULT_TOKEN   # paste token, hit enter; no echo

s32p-ctl --backend openbao setup \
  --proxy-role-id-file   /etc/s32p/proxy_role_id \
  --proxy-secret-id-file /etc/s32p/proxy_secret_id \
  --admin-role-id-file   /etc/s32p/admin_role_id \
  --admin-secret-id-file /etc/s32p/admin_secret_id

unset VAULT_TOKEN   # token is no longer needed
```

After setup the bootstrap token is **not needed for normal operation**:
- the proxy authenticates via the `s32p-proxy` AppRole (`role_id_file` + `secret_id_file` in `etc/s32p-proxy.yaml` under `auth.openbao`)
- further `s32p-ctl` commands (`user add`, `bucket add`, `import-yaml`, …) authenticate via the `s32p-admin` AppRole (`--role-id-file` + `--secret-id-file`)

Re-running `setup` generates an *additional* `secret_id` for each role; existing secret IDs stay valid until destroyed via `auth/<approle-mount>/role/<role>/secret-id/destroy`. Rotate explicitly if you need the old ones revoked.

#### YAML setup
Creates an empty directory file skeleton:

```bash
s32p-ctl --backend yaml --yaml-path /etc/s32p/directory.yaml setup
```

### Users

Commands:
- `user add`
- `user rm`
- `user ls`

Add a user:

```bash
s32p-ctl ... user add \
  --access-key alice_key_1 \
  --secret-key alice_secret \
  --username alice \
  --uid 1001 \
  --gid 1001
```

Remove a user (optionally scrubs their `access_key` from bucket ACLs):

```bash
s32p-ctl ... user rm --access-key alice_key_1 --cleanup-acls true
```

List users:

```bash
s32p-ctl ... user ls
```

### Buckets

Commands:
- `bucket add`
- `bucket rm`
- `bucket ls`
- `bucket acl-set`

Add a bucket:

```bash
s32p-ctl ... bucket add \
  --name photos \
  --data-path /srv/s3/alice/photos \
  --grant ak:alice_key_1:read_write
```

`--grant` is repeatable and supports:
- `ak:<ACCESS_KEY>:read_only|read_write`
- `group:<GROUP_NAME>:read_only|read_write`

Optional: provide a stable bucket id (otherwise a UUID is generated):

```bash
s32p-ctl ... bucket add \
  --bucket-id bkt-alice-photos \
  --name photos \
  --data-path /srv/s3/alice/photos \
  --grant ak:alice_key_1:read_write
```

Remove a bucket:

```bash
s32p-ctl ... bucket rm --bucket-id bkt-alice-photos
```

List buckets:

```bash
s32p-ctl ... bucket ls
```

Replace a bucket ACL:

```bash
s32p-ctl ... bucket acl-set \
  --bucket-id bkt-team \
  --grant group:s3-team:read_write \
  --grant ak:alice_key_1:read_only
```

### Import / Export

Import a directory YAML into the selected backend:

```bash
s32p-ctl ... import-yaml --yaml /path/to/directory.yaml --replace true
```

- openbao: `--replace` purges the directory subtrees under the configured prefix before import.
- yaml: `--replace` overwrites the destination file; `--replace false` merges by `users.access_key` and `buckets.id`.

Export backend state to a directory YAML:

```bash
s32p-ctl ... export-yaml --yaml /path/to/directory.yaml
```

#### Importing VersityGW IAM JSON

Import users from a VersityGW IAM JSON file (the `accessAccounts` map). Works
against both backends, always merges into the existing directory (existing
users with the same access key are overwritten; buckets/ACLs are not touched
since VG IAM has no bucket concept).

```bash
s32p-ctl ... import-versity-iam --json /path/to/iam.json
```

Mapping: VG `access` → `access_key`, `secret` → `secret_key`, `userID` → `uid`,
`groupID` → `gid`. The `username` field is resolved at runtime on the host
running `s32p-ctl` via `getpwuid_r(userID)`. The VG `role` field and any other
unknown fields (e.g. `projectID`) are ignored.

Filtering (mutually exclusive, both repeatable, matched against the access key):

- `--include <ACCESS_KEY>` — import only the listed users.
- `--exclude <ACCESS_KEY>` — import everything except the listed users.

What to do when `getpwuid_r(userID)` returns no entry on the local host:

- `--on-missing-user error` (default) — hard error, stop the import.
- `--on-missing-user use-access-key` — use the VG access key string as the username.
- `--on-missing-user skip` — log a warning and skip that entry.

Examples:

```bash
# OpenBao backend, only two users, fall back to access key for unknown uids
s32p-ctl --backend openbao ... \
  import-versity-iam \
    --json iam.json \
    --include alice --include bob \
    --on-missing-user use-access-key

# YAML backend, exclude a service account
s32p-ctl --backend yaml --yaml-path /etc/s32p/directory.yaml \
  import-versity-iam --json iam.json --exclude svc-test
```

## Building

```bash
# Clone the repository with submodules
git clone --recurse-submodules https://github.com/r5r3/s32p-proxy.git
cd s32p-proxy

# If you already cloned without submodules, initialize them:
git submodule update --init --recursive

# Build the workspace
cargo build
```

---

## Running (development)

Due to the usage of [`io_uring`](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io), 
you need RHEL 9.3, or another Linux distribution with a compatible kernel. 
On RHEL, it is necessary to enable the `io_uring` kernel module:

```bash
sysctl -w kernel.io_uring_disabled=0
```

You can set the log level either via environment variable or in the config file:

**Using environment variable (traditional):**
```bash
RUST_LOG=s32p_proxy=debug,pingora=info,pingora_proxy=info cargo run --bin s32p-proxy
```

**Using config file (recommended):**
The log level can be configured in `etc/s32p-proxy.yaml`:
```yaml
server:
  log_level: "s32p_proxy=debug,s32p_gateway=debug,pingora=info,pingora_proxy=info"
```

The config file approach automatically forwards the log level to worker processes.

The proxy binds to the address configured under `server.listen` in `etc/s32p-proxy.yaml` (a required field — there is no compiled-in default). The shipped dev config listens on:

```
http://0.0.0.0:9000
```

Workers are launched on-demand and bind to loopback (`127.0.0.1:<port>`) or to a Unix socket under a per-uid (and per-proxy-instance) run dir, one socket per worker profile.

---

## Testing with MinIO Client (`mcli`)

```bash
mcli alias set S32P http://localhost:9000 TESTACCESSKEY123 TESTSECRETKEY456
mcli ls --debug S32P
```

Notes:

- For the first request when no worker exists, the proxy validates SigV4 (auth header or presigned URL) before spawning.
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

Apache 2.0

---

## Acknowledgements

- Cloudflare Pingora
- AWS SDK for Rust and S3 documentation
- MinIO client for testing
- VersityGW
