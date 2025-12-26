# s3-proxy-manager

`s3-proxy-manager` is a **Rust-based S3-compatible proxy + worker manager** built on **Cloudflare Pingora**.

It accepts S3 client requests, maps S3 identities to **Unix users**, and routes traffic to **per-user worker processes** (currently: **VersityGW**) that expose a **shared POSIX filesystem** with kernel-enforced permissions.

A central design goal is to preserve Unix security semantics:

> **All filesystem access happens inside a process already running as the target Unix user.**

The proxy itself does not perform filesystem I/O.

---

## Goals

- Provide an **S3-compatible endpoint** backed by a POSIX filesystem
- Enforce **per-user isolation using Unix UIDs/GIDs** (kernel-level security)
- Support **standard S3 clients** (AWS CLI, MinIO client / SDKs)
- Start workers **on demand**, then reuse them (per user)
- Prevent easy **DoS via worker spawn storms**
- Keep proxy logic (auth/routing/management) separate from the storage worker

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
│        Per-user workers        │
│ (e.g. VersityGW, unmodified)   │
│                                │
│  • runs as unix user           │
│  • validates SigV4 again       │
└───────────────┬────────────────┘
                │ POSIX syscalls
                ▼
┌──────────────────────┐
│   Shared POSIX FS    │
│    (posix_root)      │
└──────────────────────┘

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

#### Local responses (no proxying)

- Shared response helpers in `src/responses.rs`
  - S3 REST-XML errors (e.g. `AccessDenied`, `SignatureDoesNotMatch`, `NotImplemented`)
  - A `ListBuckets` XML body builder and response helper
  - General `respond_bytes()` helper for header/body responses

> Note: currently, the proxy uses local responses mainly for errors and for returning `NotImplemented` for certain request classes.

#### SigV4 validation behavior

- **DoS mitigation via “spawn gating”**
  - If a worker is **not running**, the proxy performs **SigV4 header-only verification**
    using `aws-sigv4` and the client-provided `x-amz-content-sha256`
  - Only if the signature is valid will the proxy start the worker
  - Once a worker is already running, the proxy does **not** fully validate SigV4;
    it only extracts the access key for routing and forwards the request to the worker

- Workers (VersityGW) still validate SigV4 again (cannot be disabled).

#### Worker lifecycle management (`src/worker_manager.rs`)

- Workers are keyed by **(uid, worker_profile)**, not just uid:
  - allows routing different command classes to different worker profiles per user
- Workers are started via a configurable launcher (default: `restricted-exec`)
  - If running as root and `pass_user_flag_if_root=true`, the proxy passes `--user <username>`
- Loopback bind: `127.0.0.1:<port>`
- Readiness probing: connect loop until port is reachable
- Idle shutdown after `idle_timeout_secs`
- Sweeper removes dead/idle workers periodically (`sweep_interval_secs`)
- Worker args/env are rendered from templates:
  - `{{bind_addr}}`, `{{port}}`, `{{posix_root}}`, `{{access_key}}`, `{{secret_key}}`, etc.

---

## Configuration

Primary configuration: `etc/s3-proxy-manager.yaml`

Key sections:

- `server.listen` / `server.public_scheme`
- `workers.posix_root`
- `workers.launcher.*`
- `workers.lifecycle.*`
- `workers.profiles.*` (worker templates)
- `routing.class_map.*` (routes classifier classes to actions)

Example routing:

- multipart → not implemented
- versioning → not implemented
- other → proxy to `versitygw-default`

---

## Building

```bash
cargo build
```

---

## Running (development)

```bash
RUST_LOG=s3_proxy_manager=debug cargo run
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

* For the first request when no worker exists, the proxy may validate SigV4 (header-only) before spawning.
* VersityGW validates SigV4 again.

---

## Security Notes

* Run the proxy as **root** if you want the launcher to actually switch users (`restricted-exec --user`).
* If the proxy is not root, workers start as the proxy’s user (development convenience).
* Workers should never run as root in production.
* Keep worker listeners loopback-only (or move to Unix domain sockets later).

---

## Known limitations / TODO

* **Multipart uploads** are detected and currently return `NotImplemented`
  * Only after request validation (SigV4) to avoid turning invalid requests into “useful” responses
* **Versioning-related** requests are detected and currently return `NotImplemented`
* User database is currently a demo in-memory mapping (`UserDb::demo()`)
* More S3 API coverage still needed (ListObjectsV2, GET/PUT object streaming, etc.)
* More production hardening:
  * rate limiting / max concurrent starts
  * negative caching for repeated invalid requests
  * structured metrics

---

## License

TBD

---

## Acknowledgements

* Cloudflare Pingora
* AWS SigV4 specification
* MinIO client ecosystem
* VersityGW

---

## Project Direction

`s3-proxy-manager` is the **control plane**:
authentication/routing/worker lifecycle for per-user S3 access to a shared filesystem.

VersityGW remains the storage-facing component and performs the authoritative SigV4 validation.
