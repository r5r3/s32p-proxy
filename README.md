# s3-proxy-manager

`s3-proxy-manager` is a **Rust-based S3-compatible proxy + worker manager** built on **Cloudflare Pingora**. It accepts S3 client requests, maps S3 identities to **Unix users**, and routes traffic to **per-user VersityGW workers** that expose a **shared POSIX filesystem** with kernel-enforced permissions.

A central design goal is to preserve Unix security semantics: **all filesystem access happens inside a process already running as the target Unix user**.

---

## Goals

* Provide an **S3-compatible endpoint** backed by a POSIX filesystem
* Enforce **per-user isolation using Unix UIDs/GIDs** (kernel-level security)
* Support **standard S3 clients** (AWS CLI, MinIO client, SDKs)
* Start **one VersityGW per user on demand**, then reuse it
* Prevent easy **DoS via worker spawn storms**
* Keep the proxy (auth/routing/management) separate from storage I/O

---

## Architecture

```
        ┌──────────────┐
        │  S3 Clients  │  (aws cli, mc, SDKs)
        └──────┬───────┘
               │  HTTP(S)
               ▼
┌──────────────────────────────────────┐
│           s3-proxy-manager           │
│       (Pingora-based Rust proxy)     │
│                                      │
│  • access_key → unix user mapping    │
│  • spawn & supervise per-user worker │
│  • gate worker spawn with SigV4      │
│    header-only validation            │
│  • reverse proxy to worker           │
│  • optional response header rewriting│
└──────────────┬───────────────────────┘
               │ internal HTTP (loopback)
               ▼
   ┌──────────────────────────────┐
   │    Per-user VersityGW        │
   │  (unmodified, validates SigV4│
   │   again, runs as unix user)  │
   │   uid=1001, uid=1002, …      │
   └──────────────┬───────────────┘
                  │ POSIX syscalls
                  ▼
        ┌────────────────────────┐
        │     Shared POSIX FS    │
        │       (/tmp/s3 …)      │
        └────────────────────────┘
```

### Key idea

> **All filesystem access is performed by the per-user worker process running as the corresponding Unix user.**

`s3-proxy-manager` does not perform filesystem I/O.

---

## Current Status (December 2025)

### Implemented

* **User mapping**: `access_key → {username, uid, gid, secret_key}` (currently demo in-memory DB)
* **Worker lifecycle management**

  * On-demand worker start (singleflight per uid)
  * Starts workers via: `restricted-exec --user USERNAME -- versitygw ...`

    * The `--user` flag is only passed when the proxy runs as **root**
  * Loopback binding for workers (`127.0.0.1:<port>`)
  * Worker readiness probing (connect loop)
  * Idle shutdown after **10 minutes**
  * Background sweeper that removes dead workers from the registry
* **SigV4 spawn gating**

  * If a worker is **not running**, the proxy performs **header-only SigV4 verification** using the client-supplied `x-amz-content-sha256` (no request-body buffering) before spawning
  * If a worker **is running**, the proxy only extracts the access key for routing; the worker (VersityGW) remains the authoritative validator
* **Logging & debugging** for request flow, worker lifecycle, and failures

### In progress

* **Streaming reverse proxying** to workers (Pingora proxy mode), preserving SigV4-critical headers (especially `Host`) and streaming request/response bodies
* **Response customization hooks** (e.g., add/remove/replace headers; later potentially rewrite some XML bodies)

### Planned

* Persistent configuration (file/DB) for users and per-user worker settings
* Better limits/rate controls (max workers, max concurrent starts, negative caching of failures)
* TLS termination options and forwarding policy
* Production hardening (timeouts, observability, metrics)

---

## Why Pingora?

Pingora provides:

* High-performance async HTTP proxying
* Backpressure-aware streaming (important for large S3 objects)
* A clean Rust-native service model
* Fine-grained control over request routing and response filtering

---

## Why per-user workers?

S3 has no native concept of Unix users, but POSIX does. Instead of emulating permissions in userspace, this project relies on the kernel:

* Each worker process runs as a **single Unix UID/GID**
* The kernel enforces permissions automatically
* Bugs in one worker are contained to that user’s OS permissions

This avoids risky per-request UID switching inside a shared process.

---

## Filesystem Layout

A typical shared POSIX root looks like:

```
/tmp/s3/
  alice/
  bob/
```

Example permissions:

```bash
chown alice:alice /tmp/s3/alice
chmod 700 /tmp/s3/alice
```

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

Default listener:

```
http://localhost:9000
```

Workers are launched on-demand and bind to loopback (`127.0.0.1:<port>`).

---

## Testing with MinIO Client

```bash
mcli alias set S3PM http://localhost:9000 TESTACCESSKEY123 TESTSECRETKEY456
mcli ls --debug S3PM
```

Notes:

* The proxy **may** validate SigV4 (header-only) on the first request to gate worker startup.
* VersityGW will validate SigV4 again.

---

## Security Notes

* Run the proxy as **root** if you want `restricted-exec --user` to switch to the target Unix user.
* If the proxy is not root, workers will start as the proxy’s user (development convenience).
* Workers should never run as root in production.
* Keep worker listeners loopback-only (or move to Unix domain sockets later).

---

## Non-Goals

* Reimplement an object store
* Userspace permission checks
* Multi-tenant access within a single worker process

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

`s3-proxy-manager` is the **control plane** (auth/routing/worker lifecycle) for per-user S3 access to a shared filesystem. VersityGW remains the storage-facing component and continues to perform the authoritative SigV4 validation.

