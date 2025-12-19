# s3-proxy-manager

`s3-proxy-manager` is a **Rust-based S3-compatible proxy and manager** built on top of **Cloudflare Pingora**. It authenticates incoming S3 requests using **AWS Signature Version 4 (SigV4)**, maps S3 identities to **Unix users**, and routes requests to **per-user S3 gateway workers** (e.g. VersityGW) that access a **shared POSIX filesystem** with kernel-enforced permissions.

The project is designed to safely expose a POSIX filesystem via the S3 API while preserving Unix security semantics.

---

## Goals

* Provide an **S3-compatible endpoint** backed by a POSIX filesystem
* Enforce **per-user isolation using Unix UIDs/GIDs** (kernel-level security)
* Support **standard S3 clients** (AWS CLI, MinIO client, SDKs)
* Start **one S3 gateway worker per user on demand**
* Keep the proxy logic and filesystem access **cleanly separated**

---

## Architecture

```
        ┌──────────────┐
        │  S3 Clients  │  (aws cli, mc, SDKs)
        └──────┬───────┘
               │  HTTPS / HTTP
               ▼
┌─────────────────────────────────┐
│        s3-proxy-manager         │
│  (Pingora-based Rust service)   │
│                                 │
│  • SigV4 validation             │
│  • S3 request routing           │
│  • access_key → uid mapping     │
│  • worker lifecycle management  │
└──────────────┬──────────────────┘
               │ internal HTTP
               ▼
   ┌──────────────────────────┐
   │  Per-user S3 workers     │   (e.g. VersityGW)
   │  running as Unix users   │
   │  uid=1001, uid=1002, …   │
   └──────────────┬───────────┘
                  │ POSIX syscalls
                  ▼
        ┌──────────────────────┐
        │  Shared POSIX FS     │
        │  (/srv/s3root/…)     │
        └──────────────────────┘
```

### Key idea

> **All filesystem access is performed by processes already running as the target Unix user.**

The proxy never performs filesystem I/O itself and never switches UID per request.

---

## Current Status

**Implemented:**

* Pingora-based HTTP server
* Full AWS SigV4 request validation
* Compatible with MinIO client (`mc`) and AWS-style tooling
* Correct handling of:

  * `GET /` (ListBuckets)
  * Request framing (`Content-Length`)
* Clean request logging and debugging support

**In progress / planned:**

* On-demand spawning of per-user S3 gateway workers
* Reverse proxying requests to workers
* Full S3 API coverage (ListObjectsV2, PUT/GET objects, etc.)
* Persistent user/account configuration
* Production hardening (timeouts, limits, TLS)

---

## Why Pingora?

Pingora provides:

* High-performance async HTTP handling
* Backpressure-aware streaming
* A clean Rust-native service model
* Fine-grained control over request parsing and routing

This makes it a good fit for implementing an S3-compatible control plane.

---

## Why per-user workers?

S3 has no native concept of Unix users, but POSIX does.

Instead of emulating permissions in userspace, this project relies on the kernel:

* Each worker process runs as a **single Unix UID/GID**
* The kernel enforces file permissions automatically
* Bugs in one worker cannot affect another user’s data

This avoids the complexity and risk of per-request `setuid()` or `setfsuid()` switching.

---

## Filesystem Layout

A typical shared POSIX root looks like:

```
/srv/s3root/
  alice/
  bob/
  service-x/
```

With permissions such as:

```bash
chown alice:alice /srv/s3root/alice
chmod 700 /srv/s3root/alice
```

Each user’s S3 buckets live inside their own subtree.

---

## Building

```bash
cargo build
```

---

## Running (development)

```bash
cargo run
```

By default, the proxy listens on:

```
http://localhost:9000
```

---

## Testing with MinIO Client

```bash
mc alias set S3PM http://localhost:9000 TESTACCESSKEY123 TESTSECRETKEY456
mc ls S3PM
```

You should see the dummy bucket response immediately.

---

## Configuration (planned)

Future versions will support:

* Declarative mapping of `access_key → uid/gid`
* Configurable worker commands (e.g. VersityGW)
* Idle timeouts for worker shutdown
* TLS termination and forwarding headers

---

## Security Notes

* The proxy should start with enough privilege to spawn workers as different users
* After startup, it should drop privileges where possible
* Workers should **never** run as root
* POSIX permissions are the primary security boundary

---

## Non-Goals

* Reimplementing a full object store
* Userspace permission checks
* Multi-tenant access within a single worker process

---

## License

TBD (choose MIT / Apache-2.0 / etc.)

---

## Acknowledgements

* Cloudflare Pingora
* AWS SigV4 specification
* MinIO client and ecosystem
* VersityGW

---

## Project Direction

`s3-proxy-manager` is intended as a **control plane** and **security boundary**, not a storage backend.

If you want a POSIX filesystem exposed safely over S3 — while respecting Unix users — this project aims to provide the missing glue.

