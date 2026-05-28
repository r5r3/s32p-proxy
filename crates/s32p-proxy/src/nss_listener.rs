//! Proxy-side NSS lookup listener.
//!
//! Binds a Linux abstract-namespace UDS at `@s32p-nss-<pid>` and answers a
//! tiny request/response protocol ([`s32p_support::nss_proto`]) that lets
//! workers resolve uid → username without needing `/etc/passwd` in their
//! Landlock allow list. The abstract socket has no filesystem presence —
//! the kernel frees the name automatically when the listening fd is closed
//! and there is no chown/chmod/cleanup boilerplate.
//!
//! There is exactly one listener per proxy process; every worker connects
//! to it by name. The name is namespaced by the proxy's pid so multiple
//! proxy instances on the same host do not collide.
//!
//! `getpwuid_r` is dispatched via `tokio::task::spawn_blocking` because
//! SSSD-backed NSS can stall — keeping it off the listener's reactor
//! thread is essential.

use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};

use anyhow::{Context, Result};
use s32p_support::{nss_lookup, nss_proto};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    task::JoinHandle,
};

/// Synchronous startup half: reserves the abstract socket name with the
/// kernel and returns the `std::os::unix::net::UnixListener` plus the
/// `@`-prefixed env value workers will receive. Safe to call before the
/// tokio runtime exists (Pingora's `Server::bootstrap()` runs before its
/// runtime is up). The accept loop is started later by [`start_accept_loop`]
/// from inside the runtime.
pub fn bind() -> Result<(std::os::unix::net::UnixListener, String)> {
    let abstract_name = format!("s32p-nss-{}", std::process::id());
    let env_value = format!("{}{}", nss_proto::ABSTRACT_PREFIX, abstract_name);

    let addr = SocketAddr::from_abstract_name(abstract_name.as_bytes())
        .context("build abstract SocketAddr for nss listener")?;
    let std_listener = std::os::unix::net::UnixListener::bind_addr(&addr)
        .with_context(|| format!("bind abstract nss socket {env_value:?}"))?;
    std_listener
        .set_nonblocking(true)
        .context("set abstract nss listener non-blocking")?;
    tracing::info!(socket = %env_value, "nss-proxy listener bound (accept loop pending)");
    Ok((std_listener, env_value))
}

/// Handle to the running listener task. Dropping aborts the accept loop;
/// no filesystem cleanup is needed for an abstract socket.
pub struct NssListenerHandle {
    accept_task: JoinHandle<()>,
}

impl Drop for NssListenerHandle {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// Tokio-runtime half: wrap the pre-bound listener and spawn the accept
/// loop. Must be called from inside a tokio runtime (same constraint as
/// the replay-cache sweeper).
pub fn start_accept_loop(
    std_listener: std::os::unix::net::UnixListener,
) -> Result<NssListenerHandle> {
    let listener =
        UnixListener::from_std(std_listener).context("wrap std UnixListener into tokio")?;
    let accept_task = tokio::spawn(accept_loop(listener));
    Ok(NssListenerHandle { accept_task })
}

async fn accept_loop(listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                tokio::spawn(serve_connection(stream));
            }
            Err(e) => {
                tracing::warn!(error = %e, "nss-proxy accept error; continuing");
                // Backoff briefly so a persistent error doesn't spin.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve_connection(mut stream: tokio::net::UnixStream) {
    let mut req_buf = [0u8; nss_proto::REQUEST_LEN];
    loop {
        // EOF on the worker side ends the connection cleanly; any other read
        // error is logged at debug since it's almost always "worker exited".
        if let Err(e) = stream.read_exact(&mut req_buf).await {
            if e.kind() != std::io::ErrorKind::UnexpectedEof {
                tracing::debug!(error = %e, "nss-proxy connection read error");
            }
            return;
        }
        let uid = nss_proto::decode_request(req_buf);

        let name =
            match tokio::task::spawn_blocking(move || nss_lookup::lookup_username_blocking(uid))
                .await
            {
                Ok(opt) => opt,
                Err(e) => {
                    tracing::warn!(uid, error = %e, "nss-proxy blocking lookup join error");
                    None
                }
            };

        let bytes = match nss_proto::encode_response(name.as_deref()) {
            Ok(b) => b,
            Err(_) => {
                // Name overflowed 255 bytes — fall through as unknown.
                tracing::warn!(uid, "nss-proxy username exceeds wire limit; returning miss");
                vec![0]
            }
        };
        if let Err(e) = stream.write_all(&bytes).await {
            tracing::debug!(error = %e, "nss-proxy connection write error");
            return;
        }
    }
}
