//! Integration test helpers for noisy-shuttle
//!
//! This module provides test infrastructure for integration testing:
//! - `EchoTarget`: TCP echo server (fully functional)
//! - `Socks5Client`: SOCKS5 CONNECT client (fully functional)  
//! - `HttpClient`: HTTP CONNECT client (fully functional)
//! - `TestShuttleServer`, `TestShuttleClient`: Stubs - see note below
//!
//! # Architecture Note
//! The `noisy-shuttle` crate is a binary crate (has `main.rs` but no `lib.rs`).
//! Integration tests in `tests/` cannot access internal modules via `noisy_shuttle::*`
//! because that requires the crate to be a library.
//!
//! `TestShuttleServer` and `TestShuttleClient` are stub implementations that
//! demonstrate the intended API but cannot function without library access.
//! For full integration tests, convert shuttle to a library with `src/lib.rs`.

use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

pub const TEST_KEY: &str = "test-key-1234567890abcdef";
const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// A simple TCP echo server that reads bytes from a connection and writes them back.
/// Fully functional - can be used in any integration test.
pub struct EchoTarget {
    listener: Arc<TcpListener>,
    task: JoinHandle<Result<()>>,
}

impl EchoTarget {
    /// Start a new echo server on an ephemeral loopback port.
    /// Returns `(Self, addr)` where `addr` is the bound socket address.
    pub async fn new() -> Result<(Self, SocketAddr)> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind echo server to loopback")?;
        let addr = listener
            .local_addr()
            .context("failed to get echo server addr")?;

        let listener = Arc::new(listener);
        let listener_clone = listener.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match timeout(READY_TIMEOUT, listener_clone.accept()).await {
                    Ok(Ok(x)) => x,
                    Ok(Err(e)) => {
                        tracing::debug!("echo server accept error: {}", e);
                        continue;
                    }
                    Err(_) => {
                        tracing::debug!("echo server accept timed out");
                        break;
                    }
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        let n = match timeout(READY_TIMEOUT, socket.read(&mut buf)).await {
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => {
                                tracing::debug!("echo server read error: {}", e);
                                break;
                            }
                            Err(_) => {
                                tracing::debug!("echo server read timed out");
                                break;
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        if let Err(e) = socket.write_all(&buf[..n]).await {
                            tracing::debug!("echo server write error: {}", e);
                            break;
                        }
                    }
                });
            }
            Ok(())
        });

        Ok((Self { listener, task }, addr))
    }

    /// Get the address this echo server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }
}

impl Drop for EchoTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Launcher for a noisy-shuttle server instance on a loopback address.
/// STUB: This implementation cannot function because shuttle is a binary crate
/// without library access. The full implementation would use `noisy_shuttle::opt::SvrOpt`
/// and `noisy_shuttle::server::run_server`, but these are internal modules
/// not accessible from integration tests.
pub struct TestShuttleServer {
    _task: JoinHandle<()>,
}

impl TestShuttleServer {
    /// Start a new shuttle server on an ephemeral loopback port.
    /// STUB: Returns an error indicating library access is required.
    pub async fn new() -> Result<(Self, SocketAddr)> {
        anyhow::bail!(
            "TestShuttleServer requires library access - shuttle is a binary crate without lib.rs"
        );
    }
}

impl Drop for TestShuttleServer {
    fn drop(&mut self) {
        self._task.abort();
    }
}

/// Launcher for a noisy-shuttle client instance on a loopback address.
/// STUB: This implementation cannot function because shuttle is a binary crate
/// without library access. The full implementation would use `noisy_shuttle::opt::CltOpt`
/// and `noisy_shuttle::client::run_client`, but these are internal modules
/// not accessible from integration tests.
pub struct TestShuttleClient {
    _task: JoinHandle<()>,
}

impl TestShuttleClient {
    /// Start a new shuttle client on an ephemeral loopback port.
    /// STUB: Returns an error indicating library access is required.
    pub async fn new(_remote_addr: SocketAddr) -> Result<(Self, SocketAddr)> {
        anyhow::bail!(
            "TestShuttleClient requires library access - shuttle is a binary crate without lib.rs"
        );
    }
}

impl Drop for TestShuttleClient {
    fn drop(&mut self) {
        self._task.abort();
    }
}

/// A client for making SOCKS5 CONNECT requests through a shuttle client proxy.
/// Fully functional - works with any SOCKS5 proxy.
pub struct Socks5Client {
    proxy_addr: SocketAddr,
}

impl Socks5Client {
    /// Create a new SOCKS5 client that connects through the given proxy address.
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self { proxy_addr }
    }

    /// Send data through the SOCKS5 proxy to the given target address and get an echo response.
    /// Performs SOCKS5 CONNECT handshake then sends data, expecting echo.
    pub async fn echo(&self, target_addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect(self.proxy_addr)
            .await
            .context("failed to connect to SOCKS5 proxy")?;

        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .context("failed to write SOCKS5 greeting")?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            anyhow::bail!("SOCKS5 auth failed: {:?}", resp);
        }

        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        match target_addr.ip() {
            IpAddr::V4(ipv4) => request.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => request.extend_from_slice(&ipv6.octets()),
        }
        request.extend_from_slice(&target_addr.port().to_be_bytes());

        stream
            .write_all(&request)
            .await
            .context("failed to write SOCKS5 CONNECT request")?;

        let mut response = [0u8; 10];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 || response[1] != 0x00 {
            anyhow::bail!("SOCKS5 CONNECT failed: {:?}", response);
        }

        stream
            .write_all(data)
            .await
            .context("failed to write data through SOCKS5")?;

        let mut buf = vec![0u8; data.len()];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }
}

/// A client for making HTTP CONNECT requests through a shuttle client proxy.
/// Fully functional - works with any HTTP CONNECT proxy.
pub struct HttpClient {
    proxy_addr: SocketAddr,
}

impl HttpClient {
    /// Create a new HTTP client that connects through the given proxy address.
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self { proxy_addr }
    }

    /// Send data through the HTTP CONNECT proxy to the given target address and get an echo response.
    /// Performs HTTP CONNECT tunnel establishment then sends data, expecting echo.
    pub async fn echo(&self, target_addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect(self.proxy_addr)
            .await
            .context("failed to connect to HTTP proxy")?;

        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            target_addr.ip(),
            target_addr.port(),
            target_addr.ip(),
            target_addr.port()
        );
        stream
            .write_all(connect_req.as_bytes())
            .await
            .context("failed to write HTTP CONNECT request")?;

        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await?;
        let resp = std::str::from_utf8(&buf[..n]).context("invalid HTTP response from proxy")?;
        if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
            anyhow::bail!("HTTP CONNECT failed: {}", resp.trim());
        }

        stream
            .write_all(data)
            .await
            .context("failed to write data through HTTP CONNECT")?;

        let mut buf = vec![0u8; data.len()];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_target_works() {
        let (target, addr) = EchoTarget::new().await.unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        drop(target);
    }
}
