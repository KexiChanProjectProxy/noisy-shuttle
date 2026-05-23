//! Server-side reusable session loop handling sequential request multiplexing.

use anyhow::{anyhow, Context, Result};
use snowy_tunnel::SnowyStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep, timeout, Duration, Instant};
use tracing::{debug, info, warn};

use crate::opt::ReuseConfig;
use crate::session::frame::{read_frame, write_frame, Frame, FrameError, PROTOCOL_VERSION};
use crate::session::lifecycle::{CloseReason, SessionState};
use crate::trojan::{self, call_with_addr};

const END_REQUEST_OK: u8 = 0x00;
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Server-side loop for sequential reusable sessions.
pub struct SessionLoop {
    config: ReuseConfig,
    shutdown: watch::Receiver<bool>,
    _shutdown_guard: Option<watch::Sender<bool>>,
}

/// Mutable state for one reusable server session.
pub struct SessionContext<S = SnowyStream> {
    pub stream: S,
    pub state: SessionState,
    pub request_count: u64,
    pub created_at: Instant,
    pub last_activity: Instant,
}

#[allow(dead_code)]
pub fn looks_like_reuse_handshake(stream: &SnowyStream) -> bool {
    matches!(
        stream.buffered_plaintext().first(),
        Some(&crate::session::frame::FRAME_CLIENT_HELLO)
    )
}

impl SessionLoop {
    #[allow(dead_code)]
    pub fn new(config: ReuseConfig) -> Self {
        let (shutdown_tx, shutdown) = watch::channel(false);
        Self {
            config,
            shutdown,
            _shutdown_guard: Some(shutdown_tx),
        }
    }

    #[allow(dead_code)]
    pub fn with_shutdown(config: ReuseConfig, shutdown: watch::Receiver<bool>) -> Self {
        Self {
            config,
            shutdown,
            _shutdown_guard: None,
        }
    }

    /// Run the reusable session loop on a SnowyStream.
    #[allow(dead_code)]
    pub async fn run(&self, stream: SnowyStream) -> Result<()> {
        self.run_with_stream(stream).await
    }

    pub async fn run_with_first_frame(
        &self,
        stream: SnowyStream,
        first_frame: Frame,
    ) -> Result<()> {
        self.run_with_stream_and_first_frame(stream, Some(first_frame))
            .await
    }

    async fn run_with_stream<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.run_with_stream_and_first_frame(stream, None).await
    }

    async fn run_with_stream_and_first_frame<S>(
        &self,
        stream: S,
        first_frame: Option<Frame>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let now = Instant::now();
        let mut ctx = SessionContext {
            stream,
            state: SessionState::Handshaking,
            request_count: 0,
            created_at: now,
            last_activity: now,
        };

        info!(state = %ctx.state, "reusable session started");
        if let Some(frame) = first_frame {
            self.negotiate_frame(&mut ctx, Ok(frame)).await?;
        } else {
            self.negotiate(&mut ctx).await?;
        }
        self.serve_loop(&mut ctx).await
    }

    async fn negotiate<S>(&self, ctx: &mut SessionContext<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut shutdown = self.shutdown.clone();

        let frame = tokio::select! {
            frame = read_frame(&mut ctx.stream) => frame,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    self.close(ctx, CloseReason::ShutdownDrain).await?;
                    return Ok(());
                }
                read_frame(&mut ctx.stream).await
            }
        };

        self.negotiate_frame(ctx, frame).await
    }

    async fn negotiate_frame<S>(
        &self,
        ctx: &mut SessionContext<S>,
        frame: Result<Frame, FrameError>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match frame {
            Ok(Frame::ClientHello {
                version,
                capabilities,
            }) if version == PROTOCOL_VERSION => {
                ctx.state = SessionState::Idle;
                ctx.last_activity = Instant::now();
                info!(version, capabilities, state = %ctx.state, "reusable session negotiated");
                Ok(())
            }
            Ok(Frame::ClientHello { version, .. }) => {
                self.close(ctx, CloseReason::VersionMismatch).await?;
                warn!(version, expected = PROTOCOL_VERSION, reason = %CloseReason::VersionMismatch, "closing reusable session: version mismatch");
                Ok(())
            }
            Ok(frame) => {
                self.reset(ctx, CloseReason::ProtocolError).await?;
                warn!(?frame, reason = %CloseReason::ProtocolError, "protocol error during session negotiation");
                Ok(())
            }
            Err(error) => self.protocol_error(ctx, error).await,
        }
    }

    async fn serve_loop<S>(&self, ctx: &mut SessionContext<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if ctx.state == SessionState::Closed || ctx.state == SessionState::Poisoned {
            return Ok(());
        }

        let mut shutdown = self.shutdown.clone();

        loop {
            if *shutdown.borrow() {
                self.graceful_shutdown(ctx).await?;
                return Ok(());
            }

            if let Some(reason) = self.expired_limit(ctx, Instant::now()) {
                self.close(ctx, reason).await?;
                return Ok(());
            }

            let idle_sleep = sleep(self.config.idle_timeout);
            tokio::pin!(idle_sleep);

            tokio::select! {
                frame = read_frame(&mut ctx.stream) => {
                    match frame {
                        Ok(frame) => {
                            ctx.last_activity = Instant::now();
                            if !self.handle_frame(ctx, frame, &mut shutdown).await? {
                                return Ok(());
                            }
                        }
                        Err(error) => return self.protocol_error(ctx, error).await,
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        self.graceful_shutdown(ctx).await?;
                        return Ok(());
                    }
                }
                _ = &mut idle_sleep => {
                    self.close(ctx, CloseReason::IdleTimeout).await?;
                    return Ok(());
                }
            }
        }
    }

    async fn handle_frame<S>(
        &self,
        ctx: &mut SessionContext<S>,
        frame: Frame,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match frame {
            Frame::OpenRequest {
                cmd,
                atyp,
                addr,
                port,
            } => {
                ctx.state = SessionState::Active;
                ctx.request_count += 1;
                info!(
                    request_count = ctx.request_count,
                    cmd,
                    atyp,
                    addr_len = addr.len(),
                    port,
                    "reusable session request handled"
                );

                let relay_result = relay_open_request(
                    &mut ctx.stream,
                    cmd,
                    atyp,
                    addr,
                    port,
                    shutdown,
                    SHUTDOWN_DRAIN_TIMEOUT,
                )
                .await;
                match relay_result {
                    Ok((tx, rx)) => info!(tx, rx, "reusable request relay closed"),
                    Err(error) => {
                        warn!(error = %format!("{:#}", error), "reusable request relay failed");
                        self.reset(ctx, CloseReason::ServerError).await?;
                        return Ok(false);
                    }
                }
                ctx.state = SessionState::Idle;

                if *shutdown.borrow() {
                    self.close(ctx, CloseReason::ShutdownDrain).await?;
                    return Ok(false);
                }

                if let Some(reason) = self.expired_limit(ctx, Instant::now()) {
                    self.close(ctx, reason).await?;
                    return Ok(false);
                }

                Ok(true)
            }
            Frame::Ping { token } => {
                debug!(token, "reusable session ping received");
                write_frame(&mut ctx.stream, &Frame::Pong { token }).await?;
                Ok(true)
            }
            Frame::Close { reason } => {
                info!(client_reason = reason, reason = %CloseReason::ClientInitiated, "reusable session close received");
                self.close(ctx, CloseReason::ClientInitiated).await?;
                Ok(false)
            }
            frame => {
                warn!(?frame, reason = %CloseReason::ProtocolError, "unexpected reusable session frame");
                self.reset(ctx, CloseReason::ProtocolError).await?;
                Ok(false)
            }
        }
    }

    fn expired_limit<S>(&self, ctx: &SessionContext<S>, now: Instant) -> Option<CloseReason> {
        if ctx.request_count >= self.config.max_requests as u64 {
            return Some(CloseReason::MaxRequestsReached);
        }

        if elapsed_at_least(now, ctx.created_at, self.config.max_age) {
            return Some(CloseReason::MaxAgeExceeded);
        }

        if elapsed_at_least(now, ctx.last_activity, self.config.idle_timeout) {
            return Some(CloseReason::IdleTimeout);
        }

        None
    }

    async fn close<S>(&self, ctx: &mut SessionContext<S>, reason: CloseReason) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        ctx.state = SessionState::Closing;
        info!(reason = %reason, requests = ctx.request_count, "reusable session closing");
        write_frame(
            &mut ctx.stream,
            &Frame::Close {
                reason: close_reason_code(reason),
            },
        )
        .await?;
        ctx.state = SessionState::Closed;
        Ok(())
    }

    async fn graceful_shutdown<S>(&self, ctx: &mut SessionContext<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match ctx.state {
            SessionState::Active => {
                ctx.state = SessionState::Draining;
                let closed = timeout(
                    SHUTDOWN_DRAIN_TIMEOUT,
                    self.close(ctx, CloseReason::ShutdownDrain),
                )
                .await;
                match closed {
                    Ok(result) => result,
                    Err(_) => self.reset(ctx, CloseReason::ShutdownDrain).await,
                }
            }
            SessionState::Closed | SessionState::Poisoned => Ok(()),
            _ => self.close(ctx, CloseReason::ShutdownDrain).await,
        }
    }

    async fn reset<S>(&self, ctx: &mut SessionContext<S>, reason: CloseReason) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        ctx.state = SessionState::Poisoned;
        write_frame(
            &mut ctx.stream,
            &Frame::Reset {
                reason: close_reason_code(reason),
            },
        )
        .await?;
        Ok(())
    }

    async fn protocol_error<S>(&self, ctx: &mut SessionContext<S>, error: FrameError) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        warn!(%error, reason = %CloseReason::ProtocolError, "reusable session protocol error");
        self.reset(ctx, CloseReason::ProtocolError).await
    }
}

fn elapsed_at_least(now: Instant, then: Instant, duration: Duration) -> bool {
    now.checked_duration_since(then)
        .map(|elapsed| elapsed >= duration)
        .unwrap_or(false)
}

async fn relay_open_request<S>(
    stream: &mut S,
    cmd: u8,
    atyp: u8,
    addr: Vec<u8>,
    port: u16,
    shutdown: &mut watch::Receiver<bool>,
    drain_timeout: Duration,
) -> Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if cmd != trojan::Cmd::Connect as u8 {
        return Err(anyhow!("unsupported reusable request command: {cmd}"));
    }

    let dest_addr = frame_addr_to_trojan_addr(atyp, addr, port)?;
    let mut outbound = call_with_addr!(TcpStream::connect, dest_addr)
        .context("failed to connect reusable request target")?;
    relay_framed_tcp(stream, &mut outbound, shutdown, drain_timeout).await
}

fn frame_addr_to_trojan_addr(atyp: u8, addr: Vec<u8>, port: u16) -> Result<trojan::Addr> {
    match atyp {
        0x01 => {
            let bytes: [u8; 4] = addr
                .try_into()
                .map_err(|_| anyhow!("invalid ipv4 address length"))?;
            Ok(trojan::Addr::SocketAddr(
                (std::net::Ipv4Addr::from(bytes), port).into(),
            ))
        }
        0x04 => {
            let bytes: [u8; 16] = addr
                .try_into()
                .map_err(|_| anyhow!("invalid ipv6 address length"))?;
            Ok(trojan::Addr::SocketAddr(
                (std::net::Ipv6Addr::from(bytes), port).into(),
            ))
        }
        0x03 => Ok(trojan::Addr::Domain(
            String::from_utf8(addr).context("invalid domain address encoding")?,
            port,
        )),
        other => Err(anyhow!("unsupported address type: {other}")),
    }
}

async fn relay_framed_tcp<S>(
    stream: &mut S,
    outbound: &mut TcpStream,
    shutdown: &mut watch::Receiver<bool>,
    drain_timeout: Duration,
) -> Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tx = 0u64;
    let mut rx = 0u64;
    let (mut session_r, mut session_w) = tokio::io::split(stream);
    let (mut outbound_r, mut outbound_w) = outbound.split();
    let mut buf = vec![0u8; 16 * 1024];
    let mut client_ended = false;
    let mut target_ended = false;
    let drain_sleep = sleep(drain_timeout);
    tokio::pin!(drain_sleep);

    let mut draining = *shutdown.borrow();
    drain_sleep.as_mut().reset(Instant::now() + drain_timeout);

    loop {
        tokio::select! {
            frame = read_frame(&mut session_r), if !client_ended => {
                match frame? {
                    Frame::Data(data) => {
                        tx += data.len() as u64;
                        outbound_w.write_all(&data).await.context("failed to write reusable data to target")?;
                    }
                    Frame::EndRequest { .. } => {
                        client_ended = true;
                        outbound_w.shutdown().await.ok();
                    }
                    Frame::Reset { reason } => return Err(anyhow!("client reset reusable request: {reason}")),
                    Frame::Ping { token } => write_frame(&mut session_w, &Frame::Pong { token }).await?,
                    frame => return Err(anyhow!("unexpected reusable request frame: {:?}", frame)),
                }
            }
            read = outbound_r.read(&mut buf), if !target_ended => {
                let n = read.context("failed to read target response")?;
                if n == 0 {
                    target_ended = true;
                    write_frame(&mut session_w, &Frame::EndRequest { reason: END_REQUEST_OK }).await?;
                } else {
                    rx += n as u64;
                    write_frame(&mut session_w, &Frame::Data(buf[..n].to_vec())).await?;
                }
            }
            _ = shutdown.changed(), if !draining => {
                if *shutdown.borrow() {
                    draining = true;
                    drain_sleep.as_mut().reset(Instant::now() + drain_timeout);
                }
            }
            _ = &mut drain_sleep, if draining => {
                return Err(anyhow!("timed out draining reusable request during shutdown"));
            }
            else => break,
        }

        if client_ended && target_ended {
            break;
        }
    }

    Ok((tx, rx))
}

fn close_reason_code(reason: CloseReason) -> u8 {
    match reason {
        CloseReason::ClientClose => 0x01,
        CloseReason::ClientInitiated => 0x01,
        CloseReason::ServerClose => 0x02,
        CloseReason::ServerError => 0x02,
        CloseReason::IdleTimeout => 0x03,
        CloseReason::MaxAgeExceeded => 0x04,
        CloseReason::MaxRequestsExceeded => 0x05,
        CloseReason::MaxRequestsReached => 0x05,
        CloseReason::KeepaliveTimeout => 0x06,
        CloseReason::ProtocolError => 0x07,
        CloseReason::VersionMismatch => 0x08,
        CloseReason::ShutdownDrain => 0x09,
        CloseReason::CheckoutFailed => 0x0a,
        CloseReason::Poisoned => 0x0b,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use super::*;
    use crate::session::frame::{read_frame, write_frame, Frame};

    fn test_config(max_requests: usize) -> ReuseConfig {
        ReuseConfig {
            max_idle: 1,
            max_requests,
            max_age: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
            jitter_percent: 0,
        }
    }

    async fn start_loop(max_requests: usize) -> tokio::io::DuplexStream {
        let (client, server) = duplex(4096);
        let session_loop = SessionLoop::new(test_config(max_requests));
        tokio::spawn(async move {
            session_loop.run_with_stream(server).await.unwrap();
        });
        client
    }

    async fn start_loop_with_shutdown(
        max_requests: usize,
    ) -> (tokio::io::DuplexStream, watch::Sender<bool>) {
        let (client, server) = duplex(4096);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let session_loop = SessionLoop::with_shutdown(test_config(max_requests), shutdown_rx);
        tokio::spawn(async move {
            session_loop.run_with_stream(server).await.unwrap();
        });
        (client, shutdown_tx)
    }

    async fn hello(client: &mut tokio::io::DuplexStream) {
        write_frame(
            client,
            &Frame::ClientHello {
                version: PROTOCOL_VERSION,
                capabilities: 0,
            },
        )
        .await
        .unwrap();
    }

    async fn start_target() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            while stream.read(&mut buf).await.unwrap_or(0) != 0 {}
        });
        addr
    }

    fn open_request(addr: std::net::SocketAddr) -> Frame {
        let (addr, port) = match addr {
            std::net::SocketAddr::V4(addr) => (addr.ip().octets().to_vec(), addr.port()),
            std::net::SocketAddr::V6(addr) => (addr.ip().octets().to_vec(), addr.port()),
        };
        Frame::OpenRequest {
            cmd: 0x01,
            atyp: 0x01,
            addr,
            port,
        }
    }

    #[tokio::test]
    async fn handles_single_request() {
        let mut client = start_loop(10).await;
        hello(&mut client).await;
        let target = start_target().await;

        write_frame(&mut client, &open_request(target))
            .await
            .unwrap();
        write_frame(
            &mut client,
            &Frame::EndRequest {
                reason: END_REQUEST_OK,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::EndRequest {
                reason: END_REQUEST_OK
            }
        );
    }

    #[tokio::test]
    async fn handles_multiple_sequential_requests() {
        let mut client = start_loop(10).await;
        hello(&mut client).await;

        for port in [80, 443] {
            let target = start_target().await;
            write_frame(&mut client, &open_request(target))
                .await
                .unwrap();
            write_frame(
                &mut client,
                &Frame::EndRequest {
                    reason: END_REQUEST_OK,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                read_frame(&mut client).await.unwrap(),
                Frame::EndRequest {
                    reason: END_REQUEST_OK
                }
            );
        }
    }

    #[tokio::test]
    async fn closes_when_max_requests_reached() {
        let mut client = start_loop(1).await;
        hello(&mut client).await;
        let target = start_target().await;

        write_frame(&mut client, &open_request(target))
            .await
            .unwrap();
        write_frame(
            &mut client,
            &Frame::EndRequest {
                reason: END_REQUEST_OK,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::EndRequest {
                reason: END_REQUEST_OK
            }
        );
        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::Close {
                reason: close_reason_code(CloseReason::MaxRequestsReached)
            }
        );
    }

    #[tokio::test]
    async fn closes_on_version_mismatch() {
        let mut client = start_loop(10).await;
        write_frame(
            &mut client,
            &Frame::ClientHello {
                version: PROTOCOL_VERSION + 1,
                capabilities: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::Close {
                reason: close_reason_code(CloseReason::VersionMismatch)
            }
        );
    }

    #[tokio::test]
    async fn resets_on_protocol_error() {
        let mut client = start_loop(10).await;
        hello(&mut client).await;

        write_frame(&mut client, &Frame::Data(b"unexpected".to_vec()))
            .await
            .unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::Reset {
                reason: close_reason_code(CloseReason::ProtocolError)
            }
        );
    }

    #[tokio::test]
    async fn gracefully_closes_when_client_requests_shutdown() {
        let mut client = start_loop(10).await;
        hello(&mut client).await;

        write_frame(
            &mut client,
            &Frame::Close {
                reason: close_reason_code(CloseReason::ClientInitiated),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::Close {
                reason: close_reason_code(CloseReason::ClientInitiated)
            }
        );
    }

    #[tokio::test]
    async fn test_shutdown_during_session_loop() {
        let (mut client, shutdown_tx) = start_loop_with_shutdown(10).await;
        hello(&mut client).await;

        shutdown_tx.send(true).unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::Close {
                reason: close_reason_code(CloseReason::ShutdownDrain)
            }
        );
    }

    #[tokio::test]
    async fn shutdown_after_request_drains_before_close() {
        let (mut client, shutdown_tx) = start_loop_with_shutdown(10).await;
        hello(&mut client).await;
        let target = start_target().await;

        write_frame(&mut client, &open_request(target))
            .await
            .unwrap();
        write_frame(
            &mut client,
            &Frame::EndRequest {
                reason: END_REQUEST_OK,
            },
        )
        .await
        .unwrap();
        tokio::task::yield_now().await;
        shutdown_tx.send(true).unwrap();

        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::EndRequest {
                reason: END_REQUEST_OK
            }
        );
        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::Close {
                reason: close_reason_code(CloseReason::ShutdownDrain)
            }
        );
    }
}
