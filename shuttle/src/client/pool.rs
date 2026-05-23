/// Reusable session pool for connection multiplexing.
use std::collections::VecDeque;
use std::io;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use snowy_tunnel::SnowyStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{watch, Mutex, Notify};
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, info, warn};

use crate::opt::ReuseConfig;
use crate::session::lifecycle::{CloseReason, SessionEvent};

use super::connector::Connector;

#[async_trait]
pub trait PoolConnector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    async fn connect(&self) -> io::Result<Self::Stream>;
}

#[async_trait]
impl<T> PoolConnector for T
where
    T: Connector + Send + Sync,
{
    type Stream = SnowyStream;

    async fn connect(&self) -> io::Result<Self::Stream> {
        Connector::connect(self).await
    }
}

pub struct SessionPool<S = SnowyStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    inner: Mutex<PoolInner<S>>,
    drain_notify: Notify,
    shutdown: watch::Receiver<bool>,
    _shutdown_guard: Option<watch::Sender<bool>>,
    config: ReuseConfig,
    connector: Box<dyn PoolConnector<Stream = S>>,
}

struct PoolInner<S> {
    idle: VecDeque<PooledSession<S>>,
    checked_out: usize,
    closed: bool,
    checkout_count: u64,
    reuse_count: u64,
}

pub struct PooledSession<S = SnowyStream> {
    pub stream: S,
    pub use_count: u64,
    pub created_at: Instant,
    pub last_used: Instant,
    pub reuse_count: u64,
}

#[allow(dead_code)]
pub struct SessionHandle<'a, S = SnowyStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pool: &'a SessionPool<S>,
    session: Option<PooledSession<S>>,
    bytes_relayed: bool,
    retry_used: bool,
}

impl<S> SessionPool<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(config: ReuseConfig, connector: Box<dyn PoolConnector<Stream = S>>) -> Self {
        let (shutdown_tx, shutdown) = watch::channel(false);
        Self {
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                checked_out: 0,
                closed: false,
                checkout_count: 0,
                reuse_count: 0,
            }),
            drain_notify: Notify::new(),
            shutdown,
            _shutdown_guard: Some(shutdown_tx),
            config,
            connector,
        }
    }

    #[allow(dead_code)]
    pub fn with_shutdown(
        config: ReuseConfig,
        connector: Box<dyn PoolConnector<Stream = S>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                checked_out: 0,
                closed: false,
                checkout_count: 0,
                reuse_count: 0,
            }),
            drain_notify: Notify::new(),
            shutdown,
            _shutdown_guard: None,
            config,
            connector,
        }
    }

    pub async fn checkout(&self) -> Result<PooledSession<S>> {
        if *self.shutdown.borrow() {
            SessionEvent::CheckoutFailed.emit();
            return Err(anyhow!("session pool is shutting down"));
        }

        let now = Instant::now();
        {
            let mut inner = self.inner.lock().await;
            if inner.closed {
                SessionEvent::CheckoutFailed.emit();
                return Err(anyhow!("session pool is closed"));
            }

            while let Some(mut session) = inner.idle.pop_back() {
                if self.is_reusable(&session, now) {
                    session.use_count += 1;
                    session.reuse_count += 1;
                    session.last_used = now;
                    inner.checked_out += 1;
                    inner.checkout_count += 1;
                    inner.reuse_count += 1;
                    SessionEvent::PoolHit.emit();
                    SessionEvent::SessionReused(session.reuse_count as usize).emit();
                    debug!(
                        use_count = session.use_count,
                        reuse_count = session.reuse_count,
                        checked_out = inner.checked_out,
                        idle_remaining = inner.idle.len(),
                        "checked out reusable session"
                    );
                    return Ok(session);
                }

                self.emit_eviction(&session, now);
            }
        };

        SessionEvent::PoolMiss.emit();
        let session = self.new_session().await?;

        let mut inner = self.inner.lock().await;
        if inner.closed || *self.shutdown.borrow() {
            SessionEvent::CheckoutFailed.emit();
            return Err(anyhow!("session pool closed while checkout was connecting"));
        }
        inner.checked_out += 1;
        inner.checkout_count += 1;
        debug!(
            checked_out = inner.checked_out,
            "checked out new reusable session"
        );
        Ok(session)
    }

    #[allow(dead_code)]
    pub async fn checkout_with_retry(&self) -> Result<SessionHandle<'_, S>> {
        let session = self.checkout().await?;
        Ok(SessionHandle {
            pool: self,
            session: Some(session),
            bytes_relayed: false,
            retry_used: false,
        })
    }

    pub async fn return_session(&self, mut session: PooledSession<S>, healthy: bool) -> Result<()> {
        let now = Instant::now();
        session.last_used = now;

        let mut inner = self.inner.lock().await;
        if inner.checked_out == 0 {
            warn!("returned reusable session when none were checked out");
        } else {
            inner.checked_out -= 1;
            self.drain_notify.notify_waiters();
        }
        let has_other_checked_out = inner.checked_out > 0;

        if !healthy || !self.is_reusable(&session, now) {
            if healthy {
                self.emit_eviction(&session, now);
            } else {
                info!(reason = %CloseReason::Poisoned, "closing unhealthy reusable session");
            }
            return Ok(());
        }

        if inner.closed || *self.shutdown.borrow() {
            info!(reason = %CloseReason::ShutdownDrain, "closing returned reusable session during drain");
            return Ok(());
        }

        if inner.idle.len() >= self.config.max_idle {
            if has_other_checked_out {
                info!(reason = %CloseReason::ShutdownDrain, "closing returned reusable session instead of evicting during concurrent checkout");
                return Ok(());
            }

            if inner.idle.pop_front().is_some() {
                SessionEvent::IdleEviction.emit();
                info!(reason = %CloseReason::IdleTimeout, "evicted oldest idle reusable session");
            }
        }

        inner.idle.push_back(session);
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn close_all(&self) {
        const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

        let checked_out = {
            let mut inner = self.inner.lock().await;
            inner.closed = true;
            let closed = inner.idle.len();
            inner.idle.clear();
            info!(closed, checked_out = inner.checked_out, reason = %CloseReason::ShutdownDrain, "closed all idle reusable sessions");
            inner.checked_out
        };

        if checked_out == 0 {
            SessionEvent::GracefulDrain.emit();
            return;
        }

        let drained = timeout(DRAIN_TIMEOUT, async {
            loop {
                {
                    let inner = self.inner.lock().await;
                    if inner.checked_out == 0 {
                        break;
                    }
                }
                self.drain_notify.notified().await;
            }
        })
        .await;

        match drained {
            Ok(()) => {
                SessionEvent::GracefulDrain.emit();
                info!(reason = %CloseReason::ShutdownDrain, "reusable session pool drained");
            }
            Err(_) => {
                warn!(reason = %CloseReason::ShutdownDrain, "timed out waiting for reusable session pool drain")
            }
        }
    }

    #[allow(dead_code)]
    async fn discard_checked_out(&self) {
        let mut inner = self.inner.lock().await;
        if inner.checked_out == 0 {
            warn!("discarded reusable session when none were checked out");
            return;
        }
        inner.checked_out -= 1;
        self.drain_notify.notify_waiters();
    }

    #[cfg(test)]
    async fn checked_out(&self) -> usize {
        self.inner.lock().await.checked_out
    }

    #[cfg(test)]
    async fn idle_len(&self) -> usize {
        self.inner.lock().await.idle.len()
    }

    async fn new_session(&self) -> Result<PooledSession<S>> {
        let now = Instant::now();
        let stream = self.connector.connect().await.map_err(|error| {
            SessionEvent::CheckoutFailed.emit();
            anyhow!(error).context("failed to create reusable session")
        })?;

        Ok(PooledSession {
            stream,
            use_count: 1,
            created_at: now,
            last_used: now,
            reuse_count: 0,
        })
    }

    fn is_reusable(&self, session: &PooledSession<S>, now: Instant) -> bool {
        session.use_count < self.config.max_requests as u64
            && now.duration_since(session.created_at) < self.config.max_age
            && now.duration_since(session.last_used) < self.config.idle_timeout
    }

    fn emit_eviction(&self, session: &PooledSession<S>, now: Instant) {
        if session.use_count >= self.config.max_requests as u64 {
            SessionEvent::MaxRequestsEviction.emit();
            info!(reason = %CloseReason::MaxRequestsExceeded, "evicted reusable session");
        } else if now.duration_since(session.created_at) >= self.config.max_age {
            SessionEvent::MaxAgeEviction.emit();
            info!(reason = %CloseReason::MaxAgeExceeded, "evicted reusable session");
        } else if now.duration_since(session.last_used) >= self.config.idle_timeout {
            SessionEvent::IdleEviction.emit();
            info!(reason = %CloseReason::IdleTimeout, "evicted reusable session");
        }
    }
}

impl<'a, S> SessionHandle<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[allow(dead_code)]
    pub fn session(&self) -> Option<&PooledSession<S>> {
        self.session.as_ref()
    }

    #[allow(dead_code)]
    pub fn session_mut(&mut self) -> Option<&mut PooledSession<S>> {
        self.session.as_mut()
    }

    #[allow(dead_code)]
    pub fn mark_bytes_relayed(&mut self) {
        self.bytes_relayed = true;
    }

    #[allow(dead_code)]
    pub fn into_session(mut self) -> Result<PooledSession<S>> {
        self.session
            .take()
            .ok_or_else(|| anyhow!("session handle has no active session"))
    }

    #[allow(dead_code)]
    pub async fn retry_after_protocol_error(mut self, error: anyhow::Error) -> Result<Self> {
        if self.bytes_relayed || self.retry_used {
            return Err(error);
        }

        self.session.take();
        self.pool.discard_checked_out().await;
        info!(reason = %CloseReason::ProtocolError, "retrying reusable session before payload relay");
        SessionEvent::FallbackToOneShot.emit();
        let session = self.pool.checkout().await?;
        self.session = Some(session);
        self.retry_used = true;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::DuplexStream;
    use tokio::sync::{watch, Notify};

    struct MockConnector {
        connect_count: AtomicUsize,
        block_connect: bool,
        connect_started: Notify,
        release_connect: Notify,
    }

    impl MockConnector {
        fn new() -> Self {
            Self {
                connect_count: AtomicUsize::new(0),
                block_connect: false,
                connect_started: Notify::new(),
                release_connect: Notify::new(),
            }
        }

        fn blocking() -> Self {
            Self {
                connect_count: AtomicUsize::new(0),
                block_connect: true,
                connect_started: Notify::new(),
                release_connect: Notify::new(),
            }
        }

        fn connect_count(&self) -> usize {
            self.connect_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl PoolConnector for Arc<MockConnector> {
        type Stream = DuplexStream;

        async fn connect(&self) -> io::Result<Self::Stream> {
            self.connect_count.fetch_add(1, Ordering::SeqCst);
            self.connect_started.notify_waiters();
            if self.block_connect {
                self.release_connect.notified().await;
            }
            let (client, _server) = tokio::io::duplex(64);
            Ok(client)
        }
    }

    fn config() -> ReuseConfig {
        ReuseConfig {
            max_idle: 1,
            max_requests: 3,
            max_age: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(10),
            keepalive_timeout: Duration::from_secs(5),
            jitter_percent: 0,
        }
    }

    fn pool_with(config: ReuseConfig, connector: Arc<MockConnector>) -> SessionPool<DuplexStream> {
        SessionPool::new(config, Box::new(connector))
    }

    fn pool_with_shutdown(
        config: ReuseConfig,
        connector: Arc<MockConnector>,
        shutdown: watch::Receiver<bool>,
    ) -> SessionPool<DuplexStream> {
        SessionPool::with_shutdown(config, Box::new(connector), shutdown)
    }

    #[tokio::test]
    async fn test_pool_miss_empty_pool() {
        let connector = Arc::new(MockConnector::new());
        let pool = pool_with(config(), connector.clone());

        let session = pool.checkout().await.unwrap();

        assert_eq!(session.use_count, 1);
        assert_eq!(session.reuse_count, 0);
        assert_eq!(connector.connect_count(), 1);
    }

    #[tokio::test]
    async fn test_pool_hit_idle_available() {
        let connector = Arc::new(MockConnector::new());
        let pool = pool_with(config(), connector.clone());
        let session = pool.checkout().await.unwrap();
        pool.return_session(session, true).await.unwrap();

        let session = pool.checkout().await.unwrap();

        assert_eq!(connector.connect_count(), 1);
        assert_eq!(session.use_count, 2);
        assert_eq!(session.reuse_count, 1);
    }

    #[tokio::test]
    async fn test_eviction_when_full() {
        let connector = Arc::new(MockConnector::new());
        let mut cfg = config();
        cfg.max_idle = 1;
        let pool = pool_with(cfg, connector.clone());
        let first = pool.checkout().await.unwrap();
        let second = pool.checkout().await.unwrap();

        pool.return_session(first, true).await.unwrap();
        pool.return_session(second, true).await.unwrap();
        let session = pool.checkout().await.unwrap();

        assert_eq!(connector.connect_count(), 2);
        assert_eq!(session.use_count, 2);
    }

    #[tokio::test]
    async fn test_max_requests_eviction() {
        let connector = Arc::new(MockConnector::new());
        let mut cfg = config();
        cfg.max_requests = 1;
        let pool = pool_with(cfg, connector.clone());
        let session = pool.checkout().await.unwrap();

        pool.return_session(session, true).await.unwrap();
        let session = pool.checkout().await.unwrap();

        assert_eq!(connector.connect_count(), 2);
        assert_eq!(session.use_count, 1);
    }

    #[tokio::test]
    async fn test_max_age_eviction() {
        let connector = Arc::new(MockConnector::new());
        let mut cfg = config();
        cfg.max_age = Duration::from_millis(1);
        let pool = pool_with(cfg, connector.clone());
        let session = pool.checkout().await.unwrap();

        tokio::time::sleep(Duration::from_millis(5)).await;
        pool.return_session(session, true).await.unwrap();
        let session = pool.checkout().await.unwrap();

        assert_eq!(connector.connect_count(), 2);
        assert_eq!(session.use_count, 1);
    }

    #[tokio::test]
    async fn test_pre_payload_retry() {
        let connector = Arc::new(MockConnector::new());
        let pool = pool_with(config(), connector.clone());
        let handle = pool.checkout_with_retry().await.unwrap();

        let handle = handle
            .retry_after_protocol_error(anyhow!("protocol error before payload"))
            .await
            .unwrap();

        assert_eq!(connector.connect_count(), 2);
        assert!(handle.session().is_some());
    }

    #[tokio::test]
    async fn test_cancellation_safe_checkout() {
        let connector = Arc::new(MockConnector::blocking());
        let pool = Arc::new(pool_with(config(), connector.clone()));

        let checkout_pool = pool.clone();
        let checkout = tokio::spawn(async move { checkout_pool.checkout().await });
        connector.connect_started.notified().await;

        checkout.abort();
        match checkout.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("checkout task completed before cancellation"),
        }

        assert_eq!(pool.checked_out().await, 0);
        assert_eq!(pool.idle_len().await, 0);
    }

    #[tokio::test]
    async fn test_drain_waits_for_checked_out() {
        let connector = Arc::new(MockConnector::new());
        let pool = Arc::new(pool_with(config(), connector));
        let session = pool.checkout().await.unwrap();

        let close_pool = pool.clone();
        let close = tokio::spawn(async move { close_pool.close_all().await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!close.is_finished());

        pool.return_session(session, true).await.unwrap();
        close.await.unwrap();
        assert_eq!(pool.checked_out().await, 0);
    }

    #[tokio::test]
    async fn test_checkout_after_close_returns_error() {
        let connector = Arc::new(MockConnector::new());
        let pool = pool_with(config(), connector);

        pool.close_all().await;

        assert!(pool.checkout().await.is_err());
    }

    #[tokio::test]
    async fn test_shutdown_during_checkout() {
        let connector = Arc::new(MockConnector::blocking());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let pool = Arc::new(pool_with_shutdown(config(), connector.clone(), shutdown_rx));

        let checkout_pool = pool.clone();
        let checkout = tokio::spawn(async move { checkout_pool.checkout().await });
        connector.connect_started.notified().await;

        shutdown_tx.send(true).unwrap();
        connector.release_connect.notify_waiters();

        assert!(checkout.await.unwrap().is_err());
        assert_eq!(pool.checked_out().await, 0);
    }

    #[tokio::test]
    async fn test_eviction_no_race_with_checkout() {
        let connector = Arc::new(MockConnector::new());
        let mut cfg = config();
        cfg.max_idle = 1;
        let pool = pool_with(cfg, connector);

        let first = pool.checkout().await.unwrap();
        let second = pool.checkout().await.unwrap();
        pool.return_session(first, true).await.unwrap();
        assert_eq!(pool.idle_len().await, 1);

        pool.return_session(second, true).await.unwrap();

        assert_eq!(pool.checked_out().await, 0);
        assert_eq!(pool.idle_len().await, 1);
    }
}
