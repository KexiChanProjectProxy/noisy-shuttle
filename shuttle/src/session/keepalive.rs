//! Idle session keepalive driver.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use snowy_tunnel::SnowyStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use crate::session::frame::{read_frame, write_frame, Frame, FrameError};
use crate::session::lifecycle::SessionEvent;

/// Drives periodic ping/pong checks for an idle reusable session.
#[allow(dead_code)]
pub struct KeepaliveDriver {
    interval: Duration,
    timeout: Duration,
}

/// Errors returned by the keepalive driver.
#[derive(Debug)]
#[allow(dead_code)]
pub enum KeepaliveError {
    Timeout,
    TokenMismatch { expected: u32, received: u32 },
    UnexpectedResponse,
    Io(std::io::Error),
}

impl fmt::Display for KeepaliveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "keepalive timeout"),
            Self::TokenMismatch { expected, received } => {
                write!(
                    f,
                    "keepalive token mismatch: expected {expected}, got {received}"
                )
            }
            Self::UnexpectedResponse => write!(f, "unexpected response frame type"),
            Self::Io(error) => write!(f, "I/O error: {error}"),
        }
    }
}

impl Error for KeepaliveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KeepaliveError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl KeepaliveDriver {
    #[allow(dead_code)]
    pub fn new(interval: Duration) -> Self {
        let timeout = interval.checked_mul(2).unwrap_or(interval);
        Self { interval, timeout }
    }

    #[allow(dead_code)]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn ping<S>(&self, stream: &mut S) -> Result<(), KeepaliveError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let token: u32 = rand::random();
        write_frame(stream, &Frame::Ping { token })
            .await
            .map_err(map_frame_error)?;
        SessionEvent::PingSent.emit();
        tracing::debug!(token = %token, "keepalive ping sent");

        let response = tokio::time::timeout(self.timeout, read_frame(stream))
            .await
            .map_err(|_| {
                SessionEvent::PingTimeout.emit();
                tracing::warn!("keepalive timeout, session will be evicted");
                KeepaliveError::Timeout
            })?
            .map_err(map_frame_error)?;

        match response {
            Frame::Pong { token: received } if received == token => {
                SessionEvent::PingAcked.emit();
                tracing::debug!(token = %token, "keepalive pong received");
                Ok(())
            }
            Frame::Pong { token: received } => Err(KeepaliveError::TokenMismatch {
                expected: token,
                received,
            }),
            _ => Err(KeepaliveError::UnexpectedResponse),
        }
    }
}

#[allow(dead_code)]
pub fn spawn_keepalive_task(
    mut stream: SnowyStream,
    interval: Duration,
    on_timeout: impl FnOnce() + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let driver = KeepaliveDriver::new(interval);
        loop {
            tokio::time::sleep(driver.interval()).await;
            if let Err(error) = driver.ping(&mut stream).await {
                tracing::warn!(%error, "keepalive failed, session will be evicted");
                on_timeout();
                return;
            }
        }
    })
}

#[allow(dead_code)]
fn map_frame_error(error: FrameError) -> KeepaliveError {
    match error {
        FrameError::Io(error) => KeepaliveError::Io(error),
        _ => KeepaliveError::UnexpectedResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_keepalive_ping_pong_success() {
        let (mut client, mut server) = duplex(64);
        let server_task = tokio::spawn(async move {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Frame::Ping { token } => write_frame(&mut server, &Frame::Pong { token })
                    .await
                    .unwrap(),
                other => panic!("unexpected frame: {other:?}"),
            }
        });

        let driver = KeepaliveDriver::new(Duration::from_millis(25));
        driver.ping(&mut client).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_keepalive_timeout() {
        let (mut client, _server) = duplex(64);
        let driver = KeepaliveDriver::new(Duration::from_millis(5));

        let error = driver.ping(&mut client).await.unwrap_err();
        assert!(matches!(error, KeepaliveError::Timeout));
    }

    #[tokio::test]
    async fn test_keepalive_token_mismatch() {
        let (mut client, mut server) = duplex(64);
        let server_task = tokio::spawn(async move {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Frame::Ping { token } => {
                    write_frame(
                        &mut server,
                        &Frame::Pong {
                            token: token.wrapping_add(1),
                        },
                    )
                    .await
                    .unwrap();
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        });

        let driver = KeepaliveDriver::new(Duration::from_millis(25));
        let error = driver.ping(&mut client).await.unwrap_err();
        assert!(matches!(error, KeepaliveError::TokenMismatch { .. }));
        server_task.await.unwrap();
    }
}
