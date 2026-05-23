//! Protocol capability negotiation for reusable sessions.

use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::session::frame::{read_frame, write_frame, Frame, FrameError, PROTOCOL_VERSION};
use crate::session::lifecycle::CloseReason;

pub const CAP_REUSE: u16 = 0x0001;
pub const CAP_KEEPALIVE: u16 = 0x0002;

const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin {}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Capabilities(u16);

impl Capabilities {
    pub fn new(bits: u16) -> Self {
        Self(bits)
    }

    pub fn reuse(self) -> bool {
        self.0 & CAP_REUSE != 0
    }

    pub fn keepalive(self) -> bool {
        self.0 & CAP_KEEPALIVE != 0
    }

    pub fn bits(self) -> u16 {
        self.0
    }

    pub fn intersect(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 & other.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NegotiatedCapabilities {
    pub reuse: bool,
    pub keepalive: bool,
    pub server_version: u8,
}

impl NegotiatedCapabilities {
    pub fn from_intersect(
        client_caps: Capabilities,
        server_caps: Capabilities,
        version: u8,
    ) -> Self {
        let shared = client_caps.intersect(server_caps);
        Self {
            reuse: shared.reuse(),
            keepalive: shared.keepalive(),
            server_version: version,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum NegotiationError {
    ServerRejected { reason: u8 },
    VersionMismatch { client: u8, server: u8 },
    NoResponse,
    UnexpectedFrame,
    Io(io::Error),
}

impl From<FrameError> for NegotiationError {
    fn from(err: FrameError) -> Self {
        match err {
            FrameError::Io(err) => Self::Io(err),
            FrameError::UnexpectedEof => Self::NoResponse,
            other => Self::Io(io::Error::new(ErrorKind::InvalidData, other)),
        }
    }
}

pub async fn negotiate_client<S>(
    stream: &mut S,
    client_caps: Capabilities,
) -> Result<NegotiatedCapabilities, NegotiationError>
where
    S: AsyncReadWrite,
{
    write_frame(
        stream,
        &Frame::ClientHello {
            version: PROTOCOL_VERSION,
            capabilities: client_caps.bits(),
        },
    )
    .await?;

    let frame = read_with_timeout(stream).await?;
    match frame {
        Frame::ClientHello {
            version,
            capabilities,
        } => {
            if !client_accepts_server_version(version) {
                return Err(NegotiationError::VersionMismatch {
                    client: PROTOCOL_VERSION,
                    server: version,
                });
            }

            Ok(NegotiatedCapabilities::from_intersect(
                client_caps,
                Capabilities::new(capabilities),
                version,
            ))
        }
        Frame::Close { reason } => Err(NegotiationError::ServerRejected { reason }),
        _ => Err(NegotiationError::NoResponse),
    }
}

#[allow(dead_code)]
pub async fn negotiate_server<S>(
    stream: &mut S,
    server_caps: Capabilities,
) -> Result<NegotiatedCapabilities, NegotiationError>
where
    S: AsyncReadWrite,
{
    let frame = read_with_timeout(stream).await?;
    match frame {
        Frame::ClientHello {
            version,
            capabilities,
        } => {
            if !server_accepts_client_version(version) {
                write_frame(
                    stream,
                    &Frame::Close {
                        reason: CloseReason::VersionMismatch as u8,
                    },
                )
                .await?;
                return Err(NegotiationError::VersionMismatch {
                    client: version,
                    server: PROTOCOL_VERSION,
                });
            }

            write_frame(
                stream,
                &Frame::ClientHello {
                    version: PROTOCOL_VERSION,
                    capabilities: server_caps.bits(),
                },
            )
            .await?;

            Ok(NegotiatedCapabilities::from_intersect(
                Capabilities::new(capabilities),
                server_caps,
                PROTOCOL_VERSION,
            ))
        }
        _ => Err(NegotiationError::UnexpectedFrame),
    }
}

pub struct FallbackTracker {
    warned: Mutex<HashSet<String>>,
}

impl FallbackTracker {
    pub fn new() -> Self {
        Self {
            warned: Mutex::new(HashSet::new()),
        }
    }

    pub fn warn_fallback(&self, endpoint: &str) {
        let mut warned = self.warned.lock().unwrap();
        if warned.insert(endpoint.to_string()) {
            tracing::warn!(
                endpoint = %endpoint,
                "remote does not support reusable sessions, falling back to one-shot mode"
            );
        }
    }
}

impl Default for FallbackTracker {
    fn default() -> Self {
        Self::new()
    }
}

async fn read_with_timeout<S>(stream: &mut S) -> Result<Frame, NegotiationError>
where
    S: AsyncReadWrite,
{
    match timeout(NEGOTIATION_TIMEOUT, read_frame(stream)).await {
        Ok(result) => result.map_err(NegotiationError::from),
        Err(_) => Err(NegotiationError::NoResponse),
    }
}

fn client_accepts_server_version(server_version: u8) -> bool {
    server_version >= PROTOCOL_VERSION
}

fn server_accepts_client_version(client_version: u8) -> bool {
    client_version <= PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_successful_negotiation() {
        let (mut client, mut server) = duplex(1024);
        let client_caps = Capabilities::new(CAP_REUSE | CAP_KEEPALIVE);
        let server_caps = Capabilities::new(CAP_REUSE | CAP_KEEPALIVE);

        let (client_result, server_result) = tokio::join!(
            negotiate_client(&mut client, client_caps),
            negotiate_server(&mut server, server_caps),
        );

        let expected = NegotiatedCapabilities {
            reuse: true,
            keepalive: true,
            server_version: PROTOCOL_VERSION,
        };
        assert_eq!(client_result.unwrap(), expected);
        assert_eq!(server_result.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_capability_downgrade() {
        let (mut client, mut server) = duplex(1024);
        let client_caps = Capabilities::new(CAP_REUSE | CAP_KEEPALIVE);
        let server_caps = Capabilities::new(CAP_REUSE);

        let (client_result, server_result) = tokio::join!(
            negotiate_client(&mut client, client_caps),
            negotiate_server(&mut server, server_caps),
        );

        let expected = NegotiatedCapabilities {
            reuse: true,
            keepalive: false,
            server_version: PROTOCOL_VERSION,
        };
        assert_eq!(client_result.unwrap(), expected);
        assert_eq!(server_result.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_version_mismatch() {
        let (mut client, mut server) = duplex(1024);

        let server_task = async {
            write_frame(
                &mut server,
                &Frame::ClientHello {
                    version: PROTOCOL_VERSION - 1,
                    capabilities: CAP_REUSE,
                },
            )
            .await
            .unwrap();
            let mut drain = [0u8; 64];
            let _ = server.read(&mut drain).await;
        };

        let (client_result, _) = tokio::join!(
            negotiate_client(&mut client, Capabilities::new(CAP_REUSE)),
            server_task,
        );

        assert!(matches!(
            client_result,
            Err(NegotiationError::VersionMismatch {
                client: PROTOCOL_VERSION,
                server: 0,
            })
        ));
    }

    #[tokio::test]
    async fn test_server_rejection() {
        let (mut client, mut server) = duplex(1024);

        let server_task = async {
            let request = read_frame(&mut server).await.unwrap();
            assert!(matches!(request, Frame::ClientHello { .. }));
            write_frame(&mut server, &Frame::Close { reason: 0x7f })
                .await
                .unwrap();
        };

        let (client_result, _) = tokio::join!(
            negotiate_client(&mut client, Capabilities::new(CAP_REUSE)),
            server_task,
        );

        assert!(matches!(
            client_result,
            Err(NegotiationError::ServerRejected { reason: 0x7f })
        ));
    }

    #[tokio::test]
    async fn test_server_rejects_incompatible_client_version() {
        let (mut client, mut server) = duplex(1024);

        let client_task = async {
            write_frame(
                &mut client,
                &Frame::ClientHello {
                    version: PROTOCOL_VERSION + 1,
                    capabilities: CAP_REUSE,
                },
            )
            .await
            .unwrap();
            read_frame(&mut client).await.unwrap()
        };

        let (server_result, close_frame) = tokio::join!(
            negotiate_server(&mut server, Capabilities::new(CAP_REUSE)),
            client_task,
        );

        assert!(matches!(
            server_result,
            Err(NegotiationError::VersionMismatch {
                client: 2,
                server: PROTOCOL_VERSION,
            })
        ));
        assert_eq!(
            close_frame,
            Frame::Close {
                reason: CloseReason::VersionMismatch as u8,
            }
        );
    }

    #[tokio::test]
    async fn test_fallback_to_one_shot_on_non_client_hello_response() {
        let (mut client, mut server) = duplex(1024);

        let server_task = async {
            let request = read_frame(&mut server).await.unwrap();
            assert!(matches!(request, Frame::ClientHello { .. }));
            server.write_all(b"legacy trojan response").await.unwrap();
        };

        let (client_result, _) = tokio::join!(
            negotiate_client(&mut client, Capabilities::new(CAP_REUSE)),
            server_task,
        );

        assert!(matches!(client_result, Err(NegotiationError::NoResponse)));
    }

    #[test]
    fn test_fallback_tracker_warn_once() {
        let tracker = FallbackTracker::new();

        tracker.warn_fallback("example.com:443");
        tracker.warn_fallback("example.com:443");
        tracker.warn_fallback("other.example.com:443");

        let warned = tracker.warned.lock().unwrap();
        assert_eq!(warned.len(), 2);
        assert!(warned.contains("example.com:443"));
        assert!(warned.contains("other.example.com:443"));
    }
}
