//! Frame encoding and decoding for the Shuttle protocol.

use std::{error::Error, fmt};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FRAME_CLIENT_HELLO: u8 = 0x01;
pub const FRAME_OPEN_REQUEST: u8 = 0x02;
pub const FRAME_DATA: u8 = 0x03;
pub const FRAME_END_REQUEST: u8 = 0x04;
pub const FRAME_RESET: u8 = 0x05;
pub const FRAME_PING: u8 = 0x06;
pub const FRAME_PONG: u8 = 0x07;
pub const FRAME_CLOSE: u8 = 0x08;
#[allow(dead_code)]
pub const MAX_FRAME_PAYLOAD: usize = 65535;
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug)]
pub enum FrameError {
    UnknownFrameType(u8),
    OversizedPayload(usize),
    UnexpectedEof,
    InvalidPayload(String),
    Io(std::io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFrameType(frame_type) => write!(f, "unknown frame type: {frame_type}"),
            Self::OversizedPayload(len) => write!(f, "oversized payload: {len} bytes"),
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::InvalidPayload(message) => write!(f, "invalid payload: {message}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl Error for FrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    ClientHello {
        version: u8,
        capabilities: u16,
    },
    OpenRequest {
        cmd: u8,
        atyp: u8,
        addr: Vec<u8>,
        port: u16,
    },
    Data(Vec<u8>),
    EndRequest {
        reason: u8,
    },
    Reset {
        reason: u8,
    },
    Ping {
        token: u32,
    },
    Pong {
        token: u32,
    },
    Close {
        reason: u8,
    },
}

impl Frame {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let (frame_type, payload) = self.payload();
        let payload_len = u16::try_from(payload.len())
            .unwrap_or_else(|_| panic!("{}", FrameError::OversizedPayload(payload.len())));

        buf.push(frame_type);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&payload);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < 3 {
            return Err(FrameError::UnexpectedEof);
        }

        let frame_type = bytes[0];
        let payload_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if bytes.len() < 3 + payload_len {
            return Err(FrameError::UnexpectedEof);
        }

        let payload = &bytes[3..3 + payload_len];
        match frame_type {
            FRAME_CLIENT_HELLO => {
                require_len(payload, 3, "client hello")?;
                Ok(Self::ClientHello {
                    version: payload[0],
                    capabilities: u16::from_be_bytes([payload[1], payload[2]]),
                })
            }
            FRAME_OPEN_REQUEST => {
                if payload.len() < 4 {
                    return Err(FrameError::InvalidPayload(
                        "open request payload too short".to_string(),
                    ));
                }

                let cmd = payload[0];
                let atyp = payload[1];
                let addr_len = payload.len() - 4;
                let addr = payload[2..2 + addr_len].to_vec();
                let port =
                    u16::from_be_bytes([payload[payload.len() - 2], payload[payload.len() - 1]]);
                Ok(Self::OpenRequest {
                    cmd,
                    atyp,
                    addr,
                    port,
                })
            }
            FRAME_DATA => Ok(Self::Data(payload.to_vec())),
            FRAME_END_REQUEST => {
                require_len(payload, 1, "end request")?;
                Ok(Self::EndRequest { reason: payload[0] })
            }
            FRAME_RESET => {
                require_len(payload, 1, "reset")?;
                Ok(Self::Reset { reason: payload[0] })
            }
            FRAME_PING => {
                require_len(payload, 4, "ping")?;
                Ok(Self::Ping {
                    token: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
                })
            }
            FRAME_PONG => {
                require_len(payload, 4, "pong")?;
                Ok(Self::Pong {
                    token: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
                })
            }
            FRAME_CLOSE => {
                require_len(payload, 1, "close")?;
                Ok(Self::Close { reason: payload[0] })
            }
            other => Err(FrameError::UnknownFrameType(other)),
        }
    }

    fn payload(&self) -> (u8, Vec<u8>) {
        match self {
            Self::ClientHello {
                version,
                capabilities,
            } => {
                let mut payload = Vec::with_capacity(3);
                payload.push(*version);
                payload.extend_from_slice(&capabilities.to_be_bytes());
                (FRAME_CLIENT_HELLO, payload)
            }
            Self::OpenRequest {
                cmd,
                atyp,
                addr,
                port,
            } => {
                let mut payload = Vec::with_capacity(4 + addr.len());
                payload.push(*cmd);
                payload.push(*atyp);
                payload.extend_from_slice(addr);
                payload.extend_from_slice(&port.to_be_bytes());
                (FRAME_OPEN_REQUEST, payload)
            }
            Self::Data(data) => (FRAME_DATA, data.clone()),
            Self::EndRequest { reason } => (FRAME_END_REQUEST, vec![*reason]),
            Self::Reset { reason } => (FRAME_RESET, vec![*reason]),
            Self::Ping { token } => (FRAME_PING, token.to_be_bytes().to_vec()),
            Self::Pong { token } => (FRAME_PONG, token.to_be_bytes().to_vec()),
            Self::Close { reason } => (FRAME_CLOSE, vec![*reason]),
        }
    }
}

fn require_len(payload: &[u8], expected: usize, frame_name: &str) -> Result<(), FrameError> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(FrameError::InvalidPayload(format!(
            "{frame_name} payload must be {expected} bytes, got {}",
            payload.len()
        )))
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, FrameError> {
    let mut header = [0u8; 3];
    reader.read_exact(&mut header).await?;
    let payload_len = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    let mut full = Vec::with_capacity(3 + payload_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&payload);
    Frame::decode(&full)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), FrameError> {
    let mut buf = Vec::new();
    frame.encode(&mut buf);
    writer.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_each_frame_variant() {
        let frames = [
            Frame::ClientHello {
                version: PROTOCOL_VERSION,
                capabilities: 0x0102,
            },
            Frame::OpenRequest {
                cmd: 0x01,
                atyp: 0x03,
                addr: b"example.com".to_vec(),
                port: 443,
            },
            Frame::Data(b"hello world".to_vec()),
            Frame::EndRequest { reason: 0x01 },
            Frame::Reset { reason: 0x02 },
            Frame::Ping { token: 0x01020304 },
            Frame::Pong { token: 0x05060708 },
            Frame::Close { reason: 0x03 },
        ];

        for frame in frames {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            assert_eq!(Frame::decode(&buf).unwrap(), frame);
        }
    }

    #[test]
    fn decode_rejects_unknown_frame_type() {
        let err = Frame::decode(&[0xff, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, FrameError::UnknownFrameType(0xff)));
    }

    #[test]
    #[should_panic(expected = "oversized payload: 65536 bytes")]
    fn encode_rejects_oversized_payload() {
        let frame = Frame::Data(vec![0u8; MAX_FRAME_PAYLOAD + 1]);
        frame.encode(&mut Vec::new());
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let err = Frame::decode(&[FRAME_DATA, 0x00]).unwrap_err();
        assert!(matches!(err, FrameError::UnexpectedEof));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let err = Frame::decode(&[FRAME_DATA, 0x00, 0x02, 0x01]).unwrap_err();
        assert!(matches!(err, FrameError::UnexpectedEof));
    }

    #[tokio::test]
    async fn async_helpers_round_trip_frame() {
        let frame = Frame::Ping { token: 42 };
        let mut stream = Vec::new();

        write_frame(&mut stream, &frame).await.unwrap();

        let mut reader = std::io::Cursor::new(stream);
        let decoded = read_frame(&mut reader).await.unwrap();
        assert_eq!(decoded, frame);
    }
}
