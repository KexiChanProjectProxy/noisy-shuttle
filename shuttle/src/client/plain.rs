use anyhow::{anyhow, ensure, Context, Result};

use socks5::sync::FromIO;
use socks5_protocol as socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};
use tracing::{debug, info, instrument, trace, warn};

use std::io::{self, Cursor, Write};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use snowy_tunnel::SnowyStream;

use crate::session::frame::{read_frame, write_frame, Frame};
use crate::session::lifecycle::{CloseReason, SessionEvent};
use crate::session::negotiate::{negotiate_client, Capabilities, FallbackTracker, CAP_REUSE};
use crate::trojan::{
    self, Cmd, TrojanLikeRequest, TrojanUdpDatagramReceiver, TrojanUdpDatagramSender,
    MAX_DATAGRAM_SIZE,
};
use crate::utils::{extract_host_addr_from_url, url_to_relative, vec_uninit, DurationExt};

use super::connector::Connector;
use super::pool::{PooledSession, SessionPool};
use super::{FIRST_PACKET_TIMEOUT, MAX_FIRST_PACKET_SIZE};

pub async fn serve(
    listen_addr: SocketAddr,
    connector: Arc<impl Connector + 'static + Send + Sync>,
    pool: Option<Arc<SessionPool>>,
    endpoint: String,
) -> Result<()> {
    let fallback_tracker = Arc::new(FallbackTracker::new());
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind on {}", listen_addr))?;

    while let Ok((inbound, client_addr)) = listener.accept().await {
        // TODO: handle error
        debug!("accepting connection from {}", &client_addr);
        let connector = connector.clone();
        let pool = pool.clone();
        let endpoint = endpoint.clone();
        let fallback_tracker = fallback_tracker.clone();
        // convention: handle_connection only returns error in early/handshake phases
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                inbound,
                client_addr,
                connector,
                pool,
                endpoint,
                fallback_tracker,
            )
            .await
            {
                warn!(error = %format!("{:#}", e), "failed to serve {}", &client_addr)
            }
        });
    }
    Ok(())
}

// #[instrument(skip(connector), level = "trace")]
async fn handle_connection(
    inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
    pool: Option<Arc<SessionPool>>,
    endpoint: String,
    fallback_tracker: Arc<FallbackTracker>,
) -> Result<()> {
    let mut first = [0u8];
    inbound.peek(&mut first).await?;

    match first[0] {
        0x04 | 0x05 => {
            handle_connection_socks5(
                inbound,
                client_addr,
                connector,
                pool,
                endpoint,
                fallback_tracker,
            )
            .await
        }
        _ => {
            handle_connection_http(
                inbound,
                client_addr,
                connector,
                pool,
                endpoint,
                fallback_tracker,
            )
            .await
        }
    }
}

#[instrument(name = "socks5_proxy", skip(inbound, client_addr, connector, pool, fallback_tracker), fields(
    %client = client_addr,
    // %local_in = inbound.local_addr().unwrap(),
))]
#[inline(always)]
async fn handle_connection_socks5(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
    pool: Option<Arc<SessionPool>>,
    endpoint: String,
    fallback_tracker: Arc<FallbackTracker>,
) -> Result<()> {
    const SOCKS5_CONNECT_SUCCEEDED: &[u8] =
        &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const SOCKS5_COMMAND_NOT_SUPPORTED: &[u8] = &[0x05, 0x07, 0x00];
    // the socks5 lib is hard to use, so we use it together with raw bytes alternatively
    socks5::Version::read(&mut inbound).await?;
    let req = socks5::AuthRequest::read(&mut inbound).await?;
    inbound
        .write_all(&[0x05, req.select_from(&[socks5::AuthMethod::Noauth]).into()])
        .await?;
    // CommandRequest includes VER
    let req = socks5::CommandRequest::read(&mut inbound).await?;
    info!(
        command = ?req.command,
        dest_addr = req.address.to_string(),
        "accepting request"
    );
    match req.command {
        socks5::Command::Connect => {
            inbound
                .write_all(SOCKS5_CONNECT_SUCCEEDED)
                .await
                .context("failed to write socks5 response")?;
            // TODO: return error from connect?
            let outbuf = Some(TrojanLikeRequest::new(Cmd::Connect, req.address).encoded());
            log_relay!(relay_tcp_remote(
                &mut inbound,
                connector,
                pool,
                endpoint,
                fallback_tracker,
                outbuf
            ));
            Ok(())
        }
        socks5::Command::UdpAssociate => {
            // By binding a random port to receive inbound UDP packets, shuttle client cannot be
            // behind NAT.
            // By not connecting (ignoring address in request), the inbound can be behind NAT.
            //
            // The alternative way to implement UDPAssociate is to receive inbound UDP packets on
            // a fixed port say 0.0.0.0:1080 and maintain a queue to store NAT-like association.
            let mut bnd_addr = inbound.local_addr()?;
            bnd_addr.set_port(0);
            let mut inbound_udp = UdpSocket::bind(bnd_addr).await?;
            bnd_addr = inbound_udp.local_addr()?;
            trace!(local_in_udp = bnd_addr.to_string(), "UDP bound");
            let mut buffered_inbound = BufWriter::new(&mut inbound);
            socks5::CommandResponse::success(bnd_addr.into())
                .write(&mut buffered_inbound)
                .await
                .map_err(|e| e.to_io_err())?;
            buffered_inbound.flush().await?;

            let mut snowys = connector
                .connect()
                .await
                .context("failed to establish snowy tunnel")?;
            let header = TrojanLikeRequest::new(Cmd::UdpAssociate, Default::default());
            log_relay!(relay_udp_with(
                &mut inbound,
                &mut inbound_udp,
                &mut snowys,
                header
            ));
            Ok(())
        }
        // not supported
        socks5::Command::Bind => {
            inbound.write_all(SOCKS5_COMMAND_NOT_SUPPORTED).await?;
            Err(anyhow!("Socks5 BIND not supported"))
        }
    }
}

#[instrument(name = "http_proxy", skip(inbound, client_addr, connector, pool, fallback_tracker), fields(
    %client = client_addr,
    // %local_in = inbound.local_addr().unwrap(),
))]
#[inline(always)]
async fn handle_connection_http(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    connector: Arc<impl Connector + 'static>,
    pool: Option<Arc<SessionPool>>,
    endpoint: String,
    fallback_tracker: Arc<FallbackTracker>,
) -> Result<()> {
    const HTTP_200_CONNECTION_ESTABLISHED: &[u8] =
        b"HTTP/1.1 200 Connection Established\r\nX-Powered-By: noisy-shuttle\r\n\r\n";
    const HTTP_400_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n<html><h1>Not Proxied Request</h1>Powered by noisy-shuttle</html>";
    const HTTP_405_METHOD_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n<html><h1>Method Not Allowed</h1>Powered by noisy-shuttle</html>";

    use httparse::{Request, Status};
    let mut buf = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
    let mut end = 0;
    let mut initlen = 0; // initial data length
    let (outbuf, connect_sent_direct, outbound) = loop {
        let n = inbound.read(&mut buf).await?;
        ensure!(n > 0, "incompleted http request");
        end += n;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);
        if let Status::Complete(start) = req.parse(&buf[..end])? {
            // some mysterious lifetime / borrow checking limits here
            // so we have to process data in loop
            let method = req.method.unwrap();
            let url = req.path.unwrap();
            let hver = req.version.unwrap();
            info!(
                %method,
                url,
                version = %format!("1.{}", hver),
                "accepting request",
            );

            let mut host = None;
            let mut keepalive = false;
            let headers: Vec<_> = req
                .headers
                .iter_mut()
                .filter_map(|header| {
                    if header.name.len() >= 6 && header.name[..6].eq_ignore_ascii_case("Proxy-") {
                        if header.name[6..].eq_ignore_ascii_case("Connection") {
                            keepalive = header.value.eq_ignore_ascii_case(b"keep-alive");
                        }
                        None
                    } else {
                        if header.name.eq_ignore_ascii_case("Host") {
                            host = Some(header.value);
                        }
                        Some(header)
                    }
                })
                .collect();
            let host = match host {
                Some(host) => Some(std::str::from_utf8(host).context("invalid Host")?),
                None => None,
            };
            trace!(host = host.unwrap_or("<EMPTY>"), keepalive, "http params",);

            break match method {
                "CONNECT" => {
                    let dest_addr = trojan::Addr::from_str(url)
                        .ok()
                        .context("invalid address")?;
                    inbound.write_all(HTTP_200_CONNECTION_ESTABLISHED).await?;
                    debug!(%dest_addr);
                    let header = TrojanLikeRequest::new(Cmd::Connect, dest_addr);
                    let mut outbuf = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
                    let n = header.encode(&mut outbuf);
                    unsafe { outbuf.set_len(n) };
                    outbuf.extend_from_slice(&buf[start..end]);
                    (Some(outbuf), false, None)
                }
                method @ ("GET" | "POST" | "OPTIONS" | "HEAD" | "PUT" | "DELETE" | "TRACE"
                | "PATCH") => {
                    if url.starts_with('/') {
                        // not proxied request
                        inbound.write_all(HTTP_400_BAD_REQUEST).await?;
                        return Err(anyhow!(
                            "not proxied request (path: {}, host:{})",
                            url,
                            host.unwrap_or("<EMPTY>")
                        ));
                    }
                    let dest_addr = extract_host_addr_from_url(url)
                        .and_then(|a| {
                            if a.0.len() < 256 {
                                Some(trojan::Addr::Domain(a.0.to_owned(), a.1))
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| anyhow!("invalid url: {}", url))?;
                    let path =
                        url_to_relative(url).ok_or_else(|| anyhow!("invalid url: {}", url))?;
                    debug!(%dest_addr);
                    let header = TrojanLikeRequest::new(Cmd::Connect, dest_addr);
                    let mut outbuf = unsafe { vec_uninit(MAX_FIRST_PACKET_SIZE) };
                    let n = header.encode(&mut outbuf);
                    let mut cursor = io::Cursor::new(outbuf);
                    cursor.set_position(n as u64);
                    cursor
                        .write_fmt(format_args!("{} {} HTTP/1.{}\r\n", method, path, hver))
                        .unwrap();
                    for header in headers {
                        cursor
                            .write_fmt(format_args!(
                                "{}: {}\r\n",
                                header.name,
                                std::str::from_utf8(header.value).unwrap_or("")
                            ))
                            .unwrap();
                    }
                    io::Write::write(&mut cursor, b"\r\n").unwrap();
                    initlen = cursor.position() - n as u64 + (end - start) as u64;
                    let n = cursor.position();
                    let mut outbuf = cursor.into_inner();
                    unsafe { outbuf.set_len(n as usize) };
                    outbuf.extend_from_slice(&buf[start..end]);
                    trace!("sending request: {:?}", std::str::from_utf8(&outbuf));
                    if pool.is_some() {
                        (Some(outbuf), false, None)
                    } else {
                        let mut snowys = connector
                            .connect()
                            .await
                            .context("failed to establish snowy tunnel")?;
                        snowys.write_all(&outbuf).await?;
                        (None, true, Some(snowys))
                    }
                }
                method => {
                    inbound.write_all(HTTP_405_METHOD_NOT_ALLOWED).await?;
                    return Err(anyhow!("unspported HTTP method: {}", method));
                }
            };
        }
    };
    let _t = Instant::now();
    let relay = if let Some(mut outbound) = outbound {
        relay_tcp_with(&mut inbound, &mut outbound, outbuf).await
    } else {
        relay_tcp_remote(
            &mut inbound,
            connector,
            pool,
            endpoint,
            fallback_tracker,
            outbuf,
        )
        .await
    };
    log_relay!(async {
        relay.map(|(tx, rx)| (tx + if connect_sent_direct { initlen } else { 0 }, rx))
    });
    Ok(())
}

async fn relay_tcp_remote(
    inbound: &mut TcpStream,
    connector: Arc<impl Connector + 'static>,
    pool: Option<Arc<SessionPool>>,
    endpoint: String,
    fallback_tracker: Arc<FallbackTracker>,
    outbuf: Option<Vec<u8>>,
) -> Result<(u64, u64)> {
    if let Some(pool) = pool {
        match relay_tcp_reusable(inbound, &pool, outbuf.clone()).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                SessionEvent::FallbackToOneShot.emit();
                fallback_tracker.warn_fallback(&endpoint);
                warn!(error = %format!("{:#}", error), "reusable session failed before payload; retrying one-shot");
            }
        }
    }

    let mut outbound = connector
        .connect()
        .await
        .context("failed to establish snowy tunnel")?;
    relay_tcp_with(inbound, &mut outbound, outbuf).await
}

async fn relay_tcp_reusable(
    inbound: &mut TcpStream,
    pool: &SessionPool,
    outbuf: Option<Vec<u8>>,
) -> Result<(u64, u64)> {
    let mut session = pool
        .checkout()
        .await
        .context("failed to checkout reusable session")?;
    let negotiated = if session.reuse_count == 0 {
        match negotiate_client(&mut session.stream, Capabilities::new(CAP_REUSE)).await {
            Ok(capabilities) if capabilities.reuse => true,
            Ok(capabilities) => {
                pool.return_session(session, false).await.ok();
                return Err(anyhow!(
                    "server negotiated without reuse capability: {:?}",
                    capabilities
                ));
            }
            Err(error) => {
                pool.return_session(session, false).await.ok();
                return Err(anyhow!("reusable session negotiation failed: {:?}", error));
            }
        }
    } else {
        false
    };
    debug!(
        negotiated,
        reuse_count = session.reuse_count,
        "checked out reusable session"
    );

    let request = open_request_from_trojan_header(outbuf.as_deref())?;
    if let Err(error) = write_frame(&mut session.stream, &request).await {
        pool.return_session(session, false).await.ok();
        return Err(anyhow!(error).context("failed to send reusable open request"));
    }

    let relay_result = relay_tcp_frames(inbound, &mut session, outbuf).await;
    let healthy = relay_result.is_ok();
    pool.return_session(session, healthy).await.ok();
    relay_result
}

fn open_request_from_trojan_header(outbuf: Option<&[u8]>) -> Result<Frame> {
    let outbuf = outbuf.context("reusable tcp relay requires an encoded trojan request")?;
    let cmd = outbuf[0];
    let atyp = outbuf[1];
    let (addr_start, addr_end, port_start) = match atyp {
        0x01 => (2, 6, 6),
        0x04 => (2, 18, 18),
        0x03 => {
            let len = outbuf[2] as usize;
            (3, 3 + len, 3 + len)
        }
        _ => {
            return Err(anyhow!(
                "unsupported address type in trojan request: {atyp}"
            ))
        }
    };
    ensure!(
        outbuf.len() >= port_start + 2,
        "truncated trojan request header"
    );
    let port = u16::from_be_bytes([outbuf[port_start], outbuf[port_start + 1]]);
    Ok(Frame::OpenRequest {
        cmd,
        atyp,
        addr: outbuf[addr_start..addr_end].to_vec(),
        port,
    })
}

async fn relay_tcp_frames(
    inbound: &mut TcpStream,
    session: &mut PooledSession,
    outbuf: Option<Vec<u8>>,
) -> Result<(u64, u64)> {
    let mut tx = 0u64;
    let mut rx = 0u64;
    if let Some(mut outbuf) = outbuf {
        let header_len = trojan_header_len(&outbuf)?;
        let mut offset = outbuf.len();
        if offset < MAX_FIRST_PACKET_SIZE {
            outbuf.reserve_exact(MAX_FIRST_PACKET_SIZE - offset);
            unsafe { outbuf.set_len(MAX_FIRST_PACKET_SIZE) };
            if let Ok(Ok(n)) =
                timeout(FIRST_PACKET_TIMEOUT, inbound.read(&mut outbuf[offset..])).await
            {
                offset += n;
            }
        }
        if offset > header_len {
            let data = outbuf[header_len..offset].to_vec();
            tx += data.len() as u64;
            write_frame(&mut session.stream, &Frame::Data(data)).await?;
        }
    }

    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound);
    let (mut session_r, mut session_w) = tokio::io::split(&mut session.stream);
    let mut buf = vec![0u8; 16 * 1024];
    let mut client_closed = false;
    loop {
        tokio::select! {
            read = inbound_r.read(&mut buf), if !client_closed => {
                let n = read.context("failed to read inbound client data")?;
                if n == 0 {
                    client_closed = true;
                    write_frame(&mut session_w, &Frame::EndRequest { reason: CloseReason::ClientClose as u8 }).await?;
                } else {
                    tx += n as u64;
                    write_frame(&mut session_w, &Frame::Data(buf[..n].to_vec())).await?;
                }
            }
            frame = read_frame(&mut session_r) => {
                match frame? {
                    Frame::Data(data) => {
                        rx += data.len() as u64;
                        inbound_w.write_all(&data).await.context("failed to write framed server data to inbound client")?;
                    }
                    Frame::EndRequest { .. } => break,
                    Frame::Reset { reason } => return Err(anyhow!("reusable request reset by server: {reason}")),
                    Frame::Close { reason } => return Err(anyhow!("reusable session closed by server: {reason}")),
                    Frame::Ping { token } => write_frame(&mut session_w, &Frame::Pong { token }).await?,
                    frame => return Err(anyhow!("unexpected reusable relay frame: {:?}", frame)),
                }
            }
        }
    }
    Ok((tx, rx))
}

fn trojan_header_len(outbuf: &[u8]) -> Result<usize> {
    ensure!(outbuf.len() >= 4, "truncated trojan header");
    let addr_len = match outbuf[1] {
        0x01 => 4,
        0x04 => 16,
        0x03 => outbuf[2] as usize + 1,
        atyp => {
            return Err(anyhow!(
                "unsupported address type in trojan request: {atyp}"
            ))
        }
    };
    let len = 1 + 1 + addr_len + 2 + 2;
    ensure!(outbuf.len() >= len, "truncated trojan header");
    Ok(len)
}

// TODO: bullshit API design
#[instrument(name = "tcp_relay", skip(inbound, outbound, outbuf), fields(
    %local_out = outbound.as_inner().local_addr().unwrap(),
    // %remote = outbound.as_inner().peer_addr().unwrap(),
))]
async fn relay_tcp_with(
    mut inbound: &mut TcpStream,
    mut outbound: &mut SnowyStream,
    outbuf: Option<Vec<u8>>,
) -> Result<(u64, u64)> {
    debug!(outbuf_len = outbuf.as_ref().map(|b| b.len()), "starting");
    // Ref: https://github.com/trojan-gfw/trojan/blob/304054008bb01d6aad51c477b6b7d4e79a5853db/src/session/clientsession.cpp#L194
    // Try to send the request header in outbuf, if any, along with the first inbound packet to
    // prevent traffic from being distinguished by TLS frame size.
    // This assumes client typically send before reading data after a connection is established.
    // Set a timeout in case client expects receiving at first.
    let mut initlen = 0;
    if let Some(mut outbuf) = outbuf {
        let mut offset = outbuf.len();
        outbuf.reserve_exact(MAX_FIRST_PACKET_SIZE - outbuf.len());
        unsafe { outbuf.set_len(MAX_FIRST_PACKET_SIZE) };
        let t = Instant::now();
        match timeout(FIRST_PACKET_TIMEOUT, inbound.read(&mut outbuf[offset..])).await {
            Ok(r) => {
                initlen = r.context("failed to read initial inbound data")?;
                trace!(
                    data_len = initlen,
                    "received initial data after {}",
                    t.elapsed().autofmt()
                );
                offset += initlen;
            }
            _ => trace!("timeout waiting initial data"),
        }
        outbound
            .write_all(&outbuf[..offset])
            .await
            .context("failed to write request header together with initial inbound data")?;
    }
    let (tx, rx) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok((tx + initlen as u64, rx))
}

#[instrument(name = "udp_relay", skip(inbound_tcp, inbound, outbound, header), fields(
    %client_udp_nominal = header.dest_addr,
    %local_in_udp = inbound.local_addr().unwrap(),
    %local_out = outbound.as_inner().local_addr().unwrap(),
    // %remote = outbound.as_inner().peer_addr().unwrap(),
))]
async fn relay_udp_with(
    inbound_tcp: &mut TcpStream,
    inbound: &mut UdpSocket,
    outbound: &mut SnowyStream,
    header: TrojanLikeRequest,
) -> Result<(u64, u64)> {
    debug!("starting");
    let (outr, outw) = tokio::io::split(outbound);
    let mut outr = BufReader::new(outr);
    let mut outw = BufWriter::new(outw);
    // Send trojan request header along with the first packet.
    // NOTE: this effectively limit the max size of the first packet to be MAX_DATAGRAM_SIZE -
    // outbuf.len()
    header.write(&mut outw).await?;
    let mut tx = 0;
    let mut rx = 0;
    let atob = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) };
        loop {
            let (n, client_addr) = inbound.recv_from(&mut buf).await?;
            if inbound.peer_addr().is_err() {
                // associate the addr per the first packet, since the inbound may be behind NAT
                trace!(client_udp = %inbound.peer_addr()?, "UDP associated");
                inbound.connect(&client_addr).await?;
            }
            if buf[2] != 0 {
                // rejects fragments for simplicity
                continue;
            }
            let dest_addr = socks5::Address::read_from(&mut io::Cursor::new(&buf[3..n]))?;
            let addrlen = dest_addr.serialized_len().unwrap();

            // When sending udp packet from server to client, addr is the original address that the
            // UDP socket on server received.
            trace!(%dest_addr, len = n, "sending a UDP packet");
            outw.send_to(&buf[3 + addrlen..n], dest_addr).await?;
            outw.flush().await?;
            tx += n as u64;
        }
    };
    let btoa = async {
        let mut buf = unsafe { vec_uninit(MAX_DATAGRAM_SIZE) }; // + header?
        loop {
            let (n, orig_addr) = match outr.recv_from(&mut buf).await? {
                Some(inner) => inner,
                None => return Ok(()),
            };
            trace!(%orig_addr, len = n, "receiving a UDP packet");
            let addrlen = orig_addr.serialized_len().unwrap();
            buf.copy_within(0..n, 2 + 1 + addrlen);
            buf[0..3].copy_from_slice(&[0x00, 0x00, 0x00]);
            orig_addr
                .write_to(&mut Cursor::new(&mut buf[3..3 + addrlen]))
                .unwrap();
            inbound.send(&buf[..3 + n + addrlen]).await?;
            rx += n as u64;
        }
    };
    let f = async {
        let r: (Result<()>, Result<()>) = tokio::join!(atob, btoa);
        r
    };
    // keep relaying as long as the TCP control connection is active
    tokio::select! {
        r = inbound_tcp.read_u8() => match r {
            Ok(_) => Err(anyhow!("unexpected data received from tcp connection")),
            Err(e) => match e.kind() {
                io::ErrorKind::UnexpectedEof => Ok((tx, rx)),
                _ => Err(e).context("control connection terminated")
            }
        },
        (r1, r2) = f => match (r1, r2) {
            (Err(e), _) => Err(e).context("error when forward data from peer to remote"),
            (_, Err(e)) => Err(e).context("error when forward data from remote to peer"),
            _ => unreachable!()
        }
    }
}

macro_rules! log_relay {
    ($fut: expr) => {
        let t = Instant::now();
        match $fut.await
        {
            Ok((tx, rx)) => {
                info!(
                    tx,
                    rx,
                    "relay closed after {}",
                    t.elapsed().autofmt(),
                );
            }
            Err(error) => {
                warn!(
                    error = %format!("{:#}", error),
                    "relay terminated after {}",
                    t.elapsed().autofmt(),
                );
            }
        }
    }
}
use log_relay;
