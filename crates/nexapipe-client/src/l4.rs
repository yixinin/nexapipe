//! Client side of the L4 tunnel: TCP and UDP to a route's backend.
//!
//! # Why a preface and not a `CONNECT` line
//!
//! The desktop TUN used to write `CONNECT host:port HTTP/1.1` as the first bytes of the
//! bi-stream. Nothing on the server understood that: the bytes were parsed as an HTTP
//! request, the path came out empty, no route matched, and the stream was forwarded to
//! `default_backend`. Two things were wrong with it — the port was thrown away, so only
//! 443 ever worked, and a failure looked like success.
//!
//! The tunnel now starts with a [`Preface`] that states the protocol, the host and the
//! port, and the server answers with exactly one [`Status`] byte before any payload. The
//! client can tell "no route" from "backend down", and the server never guesses.
//!
//! # Who decides the destination
//!
//! The client asks for a host name and a port; **the route on the server decides which
//! address is dialled** (see the server's `l4` module). A client that holds 2FA
//! credentials therefore cannot use the server as an open relay.
//!
//! # Framing
//!
//! * TCP: raw bytes in both directions.
//! * UDP: one datagram per [`nexapipe_proto::encode_frame`] frame, because a QUIC
//!   bi-stream has no message boundaries of its own.

use crate::ClientError;
use crate::endpoint_group::{EndpointGroup, PooledConnection};
use crate::local_proxy::open_stream_with_retry;
use iroh::endpoint::{RecvStream, SendStream};
use std::sync::Arc;
use std::time::Duration;

pub use nexapipe_proto::{L4Proto, Preface, Status};

/// How long the server may take to answer the preface.
///
/// Generous on purpose: the server has to resolve and dial the backend before it can
/// answer, and a cold database connection is slow.
const STATUS_TIMEOUT: Duration = Duration::from_secs(30);

/// Open a TCP flow to `host:port`.
///
/// Returns the pooled connection together with the stream. The caller owns the pooled
/// connection for the life of the tunnel and must hand it back with
/// [`EndpointGroup::return_connection`] — unlike the HTTP paths, an L4 flow can last
/// minutes, so it cannot be returned as soon as the first response arrives.
pub async fn open_tcp(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    port: u16,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    open(endpoint_group, L4Proto::Tcp, host, port).await
}

/// Open a UDP flow to `host:port`.
///
/// The tunnel carries datagrams as length-prefixed frames; see [`nexapipe_proto`].
pub async fn open_udp(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    port: u16,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    open(endpoint_group, L4Proto::Udp, host, port).await
}

/// Write the preface and wait for the server's answer, on a stream the caller opened.
///
/// Separate from [`open_tcp`] for callers that manage their own connection instead of
/// using the pool — the desktop TUN owns its iroh connection directly. Either way the
/// preface and the status byte are handled in exactly one place, so both paths agree on
/// the wire format and on what a refusal means.
pub async fn handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
    proto: L4Proto,
    host: &str,
    port: u16,
) -> Result<(), ClientError> {
    let preface = Preface::new(proto, host, port).to_bytes().map_err(|e| {
        ClientError::InvalidConfig(format!("cannot ask the server for {host}:{port}: {e}"))
    })?;

    send.write_all(&preface).await?;

    let status = read_status(recv, proto, host, port).await?;
    if status.is_ok() {
        Ok(())
    } else {
        Err(status_error(status, proto, host, port))
    }
}

async fn open(
    endpoint_group: &Arc<EndpointGroup>,
    proto: L4Proto,
    host: &str,
    port: u16,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    let preface = Preface::new(proto, host, port).to_bytes().map_err(|e| {
        ClientError::InvalidConfig(format!("cannot ask the server for {host}:{port}: {e}"))
    })?;

    let mut last_err: Option<ClientError> = None;

    // The retry exists for the same reason it does on the HTTP path: a pooled connection
    // may have been closed by the peer without anything noticing, and the failure only
    // shows up on the first write or read. A refusal is final and breaks out early.
    for _attempt in 1..=crate::local_proxy::OPEN_ATTEMPTS {
        // `send` stays untouched: the caller writes the payload once the server has
        // accepted the flow, so nothing is pipelined behind the preface.
        let (pooled, send, mut recv) =
            open_stream_with_retry(endpoint_group, host, Some(&preface)).await?;

        match read_status(&mut recv, proto, host, port).await {
            Ok(status) if status.is_ok() => return Ok((pooled, send, recv)),
            Ok(status) => {
                // The server understood us and said no. Retrying the same request on a
                // fresh connection cannot change the answer.
                endpoint_group.return_connection(host, pooled).await;
                return Err(status_error(status, proto, host, port));
            }
            Err(e) => {
                endpoint_group.return_connection(host, pooled).await;
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or(ClientError::TimeoutError))
}

/// Read the single status byte, mapping a missing or late one to a readable error.
///
/// Uses `read`, not `read_exact`: a `RecvStream` read is documented as cancel-safe while
/// `read_exact` is documented as *not* being one, and this call sits inside a timeout. A
/// timeout that fired after `read_exact` had already consumed the byte would leave the
/// next attempt reading a payload byte as if it were a status.
async fn read_status(
    recv: &mut RecvStream,
    proto: L4Proto,
    host: &str,
    port: u16,
) -> Result<Status, ClientError> {
    let mut byte = [0u8; 1];
    let unannounced = |detail: String| {
        ClientError::ReceiveError(format!(
            "the server closed the {} tunnel to {host}:{port} before answering{detail}",
            proto.name()
        ))
    };

    match tokio::time::timeout(STATUS_TIMEOUT, recv.read(&mut byte)).await {
        Ok(Ok(Some(1))) => Ok(Status::from_byte(byte[0])),
        // Zero bytes with a one-byte buffer: the peer finished the stream without
        // saying anything about the flow.
        Ok(Ok(_)) => Err(unannounced(String::new())),
        Ok(Err(e)) => Err(unannounced(format!(": {e}"))),
        Err(_) => Err(ClientError::TimeoutError),
    }
}

/// Turn a refusal into an error that says what to do about it.
///
/// `NoRoute` and `BackendFailed` are deliberately different: the first is a
/// configuration mistake (nobody added a route for this host), the second is the
/// backend being down. Conflating them sends the reader looking in the wrong place.
fn status_error(status: Status, proto: L4Proto, host: &str, port: u16) -> ClientError {
    let detail = match status {
        Status::NoRoute => format!(
            "the server has no `mode = \"{}\"` route for {host}:{port}",
            proto.name().to_lowercase()
        ),
        Status::BackendFailed => format!(
            "the server could not reach the backend for {host}:{port} (route matched, dial failed)"
        ),
        Status::TooManyFlows => format!(
            "the server is already carrying as many flows on this connection as it allows, \
             so the flow to {host}:{port} was refused"
        ),
        Status::BadPreface => format!(
            "the server rejected the {} preface for {host}:{port}; \
             this client and that server disagree on the protocol version",
            proto.name()
        ),
        // Unreachable byte: a version mismatch is the realistic cause.
        Status::Unknown | Status::Ok => format!(
            "the server answered with an unrecognised status byte for {host}:{port}; \
             this client and that server disagree on the protocol version"
        ),
    };
    ClientError::ConnectionError(detail)
}

/// Parse the authority-form target of a `CONNECT` request (`host:port`, RFC 9110 §9.3.6).
///
/// A missing port is refused rather than defaulted. Defaulting is what made this branch
/// work only for 443: with no port on the wire there is nothing to route on, so the
/// request would land wherever the server's fallback points.
pub fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    let trimmed = target.trim();

    // IPv6 literals arrive bracketed, and the port separator is outside the brackets.
    let (host, port) = match trimmed.strip_prefix('[') {
        Some(rest) => rest.split_once("]:")?,
        None => trimmed.rsplit_once(':')?,
    };

    if host.is_empty() {
        return None;
    }
    // Port 0 is not a destination; refusing it here keeps the wire format honest.
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .map(|port| (host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexapipe_proto::PREFACE_MAGIC;

    #[test]
    fn parses_the_authority_form_a_client_sends() {
        assert_eq!(
            parse_connect_target("db.iroh.iakl.top:5432"),
            Some(("db.iroh.iakl.top".to_string(), 5432))
        );
        assert_eq!(
            parse_connect_target("10.0.0.50:443"),
            Some(("10.0.0.50".to_string(), 443))
        );
        // A bracketed IPv6 literal keeps its address and drops the brackets.
        assert_eq!(
            parse_connect_target("[2001:db8::1]:5432"),
            Some(("2001:db8::1".to_string(), 5432))
        );
        assert_eq!(
            parse_connect_target("  host.test:80  "),
            Some(("host.test".to_string(), 80))
        );
        assert_eq!(
            parse_connect_target("host.test:65535"),
            Some(("host.test".to_string(), 65535))
        );
    }

    #[test]
    fn a_target_without_a_usable_port_is_refused() {
        // The old code dropped the port and only ever worked on 443. Refusing is the
        // point: a portless CONNECT cannot be routed.
        for target in [
            "db.iroh.iakl.top",
            "db.iroh.iakl.top:",
            "db.iroh.iakl.top:notaport",
            "db.iroh.iakl.top:0",
            "db.iroh.iakl.top:70000",
            ":5432",
            "",
            "[2001:db8::1]",
        ] {
            assert_eq!(parse_connect_target(target), None, "target {target:?}");
        }
    }

    #[test]
    fn the_preface_starts_with_the_dispatch_byte() {
        // The server keys on this byte before it parses anything, so the client's first
        // byte has to be the one the dispatcher expects.
        let preface = Preface::new(L4Proto::Tcp, "db.test", 5432).to_bytes().unwrap();
        assert_eq!(preface[0], PREFACE_MAGIC);
    }

    #[test]
    fn refusals_say_which_kind_of_failure_it_was() {
        let tcp = L4Proto::Tcp;

        let no_route = status_error(Status::NoRoute, tcp, "db.test", 5432).to_string();
        assert!(no_route.contains("no `mode = \"tcp\"` route"), "{no_route}");
        assert!(no_route.contains("db.test:5432"), "{no_route}");

        let backend = status_error(Status::BackendFailed, tcp, "db.test", 5432).to_string();
        assert!(backend.contains("could not reach the backend"), "{backend}");

        let full = status_error(Status::TooManyFlows, tcp, "db.test", 5432).to_string();
        assert!(full.contains("as many flows on this connection"), "{full}");

        // A version mismatch is the realistic cause of these two, and saying so beats
        // "unexpected byte".
        for status in [Status::BadPreface, Status::Unknown] {
            let text = status_error(status, tcp, "db.test", 5432).to_string();
            assert!(text.contains("disagree on the protocol version"), "{text}");
        }

        let udp = status_error(Status::NoRoute, L4Proto::Udp, "turn.test", 3478).to_string();
        assert!(udp.contains("no `mode = \"udp\"` route"), "{udp}");
    }
}
