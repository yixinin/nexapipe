//! The tests of the L4 tunnel.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::*;
use crate::config::RouteMode;
use crate::lb::LoadBalancingStrategy;
use crate::routes::{L4Options, Route};
use nexapipe_proto::{PREFACE_VERSION, encode_frame_to_vec};
use std::collections::HashMap;
use std::net::IpAddr;

fn tcp_route(host: &str, backend: &str) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Tcp,
        None,
    )
}

fn udp_route(host: &str, backend: &str, idle: Option<Duration>) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Udp,
        None,
    )
    .with_l4_options(L4Options {
        client_ports: None,
        idle_timeout: idle,
        flow_timeout: None,
    })
}

fn config_with(tcp_backend: &str, udp_backend: &str) -> RoutingTable {
    RoutingTable::new(vec![
        tcp_route("db.test", tcp_backend),
        udp_route("turn.test", udp_backend, None),
    ])
}

fn limiter() -> Arc<FlowLimiter> {
    Arc::new(FlowLimiter::new(DEFAULT_MAX_FLOWS_PER_CONNECTION))
}

fn preface(proto: L4Proto, host: &str, port: u16) -> Vec<u8> {
    Preface::new(proto, host, port).to_bytes().unwrap()
}

async fn read_status<R: AsyncRead + Unpin>(reader: &mut R) -> Status {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).await.expect("status byte");
    Status::from_byte(byte[0])
}

async fn read_udp_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await.expect("frame header");
    let mut body = vec![0u8; u16::from_be_bytes(header) as usize];
    reader.read_exact(&mut body).await.expect("frame body");
    body
}

#[tokio::test]
async fn tcp_flow_carries_bytes_both_ways() {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    let config = config_with(&backend_addr.to_string(), "127.0.0.1:1");
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    // Preface and first payload in one write, which is what a real client does.
    let mut payload = preface(L4Proto::Tcp, "db.test", 5432);
    payload.extend_from_slice(b"ping");
    client_write.write_all(&payload).await.unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::Ok);

    let mut echoed = [0u8; 4];
    client_read.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    drop(client_write);
    drop(client_read);
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the flow should end with the client")
        .unwrap();
    assert!(outcome.is_ok());
    echo.await.unwrap();
}

#[tokio::test]
async fn a_host_without_a_route_gets_no_route() {
    // The other route's backend is deliberately unreachable: if the lookup
    // served a host it has no route for, this test would fail with
    // BackendFailed instead of NoRoute.
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "not-configured.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
    assert!(task.await.unwrap().is_ok());
}

/// A restricted client asking for a host its allowlist never named gets the
/// same `NoRoute` an unconfigured host gets — a distinct status would let a
/// compromised client probe which hosts exist behind the tunnel.
#[tokio::test]
async fn a_host_off_the_clients_allowlist_answers_no_route() {
    use crate::auth::ClientAcl;

    // The route exists and its backend would answer; only the ACL refuses.
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let acl = ClientAcl::from_hosts(Some(&["elsewhere.test".to_string()]));
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            Some(&acl),
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
    assert!(task.await.unwrap().is_ok());
}

/// A client whose port list does not name the port it asked for is refused
/// the same way one asking for an off-list host is: `NoRoute`, not a
/// distinct status, so the answer cannot be used to probe which ports are
/// open behind the tunnel.
#[tokio::test]
async fn a_port_off_the_clients_port_list_answers_no_route() {
    use crate::auth::ClientAcl;

    // The route exists and its backend would answer; only the ACL refuses.
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[443]));
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            Some(&acl),
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
    assert!(task.await.unwrap().is_ok());
}

/// The list is held against the port the client names, and the route
/// decides where that service is answered from: `client_ports` only
/// selects the route, it never decides where the connection goes.
///
/// So the port the client named is the service it reached, and a client
/// whose list names that port reaches the service. The port the route
/// answers it from is the route's own business — the list says which
/// services the client may reach, not how the server reaches them.
#[tokio::test]
async fn the_port_the_client_names_is_the_port_the_list_is_held_against() {
    use crate::auth::ClientAcl;

    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    // The route answers from the backend's own port, and the preface names
    // another one: the port asked for is never the one dialled.
    let config = config_with(&backend_addr.to_string(), "127.0.0.1:1");
    let asked = backend_addr.port().wrapping_add(1).max(1);
    // The list names the port the client asks for, and not the one the
    // route would answer it from.
    let acl = ClientAcl::from_hosts_and_ports(None, Some(&[asked]));
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            Some(&acl),
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", asked))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::Ok);
    client_write.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client_read.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    drop(client_write);
    drop(client_read);
    task.await.unwrap().unwrap();
    echo.await.unwrap();
}

/// The allowlist check happens before the flow limiter too, so a client
/// probing off-list hosts cannot spend flow slots doing it. An on-list
/// host is unaffected and reaches its backend as usual.
#[tokio::test]
async fn an_allowed_host_reaches_its_backend_under_an_acl() {
    use crate::auth::ClientAcl;

    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    let config = config_with(&backend_addr.to_string(), "127.0.0.1:1");
    let acl = ClientAcl::from_hosts(Some(&["db.test".to_string()]));
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            Some(&acl),
            "test-request-id",
            // No handshake in this test: the ACL is handed in directly.
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::Ok);
    client_write.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client_read.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    drop(client_write);
    drop(client_read);
    task.await.unwrap().unwrap();
    echo.await.unwrap();
}

#[tokio::test]
async fn the_two_l4_modes_never_see_each_other() {
    // The same host name served by a `tcp` route must not answer a UDP flow: the
    // two modes are different services, not two spellings of one.
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Udp, "db.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::NoRoute);
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn the_configured_udp_idle_deadline_closes_a_silent_flow() {
    // The observation this test exists for: `l4_idle_secs` has to reach the
    // flow it names, not merely parse. A key resolved into `Deadlines` and
    // then read by nobody parses, validates and does nothing — which is
    // exactly the shape this wiring arrived in, so the assertion is on the
    // flow's lifetime, not on the config's arithmetic.
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                return;
            };
            let _ = udp.send_to(&buf[..n], from).await;
        }
    });

    // One second of silence closes the flow; the sixty-second default the
    // key overrides would not, so a regression back to the constant fails
    // this on its three-second outer bound.
    let mut timeouts = crate::config::Timeouts::resolve(crate::config::TimeoutsConfig::default());
    timeouts.deadlines.l4_idle = Duration::from_secs(1);
    let config = RoutingTable::with_timeouts(
        vec![udp_route("turn.test", &udp_addr.to_string(), None)],
        timeouts,
    );

    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
        .await
        .unwrap();
    assert_eq!(read_status(&mut client_read).await, Status::Ok);

    // One round trip proves the flow works, then the client goes silent.
    client_write
        .write_all(&encode_frame_to_vec(b"ping").unwrap())
        .await
        .unwrap();
    assert_eq!(read_udp_frame(&mut client_read).await, b"ping");

    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut [0u8; 1]),
    )
    .await;
    // EOF or an error both count as closed; only a hang fails.
    assert!(
        closed.is_ok(),
        "the flow must close within the configured idle deadline"
    );
    assert!(task.await.unwrap().is_ok());
    echo.abort();
}

#[tokio::test]
async fn an_unreachable_backend_answers_backend_failed() {
    // Port 1 on loopback: nothing listens there, so connect is refused immediately.
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::BackendFailed);
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn a_preface_from_a_newer_client_answers_bad_preface() {
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&[
            PREFACE_MAGIC,
            PREFACE_VERSION + 1,
            0x01,
            4,
            b'h',
            b'o',
            b's',
            b't',
        ])
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::BadPreface);
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn udp_flow_forwards_datagrams_in_both_directions() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        for _ in 0..2 {
            let (n, from) = backend.recv_from(&mut buf).await.unwrap();
            backend.send_to(&buf[..n], from).await.unwrap();
        }
    });

    let config = config_with("127.0.0.1:1", &backend_addr.to_string());
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    // Preface and the first datagram in one write: the datagram must not be lost
    // to the handshake.
    let mut first = preface(L4Proto::Udp, "turn.test", 3478);
    first.extend_from_slice(&encode_frame_to_vec(b"one").unwrap());
    client_write.write_all(&first).await.unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::Ok);
    assert_eq!(read_udp_frame(&mut client_read).await, b"one");

    // A later datagram is framed the same way.
    client_write
        .write_all(&encode_frame_to_vec(b"two").unwrap())
        .await
        .unwrap();
    assert_eq!(read_udp_frame(&mut client_read).await, b"two");

    // Both halves have to go: with `tokio::io::split` each holds an `Arc` to the same
    // stream, so dropping only one of them signals nothing to the peer.
    drop(client_write);
    drop(client_read);
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the flow should end when the client closes")
        .unwrap();
    assert!(outcome.is_ok());
    echo.await.unwrap();
}

#[tokio::test]
async fn udp_flow_ends_when_nobody_sends_anything() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();

    let idle = Duration::from_millis(150);
    let config = RoutingTable::new(vec![udp_route(
        "turn.test",
        &backend_addr.to_string(),
        Some(idle),
    )]);

    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    client
        .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
        .await
        .unwrap();
    assert_eq!(read_status(&mut client).await, Status::Ok);

    // Neither side sends anything after that, so the idle timeout has to be what
    // ends the flow — and the client has to see a clean end of stream, not a reset.
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "the flow must end without payload");

    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the idle timeout should end the flow")
        .unwrap();
    assert!(outcome.is_ok());
}

#[tokio::test]
async fn a_udp_flow_ends_when_it_has_run_for_its_flow_timeout() {
    // The gap the idle bound cannot close: a peer that keeps a datagram
    // moving faster than `idle` never trips it, so without a bound on the
    // whole flow this datagram loop would hold the slot and the task forever.
    // The idle here is generous and the flow timeout is short, which is the
    // only arrangement in which the flow bound is what ends it.
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();

    let idle = Duration::from_secs(30);
    let flow = Duration::from_millis(300);
    let config = RoutingTable::new(vec![
        Route::new(
            "turn.test",
            "/",
            true,
            vec![backend_addr.to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Udp,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: None,
            idle_timeout: Some(idle),
            flow_timeout: Some(flow),
        }),
    ]);

    let (mut client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    client
        .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
        .await
        .unwrap();
    assert_eq!(read_status(&mut client).await, Status::Ok);

    // Keep sending well inside the idle window for longer than the flow
    // budget, so only the flow deadline can end this.
    let started = std::time::Instant::now();
    let mut kept_alive = 0;
    while started.elapsed() < Duration::from_millis(250) {
        client
            .write_all(&encode_frame_to_vec(b"tick").unwrap())
            .await
            .unwrap();
        kept_alive += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(kept_alive > 1, "the flow really was still being renewed");

    // And it does end, on the flow budget rather than on anything else.
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("the flow timeout should end the flow");
    assert!(read.is_ok());

    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the flow should have ended on its own")
        .unwrap();
    assert!(outcome.is_ok());
}

#[tokio::test]
async fn a_full_connection_answers_too_many_flows() {
    let config = config_with("127.0.0.1:1", "127.0.0.1:1");
    let full = Arc::new(FlowLimiter::new(0));
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &full,
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
        .await
        .unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::TooManyFlows);
    assert!(task.await.unwrap().is_ok());
}

#[test]
fn the_flow_limiter_refuses_past_its_ceiling_and_releases_on_drop() {
    let limiter = Arc::new(FlowLimiter::new(2));

    let first = limiter.try_acquire().expect("first flow fits");
    let second = limiter.try_acquire().expect("second flow fits");
    assert_eq!(limiter.current(), 2);
    assert!(
        limiter.try_acquire().is_none(),
        "the third flow must be refused"
    );

    drop(first);
    assert_eq!(limiter.current(), 1);
    let third = limiter.try_acquire().expect("the freed slot is reusable");
    assert_eq!(limiter.max(), 2);
    drop(second);
    drop(third);
    assert_eq!(limiter.current(), 0);
}

#[test]
fn only_the_preface_magic_is_an_l4_stream() {
    assert!(is_l4_stream(PREFACE_MAGIC));
    assert!(!is_l4_stream(0x16));
    assert!(!is_l4_stream(b'G'));
}

#[test]
fn backend_addresses_need_a_port() {
    assert_eq!(
        parse_backend_addr("10.0.0.50:5432"),
        Some(("10.0.0.50".to_string(), 5432))
    );
    assert_eq!(
        parse_backend_addr("tcp://db.internal:5432"),
        Some(("db.internal".to_string(), 5432))
    );
    assert_eq!(
        parse_backend_addr("udp://turn.internal:3478"),
        Some(("turn.internal".to_string(), 3478))
    );
    // No fallback port: an L4 target that does not say which port to dial is a
    // configuration mistake, not something to guess at.
    assert_eq!(parse_backend_addr("db.internal"), None);
    assert_eq!(parse_backend_addr("http://db.internal"), None);
    assert_eq!(parse_backend_addr(":5432"), None);
    assert_eq!(parse_backend_addr(""), None);
}

/// An address that refuses the connection: a port that was bound and
/// released, so nothing is listening on it any more.
async fn refusing_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test]
async fn the_dial_tries_the_next_address_when_the_first_refuses() {
    // A backend with two addresses: the first refuses, the second
    // accepts. The dial has to get to the second one — that is what
    // `TcpStream::connect((host, port))` did, and what the hand-written
    // dial has to keep doing.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let accepting = listener.local_addr().unwrap();
    let refused = refusing_addr().await;

    let started = std::time::Instant::now();
    let stream = crate::backend_conn::connect_addrs(
        &[refused, accepting],
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .expect("the second address should have been tried");

    assert_eq!(
        stream.peer_addr().unwrap(),
        accepting,
        "the dial should have ended on the address that accepted"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the second address is inside the same deadline, not a new one, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_spent_deadline_is_not_waited_for_once_per_address() {
    // The deadline has passed: every attempt is over before it starts, so
    // the dial gives up at once instead of waiting once per address.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let accepting = listener.local_addr().unwrap();

    let started = std::time::Instant::now();
    let error = crate::backend_conn::connect_addrs(
        &[accepting, accepting, accepting],
        tokio::time::Instant::now() - Duration::from_secs(1),
    )
    .await
    .expect_err("the deadline has passed");

    assert!(
        started.elapsed() < Duration::from_millis(500),
        "a spent deadline must not be waited for once per address, took {:?}",
        started.elapsed()
    );
    assert!(
        error.to_string().contains("the connect budget was spent"),
        "the error should say the budget was spent, got {error}"
    );
    // The addresses that were not reached are named too, so an operator can
    // see which one the dial never got to.
    assert!(
        error.to_string().contains(&accepting.to_string()),
        "the error should name the address that was not reached, got {error}"
    );
}

#[tokio::test]
async fn a_dial_to_an_address_that_refuses_says_which_one() {
    let refused = refusing_addr().await;

    let error = crate::backend_conn::connect_addrs(
        &[refused],
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .expect_err("nothing is listening on that port");

    assert!(
        error.to_string().contains(&refused.to_string()),
        "the error should name the address that failed, got {error}"
    );
}

/// A resolver the test can steer.
///
/// A name it knows is answered from the table; anything else is the
/// system's business, so a test that has it installed cannot disturb the
/// tests that run beside it.
struct StubResolver {
    answers: std::sync::Mutex<HashMap<String, Vec<IpAddr>>>,
}

impl StubResolver {
    fn new() -> Self {
        Self {
            answers: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Changes what the name resolves to, the way a DNS record moves.
    fn set(&self, host: &str, addrs: Vec<IpAddr>) {
        self.answers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(host.to_string(), addrs);
    }
}

impl crate::dns::Resolve for StubResolver {
    fn resolve(&self, host: &str) -> Result<Vec<SocketAddr>, crate::dns::ResolveError> {
        let known = self
            .answers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(host)
            .cloned();
        match known {
            Some(addrs) => Ok(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect()),
            // Everything else is the system's business.
            None => crate::dns::SystemResolver.resolve(host),
        }
    }
}

/// A UDP flow does not use an address the cache is holding.
///
/// The cache is for the paths that dial: a TCP dial to an address that
/// has gone away is refused, and the flow fails with it. A UDP flow has
/// **no dial** — `connect` on a UDP socket is local, so it cannot tell
/// that the peer is gone — and a datagram sent to an address that is no
/// longer there is dropped without a word. So a UDP flow resolves its
/// target every time it opens, and the address the cache is holding is
/// not the one it uses.
#[tokio::test]
async fn a_udp_flow_does_not_use_a_stale_address() {
    // The backend that answers: a UDP echo on the loopback.
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, from) = backend.recv_from(&mut buf).await.unwrap();
        backend.send_to(&buf[..n], from).await.unwrap();
    });

    // The name resolves to an address where nobody is listening, and to
    // the backend after that: the address the cache is holding is one
    // the flow must not use.
    let stub = Arc::new(StubResolver::new());
    stub.set("udp.test", vec![IpAddr::from([127, 0, 0, 2])]);
    let _resolver = crate::dns::swap_resolver(stub.clone());

    // The cache is given the address nobody is listening on, the way a
    // flow that resolved the name a moment ago would have left it.
    let cached = crate::dns::resolve("udp.test")
        .await
        .expect("the name resolves");
    assert_eq!(
        cached,
        vec![SocketAddr::new(IpAddr::from([127, 0, 0, 2]), 0)]
    );

    // And now the name resolves to the backend.
    stub.set("udp.test", vec![IpAddr::from([127, 0, 0, 1])]);

    let backend = format!("udp.test:{}", backend_addr.port());
    let config = RoutingTable::new(vec![udp_route("udp.test", &backend, None)]);
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let mut first = preface(L4Proto::Udp, "udp.test", 3478);
    first.extend_from_slice(&encode_frame_to_vec(b"one").unwrap());
    client_write.write_all(&first).await.unwrap();

    assert_eq!(read_status(&mut client_read).await, Status::Ok);
    // The datagram has to come back from the backend. Before the fix the
    // flow was pointed at the address the cache was holding, so nothing
    // came back and the flow ended instead.
    let echoed = tokio::time::timeout(Duration::from_secs(5), read_udp_frame(&mut client_read))
        .await
        .expect("the echo should come back");
    assert_eq!(echoed, b"one");

    drop(client_write);
    drop(client_read);
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the flow should end when the client closes")
        .unwrap();
    assert!(outcome.is_ok());
    echo.await.unwrap();
}

/// A TCP flow and a UDP flow, side by side: the copy buffers of the first are
/// charged to the process byte budget, the second's 64 KiB receive buffer is
/// not.
#[tokio::test]
async fn a_udp_flow_holds_no_bytes_against_the_process_budget() {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await.unwrap();
        let mut buf = [0u8; 64];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });
    let udp_backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp_backend.local_addr().unwrap();
    let udp_echo = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = udp_backend.recv_from(&mut buf).await else {
                return;
            };
            udp_backend.send_to(&buf[..n], from).await.unwrap();
        }
    });

    let budget = crate::conn::limits::body_budget();
    let base = budget.held();

    // --- a TCP flow ---
    let config = RoutingTable::new(vec![tcp_route("db.test", &backend_addr.to_string())]);
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });
    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Tcp, "db.test", 5432))
        .await
        .unwrap();
    assert_eq!(read_status(&mut client_read).await, Status::Ok);
    client_write.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client_read.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    let during_tcp = budget.held() - base;
    assert_eq!(
        during_tcp,
        2 * crate::stream_util::COPY_BUF_SIZE,
        "a TCP flow is charged for its two copy buffers"
    );
    drop(client_write);
    drop(client_read);
    task.await.unwrap().unwrap();
    echo.abort();

    // --- a UDP flow ---
    let base = budget.held();
    let config = RoutingTable::new(vec![udp_route(
        "turn.test",
        &udp_addr.to_string(),
        Some(Duration::from_secs(2)),
    )]);
    let (client, server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        serve_stream(
            server,
            Vec::new(),
            &config,
            &limiter(),
            "test",
            None,
            "test-request-id",
            None,
        )
        .await
    });
    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&preface(L4Proto::Udp, "turn.test", 3478))
        .await
        .unwrap();
    assert_eq!(read_status(&mut client_read).await, Status::Ok);
    client_write
        .write_all(&encode_frame_to_vec(b"ping").unwrap())
        .await
        .unwrap();
    assert_eq!(read_udp_frame(&mut client_read).await, b"ping");
    let during_udp = budget.held() - base;
    assert_eq!(
        during_udp, 0,
        "a UDP flow holds a 64 KiB receive buffer and is charged nothing"
    );
    drop(client_write);
    drop(client_read);
    let _ = task.await;
    udp_echo.abort();
}
