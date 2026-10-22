//! The TUN's per-packet cost — the path a phone pays for every packet.
//!
//! Five benches, from the inside out:
//!
//! - `dns_query`: the query the system resolver sends, answered from the
//!   virtual address pool. The path a name resolution takes.
//! - `ip_mapping`: the bookkeeping behind those answers — one address per
//!   domain, and the reverse lookup that turns a packet's destination back
//!   into a name.
//! - `packet_copy`: the allocation and the copy the answer's frame costs on
//!   its way to the stack, on its own so that its share of `tun_packet` is
//!   visible.
//! - `ip_mapping_concurrent`: the same lookup, looked up by several tasks at
//!   once, where the lock it takes is what the parallelism contends on.
//! - `tun_packet`: the whole path, with the query arriving as an IP packet on
//!   the TUN device and the answer leaving as one. The stack in the middle is
//!   smoltcp's; what is measured around it is ours.
//!
//! The TUN device is a `tokio::io::duplex` pair standing in for the fd, and
//! the iroh endpoint is bound locally, so the bench needs no network.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, criterion_group, criterion_main};
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_client::EndpointGroup;
use nexapipe_client::dns::UpstreamResolvers;
use nexapipe_client::lb::LoadBalancingStrategy;
use nexapipe_client::tun_proxy::{TunProxy, TunStackConfig, handle_dns_query};
use nexapipe_client::virtual_ip::IpMapping;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The address the system resolver is pointed at, on the block this branch
/// still hard-codes. It has to be the address the packets are sent to.
const DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);

/// The address the query appears to come from. The stack accepts a query from
/// anywhere (`any_ip`), so this only has to be a plausible one.
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 16);

/// The domain the queries ask for.
const DOMAIN: &str = "example.com";

/// How many frames the copy bench keeps alive at once.
///
/// The frames are freed outside the clock, so this is what keeps the memory
/// bounded: criterion runs the loop tens of millions of times, and a frame
/// per iteration would be gigabytes of it.
const FRAMES_PER_BATCH: u64 = 1024;

/// A DNS query for [DOMAIN]: 12 bytes of header, then the question.
fn dns_query() -> Vec<u8> {
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in DOMAIN.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    packet
}

/// The one's complement of the one's complement sum of the header's words.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for word in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The DNS query as the IP packet the TUN device would carry it in.
///
/// The IPv4 header's checksum is computed, because the stack checks it; the
/// UDP checksum is left at zero, which IPv4 allows and the stack accepts.
fn dns_packet(dns: &[u8]) -> Vec<u8> {
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut packet = Vec::with_capacity(total_len);

    packet.push(0x45); // version 4, header length 5 (20 bytes)
    packet.push(0x00); // DSCP / ECN
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // identification
    packet.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    packet.push(64); // TTL
    packet.push(17); // UDP
    packet.extend_from_slice(&[0, 0]); // checksum, filled in below
    packet.extend_from_slice(&CLIENT_IP.octets());
    packet.extend_from_slice(&DNS_IP.octets());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&40000u16.to_be_bytes()); // source port
    packet.extend_from_slice(&53u16.to_be_bytes()); // destination port
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // no UDP checksum
    packet.extend_from_slice(dns);
    packet
}

fn tun_pump(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("tun_pump");

    group.bench_function("dns_query", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let mapping = IpMapping::new();
                let domains = vec![DOMAIN.to_string()];
                let query = dns_query();
                // No upstream: a proxied name is never forwarded, so the
                // benchmark measures the hijack and not the network.
                let resolvers = UpstreamResolvers::new(
                    &[],
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let answer = handle_dns_query(&query, &domains, &resolvers, &mapping).await;
                    black_box(answer);
                }
                start.elapsed()
            })
        })
    });

    group.bench_function("ip_mapping", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let mapping = IpMapping::new();
                // The names are made before the clock starts: what is measured
                // is the mapping's work, not the allocation of a name. There
                // are more of them than the pool holds addresses, so the
                // eviction path is part of what is measured too.
                let names: Vec<String> = (0..512).map(|i| format!("host{i}.test")).collect();

                let start = std::time::Instant::now();
                for i in 0..iters {
                    let name = &names[(i % names.len() as u64) as usize];
                    let address = mapping.allocate(name);
                    let back = mapping.lookup_domain(&address);
                    black_box(back);
                }
                start.elapsed()
            })
        })
    });

    // The copy the TUN's inbound path makes for every packet: the bytes are
    // read into a buffer that is reused, and the stack is handed a **copy**,
    // because the frame it takes is a `Vec<u8>` of its own.
    //
    // It is here on its own so that its share of `tun_packet` is visible:
    // the whole path is measured above, and this is the part of it that the
    // allocator pays for. It is 0.24% of that path.
    group.bench_function("packet_copy", |b| {
        b.iter_custom(|iters| {
            let packet = dns_packet(&dns_query());
            let mut buf = vec![0u8; 1500];

            // The read into the buffer stands in for the fd's read, and it
            // happens before the copy the production path measures: the frame
            // is on its way to the stack by then, and the copy is what the
            // stack is handed. Timing it here would time two copies where the
            // path pays for one.
            buf[..packet.len()].copy_from_slice(&packet);

            // The frames are freed outside the clock, in batches: in the
            // production path the frame is handed to the stack and freed
            // there, and a free inside the loop would be a cost the path does
            // not pay at this point. The batch is what keeps the memory
            // bounded -- criterion runs this loop tens of millions of times,
            // and a frame per iteration would be gigabytes of it.
            let mut frames = Vec::with_capacity(FRAMES_PER_BATCH as usize);
            let mut elapsed = std::time::Duration::ZERO;
            let mut left = iters;
            while left > 0 {
                let batch = left.min(FRAMES_PER_BATCH);
                let start = std::time::Instant::now();
                for _ in 0..batch {
                    let frame = buf[..packet.len()].to_vec();
                    frames.push(frame);
                }
                elapsed += start.elapsed();
                // The frees are here, where the clock is not.
                black_box(&frames);
                frames.clear();
                left -= batch;
            }
            elapsed
        })
    });

    // The same mapping, looked up by several tasks at once.
    //
    // The lookup takes the mapping's lock, and it takes the **write** lock --
    // so two lookups cannot happen at the same time. That does not show up in
    // the single-task case above; it shows up here, where the work is the
    // same and the only difference is that it is concurrent.
    //
    // **A read lock was tried here, and it is worse.** Making the clock and
    // the "last used" atomic, so that the lookup needs no write lock, moves
    // two updates out of the (serialising) lock and into eight cores
    // contending for the same two cache lines: the measurement went from
    // 97 ns per lookup to 357 ns. The critical section is far too short for
    // the parallelism to pay for the contention, so the mapping keeps its
    // exclusive lock.
    //
    // The variant that number came from was a branch, and it is not a branch
    // any more: the figure is here because the decision is, and nobody can
    // re-run the other half of it.
    group.bench_function("ip_mapping_concurrent", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let mapping = Arc::new(IpMapping::new());
                let names: Vec<String> = (0..512).map(|i| format!("host{i}.test")).collect();
                // The addresses are shared rather than copied into each task,
                // so that the copy is not part of what the clock measures.
                let addresses: Arc<Vec<std::net::Ipv4Addr>> =
                    Arc::new(names.iter().map(|name| mapping.allocate(name)).collect());

                // How many lookups run at once.
                const TASKS: usize = 8;

                // The lookups are **split** between the tasks, so that the
                // number criterion reports is the time of one lookup -- the
                // same thing the single-task case above reports, and the two
                // can be compared.
                //
                // The split has to add up to `iters`: criterion divides the
                // elapsed time by the iteration count, so a divisor that did
                // not match the work would report a number that is not the
                // time of one lookup. The remainder goes to the first tasks,
                // because `iters` is not always a multiple of the task count
                // -- criterion's warm-up starts at one iteration.
                let per_task = iters / TASKS as u64;
                let remainder = iters % TASKS as u64;

                let start = std::time::Instant::now();
                let mut handles = Vec::with_capacity(TASKS);
                for task in 0..TASKS as u64 {
                    let mapping = mapping.clone();
                    let addresses = addresses.clone();
                    let count = per_task + u64::from(task < remainder);
                    handles.push(tokio::spawn(async move {
                        for i in 0..count {
                            let index = ((i + task) % addresses.len() as u64) as usize;
                            let back = mapping.lookup_domain(&addresses[index]);
                            black_box(back);
                        }
                    }));
                }
                for handle in handles {
                    let _ = handle.await;
                }
                start.elapsed()
            })
        })
    });

    group.bench_function("tun_packet", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let endpoint = Endpoint::builder(presets::N0)
                    .bind()
                    .await
                    .expect("binding a local endpoint needs no network");
                let group = Arc::new(
                    EndpointGroup::new_with_nodes_and_endpoint(
                        Vec::new(),
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        endpoint,
                    )
                    .await
                    .expect("a group with no backend still builds"),
                );

                // The TUN device: one end of a duplex pair stands in for the
                // fd, the other for the application.
                let (device, application) = tokio::io::duplex(64 * 1024);
                let (reader, writer) = tokio::io::split(device);
                let mapping = Arc::new(IpMapping::new());
                let proxy = TunProxy::with_io(
                    reader,
                    writer,
                    group,
                    vec![DOMAIN.to_string()],
                    Vec::new(),
                    TunStackConfig {
                        dns_ip: DNS_IP,
                        legacy_proxy_ip: None,
                        ip_mapping: mapping,
                        tcp_window: None,
                    },
                )
                .expect("the TUN proxy starts on a duplex pair");
                let mut application = application;

                let packet = dns_packet(&dns_query());
                let mut answer = vec![0u8; 1500];

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    application.write_all(&packet).await.unwrap();
                    let read = application.read(&mut answer).await.unwrap();
                    black_box(read);
                }
                let elapsed = start.elapsed();

                proxy.stop();
                elapsed
            })
        })
    });

    group.finish();
}

criterion_group!(benches, tun_pump);
criterion_main!(benches);
