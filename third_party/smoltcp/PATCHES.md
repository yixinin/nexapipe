# Vendored smoltcp (0.12.0) — local patch

This directory is a vendored copy of `smoltcp` 0.12.0 from crates.io, wired in via
`[patch.crates-io]` in the workspace root `Cargo.toml`.

## Why

Without the patch, real-world TCP traffic through the Android TUN proxy can trigger:

```
RUST PANIC: attempt to subtract sequence numbers with underflow
  at smoltcp-0.12.0/src/wire/tcp.rs:81:13
```

The panic comes from the unguarded `self.remote_last_seq - self.local_seq_no`
subtraction in the TCP transmit path (`socket/tcp.rs`). When the remote ACKs
beyond what we have sent (possible with retransmissions / stale segments), the
sequence subtraction underflows and panics, killing the smoltcp stack task and
tearing down the whole TUN tunnel a few seconds after connecting.

## Local changes vs upstream 0.12.0

- `src/socket/tcp.rs` (transmit path): guard the `remote_last_seq - local_seq_no`
  subtraction so an underflow yields `0` (nothing new to send) instead of panicking.
- `src/socket/tcp.rs` (trace log): the same subtraction is repeated in a `tcp_trace!`;
  it now uses the same guarded expression.

Everything else is byte-for-byte upstream 0.12.0.
