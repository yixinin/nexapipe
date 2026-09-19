//! Byte-stream plumbing shared by the two paths that move opaque bytes.
//!
//! TLS passthrough and the L4 tunnel both end up doing the same two things: presenting
//! an iroh bi-stream as one duplex object, and copying bytes both ways until one side
//! stops. They differ only in what they do *before* that point — SNI sniffing versus
//! preface decoding — so that part stays in each module.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Read size for the copy loops. Large enough that a 1400-byte inner segment never
/// needs two syscalls, small enough to stay off the allocator's slow path.
pub const COPY_BUF_SIZE: usize = 16 * 1024;

/// An iroh bi-stream seen as one duplex stream, so it can be piped like a socket.
///
/// The iroh streams also carry inherent `poll_*` methods with their own error type,
/// which win method resolution; the trait paths below are written out in full so the
/// tokio ones are the ones called.
pub struct DuplexIroh {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

impl DuplexIroh {
    pub fn new(send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream) -> Self {
        DuplexIroh { send, recv }
    }
}

impl AsyncRead for DuplexIroh {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for DuplexIroh {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// Copies bytes in both directions until either side stops.
///
/// First EOF wins rather than waiting for both: a tunnel is finished when either end
/// is, and waiting would pin a half-open connection. Whichever direction ends first
/// gets a half-close so the peer sees a clean EOF.
///
/// `label` only ever reaches a debug log — it exists so an operator can tell the TLS
/// path from the L4 path when both are in play.
pub async fn copy_both_ways<A, B>(client: A, backend: B, label: &str) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);

    let client_to_backend = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = backend_write.write_all(&buf[..n]).await {
                        tracing::debug!("{}: client->backend write failed: {}", label, e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("{}: client read failed: {}", label, e);
                    break;
                }
            }
        }
        let _ = backend_write.shutdown().await;
    };

    let backend_to_client = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match backend_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        tracing::debug!("{}: backend->client write failed: {}", label, e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        tracing::debug!("{}: client flush failed: {}", label, e);
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("{}: backend read failed: {}", label, e);
                    break;
                }
            }
        }
        let _ = client_write.shutdown().await;
    };

    tokio::select! {
        _ = client_to_backend => (),
        _ = backend_to_client => (),
    }

    Ok(())
}

/// Appends one chunk to `buf`; `false` on EOF, timeout or read error.
///
/// A peer that goes quiet is not an error here: the caller decides whether the bytes
/// received so far are enough (SNI parsing) or not (a preface that must be complete).
pub async fn read_more<R>(reader: &mut R, buf: &mut Vec<u8>, timeout: Duration) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    match tokio::time::timeout(timeout, reader.read(&mut chunk)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(false),
    }
}
