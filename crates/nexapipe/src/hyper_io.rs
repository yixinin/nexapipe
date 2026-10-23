//! An iroh bi-stream as hyper's IO, so the tunnel path can use hyper's own
//! HTTP/1 codec.
//!
//! The two ends of the tunnel are an iroh `SendStream` and a `RecvStream`.
//! Hyper reads and writes through **its own** IO traits — not tokio's — so
//! the streams have to be presented as one of those before hyper's codec can
//! be pointed at them.
//!
//! This is the same shape as [`crate::stream_util::DuplexIroh`], which presents
//! the same pair as a tokio duplex stream. The two are kept apart because their
//! traits are apart: tokio's `AsyncRead`/`AsyncWrite` and hyper's `Read`/`Write`
//! say the same thing in different words, and a type that implements one does
//! not implement the other.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::rt::{Read, ReadBufCursor, Write};
use pin_project_lite::pin_project;

/// An iroh bi-stream seen as hyper's IO.
pub struct IrohIo {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

impl IrohIo {
    /// The two halves of one bi-stream.
    pub fn new(send: iroh::endpoint::SendStream, recv: iroh::endpoint::RecvStream) -> Self {
        IrohIo { send, recv }
    }
}

impl hyper::rt::Read for IrohIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();

        // Hyper's cursor and tokio's buffer are the same idea — a region of
        // memory with a "filled" part and an "unfilled" part — and the bytes
        // tokio writes into the unfilled part are the bytes hyper reads out
        // of it. The cursor hands out its unfilled region as
        // `MaybeUninit<u8>`, which is what tokio's `ReadBuf::uninit` takes.
        //
        // SAFETY: the region belongs to the cursor, and the cursor is only
        // advanced by this function, after the read has said how many bytes
        // arrived. A `MaybeUninit<u8>` is exactly what an uninitialized
        // buffer is.
        let mut read_buf = tokio::io::ReadBuf::uninit(unsafe { buf.as_mut() });

        match tokio::io::AsyncRead::poll_read(Pin::new(&mut this.recv), cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                // The bytes tokio read are initialized, so the cursor can be
                // told they are there.
                let filled = read_buf.filled().len();
                // SAFETY: the cursor's unfilled region is the one tokio was
                // given, and `filled` is how many of those bytes tokio
                // initialized.
                unsafe { buf.advance(filled) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for IrohIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }

    fn is_write_vectored(&self) -> bool {
        false
    }
}

/// The timer hyper's deadlines are measured against.
///
/// Hyper does not ship one: it says what a runtime has to provide, and
/// tokio's is what this process has. The head's deadline is the one that
/// matters here — a peer that opens a stream and sends nothing must not hold
/// the slot forever — and hyper measures it with this.
#[derive(Clone, Copy, Debug)]
pub struct TokioTimer;

impl hyper::rt::Timer for TokioTimer {
    fn sleep(&self, duration: std::time::Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep(duration),
        })
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep_until(deadline.into()),
        })
    }
}

pin_project! {
    struct TokioSleep {
        #[pin]
        inner: tokio::time::Sleep,
    }
}

impl std::future::Future for TokioSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl hyper::rt::Sleep for TokioSleep {}

/// The other side of an upgrade, as tokio's IO.
///
/// Once the `101` is written the connection stops being HTTP and becomes
/// bytes, and hyper hands those bytes over through its own traits. The copy
/// loop that moves them is tokio's, so the two are bridged here — the same
/// job [`IrohIo`] does in the other direction.
pub struct UpgradedIo {
    inner: hyper::upgrade::Upgraded,
}

impl UpgradedIo {
    /// The stream hyper handed over.
    pub fn new(inner: hyper::upgrade::Upgraded) -> Self {
        Self { inner }
    }
}

impl tokio::io::AsyncRead for UpgradedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Hyper's cursor is over the part of the buffer that is not filled
        // yet, and it is told how much was read afterwards.
        let filled = {
            // SAFETY: the unfilled part of the buffer is exactly the memory
            // hyper is about to fill, and the cursor is told afterwards how
            // much of it was.
            let unfilled = unsafe { buf.unfilled_mut() };
            let mut hyper_buf = hyper::rt::ReadBuf::uninit(unfilled);
            let cursor = hyper_buf.unfilled();
            match Pin::new(&mut this.inner).poll_read(cx, cursor) {
                Poll::Ready(Ok(())) => hyper_buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        // The bytes hyper read are in the buffer, and `filled` is how many of
        // them there are.
        buf.advance(filled);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for UpgradedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::IrohIo;
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use std::net::SocketAddr;

    const ALPN: &[u8] = b"nexapipe";

    /// **Hyper's own HTTP/1 codec serves a request over an iroh bi-stream.**
    ///
    /// This is the whole point of the adapter: hyper reads the head itself,
    /// so nothing has to be read out of the stream and handed back, and the
    /// request arrives whole.
    #[tokio::test]
    async fn hyper_serves_a_request_over_an_iroh_stream() {
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the server binds");
        let server_addr = server.addr();
        // The endpoint and the connection both outlive the stream: a dropped
        // endpoint takes every connection on it down, and a dropped
        // `Connection` handle closes the connection — and a connection that
        // closes before the answer is on its way loses it.
        let _server = server.clone();

        // The far side waits for a connection, and the connection is the
        // client's to make — so it waits in its own task. A far side that
        // waited for it here would wait for a client this task has not
        // built yet, and the two would never meet.
        //
        // It holds on to the connection until the client says it has the
        // answer: dropping the last `Connection` handle closes the
        // connection, and a close can throw away the answer that is still on
        // its way.
        let (answered, waiting) = tokio::sync::oneshot::channel::<()>();
        let far_side = tokio::spawn(async move {
            let incoming = server.accept().await.expect("a connection");
            let accepting = incoming.accept().expect("the connection is accepted");
            let connection = accepting.await.expect("the handshake finishes");
            let (send, recv) = connection.accept_bi().await.expect("a bi-stream");

            let io = IrohIo::new(send, recv);
            let service = hyper::service::service_fn(
                |_req: hyper::Request<hyper::body::Incoming>| async move {
                    Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                        bytes::Bytes::from_static(b"hello"),
                    )))
                },
            );
            // The codec's own verdict on the connection. It is not asserted on
            // — the client reads the answer, and the answer is what the test
            // is about — but it is not dropped either: a connection that ends
            // in an error is worth saying out loud.
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::warn!("The served connection ended with an error: {}", e);
            }

            // The connection outlives the served one: the answer is written,
            // but it is still on its way, and a connection that closes now
            // takes it with it.
            let _ = waiting.await;
        });

        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the client binds");
        let connection = client
            .connect(server_addr, ALPN)
            .await
            .expect("the connection opens");
        let (mut send, mut recv) = connection.open_bi().await.expect("a bi-stream");

        send.write_all(b"GET /thing HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("the request goes out");

        let mut answer = Vec::new();
        // The trait path, not the inherent method: iroh's own `read_to_end`
        // takes a length rather than a buffer.
        tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut answer)
            .await
            .expect("the answer comes back");
        let answer = String::from_utf8_lossy(&answer).to_string();

        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("hello"), "{answer}");

        // The answer is here, so the far side may let go of the connection.
        let _ = answered.send(());
        // And it has to have finished too: it is the one that wrote the
        // answer, and a task that panicked would have taken it with it.
        far_side.await.expect("the far side finished");
    }
}
