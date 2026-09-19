//! Datagram framing for the UDP half of the L4 tunnel.

use crate::ProtoError;

/// Largest payload one frame may carry — RFC 768's limit for a UDP datagram over IPv4.
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// Bytes of length prefix in front of every payload.
pub const FRAME_HEADER_LEN: usize = 2;

/// Append one datagram as `u16` big-endian length + payload.
///
/// A QUIC bi-stream is a byte stream with no message boundaries, so UDP's datagram
/// boundaries have to be re-created here. This is what makes the tunnel order-preserving
/// and reliable, which UDP itself is not — the SOCKS5-style contract is that the proxy
/// carries datagrams faithfully and the application tolerates reordering.
pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) -> Result<(), ProtoError> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge);
    }
    out.reserve(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// [`encode_frame`] into a fresh buffer, for callers sending one datagram at a time.
pub fn encode_frame_to_vec(payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    encode_frame(payload, &mut out)?;
    Ok(out)
}

/// Result of reading a frame off the front of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// The length prefix, or the payload it announces, has not arrived yet.
    Incomplete,
    /// A complete datagram, plus how many buffer bytes it occupied.
    Ready { payload: &'a [u8], consumed: usize },
}

/// Read one frame off the front of `buf`.
///
/// Zero-payload frames are legal: an empty UDP datagram is a real thing an application
/// can send, and dropping it would be a silent behavioural difference. A reader that
/// sees [`Frame::Incomplete`] must read more bytes, not assume the stream ended —
/// `consumed` is always `FRAME_HEADER_LEN` or more, so a caller draining a loop makes
/// progress or blocks on the socket.
pub fn decode_frame(buf: &[u8]) -> Frame<'_> {
    if buf.len() < FRAME_HEADER_LEN {
        return Frame::Incomplete;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = FRAME_HEADER_LEN + len;
    if buf.len() < total {
        return Frame::Incomplete;
    }
    Frame::Ready {
        payload: &buf[FRAME_HEADER_LEN..total],
        consumed: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_have_the_documented_bytes() {
        let frame = encode_frame_to_vec(b"hi").unwrap();
        assert_eq!(frame, vec![0x00, 0x02, b'h', b'i']);

        // A 300-byte payload needs a two-byte length, big-endian.
        let frame = encode_frame_to_vec(&[0xab; 300]).unwrap();
        assert_eq!(&frame[..2], &[0x01, 0x2c]);
        assert_eq!(frame.len(), 2 + 300);
    }

    #[test]
    fn round_trip_through_decode() {
        for payload in [&b""[..], &b"x"[..], &[0u8; 1400][..]] {
            let frame = encode_frame_to_vec(payload).unwrap();
            match decode_frame(&frame) {
                Frame::Ready { payload: out, consumed } => {
                    assert_eq!(out, payload);
                    assert_eq!(consumed, frame.len());
                }
                Frame::Incomplete => panic!("encoded frame did not decode"),
            }
        }
    }

    #[test]
    fn decode_is_incomplete_until_the_whole_frame_arrived() {
        let frame = encode_frame_to_vec(b"hello").unwrap();
        for cut in 0..frame.len() {
            assert_eq!(
                decode_frame(&frame[..cut]),
                Frame::Incomplete,
                "cut at {cut}"
            );
        }
        assert!(matches!(decode_frame(&frame), Frame::Ready { .. }));
    }

    #[test]
    fn decode_reports_how_much_it_consumed() {
        // Two frames in one buffer: the reader must be able to find the second one
        // without guessing.
        let mut buf = encode_frame_to_vec(b"one").unwrap();
        buf.extend_from_slice(&encode_frame_to_vec(b"two").unwrap());

        let Frame::Ready { payload, consumed } = decode_frame(&buf) else {
            panic!("first frame should be complete");
        };
        assert_eq!(payload, b"one");
        let Frame::Ready { payload, .. } = decode_frame(&buf[consumed..]) else {
            panic!("second frame should be complete");
        };
        assert_eq!(payload, b"two");
    }

    #[test]
    fn an_empty_datagram_is_a_frame_not_an_end_of_stream() {
        let frame = encode_frame_to_vec(b"").unwrap();
        assert_eq!(frame, vec![0x00, 0x00]);
        let Frame::Ready { payload, consumed } = decode_frame(&frame) else {
            panic!("empty frame should still be a frame");
        };
        assert!(payload.is_empty());
        assert_eq!(consumed, 2);
    }

    #[test]
    fn oversized_payloads_are_refused_before_they_wrap_the_length_prefix() {
        assert!(encode_frame_to_vec(&[0u8; MAX_UDP_PAYLOAD]).is_ok());
        assert_eq!(
            encode_frame_to_vec(&[0u8; MAX_UDP_PAYLOAD + 1]),
            Err(ProtoError::PayloadTooLarge)
        );
    }
}
