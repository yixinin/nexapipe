//! Device public keys: the credential a device proves without a human.
//!
//! A device secret is a second factor somebody reads off a screen and types,
//! which is the right shape at the one moment a person is certainly present —
//! enrollment, when the invite is scanned. A device that then runs unattended
//! has no such moment per connection, so it can hold an Ed25519 key of its
//! own instead: the operator registers the public half under
//! `[auth.clients.<id>.devices.<name>] public_key`, the private half never
//! leaves the device, and every later handshake is proven by a signature only
//! the device can produce.
//!
//! What is signed is the same byte string the HMAC path signs, defined once in
//! [`nexapipe_proto::auth::challenge_message`] and called from both — so
//! whichever credential answers, the handshake proves the same thing: this
//! client saw this connection's nonce at this time.
//!
//! The client half — generating a key and signing with it — lives in
//! `crates/nexapipe-client/src/auth.rs`. The message it signs is the same one
//! this module verifies against, because both sides link the definition in
//! `nexapipe-proto` rather than each keeping a copy of it.

use iroh::PublicKey;
use nexapipe_proto::auth::challenge_message;

/// The length of a device public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = PublicKey::LENGTH;

/// The length of a device public key's stored spelling: lowercase hex.
pub const PUBLIC_KEY_HEX_LEN: usize = PUBLIC_KEY_LEN * 2;

/// The stored spelling of a public key: lowercase hex.
pub fn public_key_hex(key: &PublicKey) -> String {
    hex::encode(key.as_bytes())
}

/// Reads a stored public key: 64 hex characters that decode to a point on the
/// ed25519 curve.
///
/// Called both where a key is written and where one is loaded, so a key nobody
/// could ever verify with is refused by the operator's own command and by the
/// loader — never at a handshake, where the only thing that could be said is
/// that some device was refused.
pub fn parse_public_key(stored: &str) -> anyhow::Result<PublicKey> {
    let spelled = stored.trim();
    let decoded =
        hex::decode(spelled).map_err(|_| anyhow::anyhow!("public key {spelled:?} is not hex"))?;
    let decoded_len = decoded.len();
    let bytes: [u8; PUBLIC_KEY_LEN] = decoded.try_into().map_err(|_| {
        anyhow::anyhow!(
            "public key {spelled:?} is {decoded_len} bytes of hex; a public key is \
             {PUBLIC_KEY_HEX_LEN} hex characters ({PUBLIC_KEY_LEN} bytes)"
        )
    })?;
    PublicKey::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("public key {spelled:?} is not a point on the ed25519 curve"))
}

/// Whether `signature` is proof that the holder of `key`'s private half saw
/// this connection's nonce at this timestamp.
///
/// The one verification the key path performs, called from
/// [`super::totp::TotpValidator::verify_response`] where the secret path calls
/// its HMAC comparison. `false` is a wrong credential — the bytes were not
/// produced by this key — and is counted against the client the way a wrong
/// TOTP code is, because for a key device there is no code to be the wrong one.
///
/// A signature that is not 64 bytes reads the same way as one that does not
/// verify: nothing that is not a signature is proof, and the fields this takes
/// arrive from a peer, so the answer is a verdict rather than an error.
pub(crate) fn ed25519_verify(
    key: &PublicKey,
    nonce: &[u8],
    timestamp: i64,
    signature: &[u8],
) -> bool {
    let Ok(signature) = iroh::Signature::try_from(signature) else {
        return false;
    };
    key.verify(&challenge_message(nonce, timestamp), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    /// A stand-in nonce, built rather than written out. No test here needs a
    /// particular value — each one asserts what a proof does with the nonce it
    /// was handed — and a literal array where a nonce goes reads to the scanner
    /// as a hard-coded key.
    fn test_nonce(seed: u8) -> [u8; 32] {
        std::array::from_fn(|i| seed ^ (i as u8))
    }

    /// A key survives the file: what is written is parsed back to the same
    /// point, which is what makes `public_key = "…"` in a config mean the
    /// device's key and not merely some hex.
    #[test]
    fn a_key_round_trips_through_its_stored_spelling() {
        let key = SecretKey::generate().public();

        let spelled = public_key_hex(&key);
        assert_eq!(spelled.len(), PUBLIC_KEY_HEX_LEN, "{spelled}");
        assert!(
            spelled
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "the stored spelling is lowercase hex: {spelled}"
        );

        assert_eq!(parse_public_key(&spelled).unwrap(), key);
    }

    /// An operator pastes the key the way it was handed to them — upper case,
    /// maybe with the whitespace a copied line brings along — and what lands on
    /// disk is the canonical spelling.
    #[test]
    fn the_stored_spelling_is_read_the_way_an_operator_writes_it() {
        let key = SecretKey::generate().public();
        let spelled = public_key_hex(&key);

        let pasted = format!("  {}\n", spelled.to_uppercase());
        assert_eq!(parse_public_key(&pasted).unwrap(), key);
    }

    /// Every way a key that is not a key can arrive is refused where it is
    /// written, naming what is wrong: bytes that are not hex, the wrong number
    /// of them, and 32 bytes that are not a point on the curve — which is what
    /// a value that is the right shape but not a key looks like.
    #[test]
    fn a_key_that_is_not_a_key_is_refused() {
        let not_hex = parse_public_key("not a key at all").unwrap_err();
        assert!(not_hex.to_string().contains("not hex"), "{not_hex}");

        let short = parse_public_key("aabb").unwrap_err();
        assert!(
            short.to_string().contains("2 bytes"),
            "the message has to say how long what arrived was: {short}"
        );

        // 32 bytes that are not a point: `y` = 2 with the sign bit clear,
        // which leaves 3/(4d + 1) to solve for x² — a non-residue, so no x
        // does. A digest pasted where a key belongs has exactly this shape.
        let mut off_curve = [0u8; PUBLIC_KEY_LEN];
        off_curve[0] = 0x02;
        let unwrapped = parse_public_key(&hex::encode(off_curve)).unwrap_err();
        assert!(unwrapped.to_string().contains("not a point"), "{unwrapped}");
    }

    /// The pin on the message definition both proof paths share: it is the
    /// nonce, byte for byte, then the timestamp little-endian. Both halves of
    /// the protocol are hand-synced, so this is the one place the bytes are
    /// spelled out for comparison.
    #[test]
    fn the_signed_message_is_the_nonce_then_the_little_endian_timestamp() {
        let nonce = test_nonce(0x5a);
        let timestamp = 0x0102030405060708i64;

        let signed = challenge_message(&nonce, timestamp);

        assert_eq!(
            &signed[..nonce.len()],
            &nonce[..],
            "the nonce first, byte for byte"
        );
        assert_eq!(
            &signed[nonce.len()..],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "then that timestamp as little-endian bytes"
        );
        assert_eq!(challenge_message(&[], 0), vec![0; 8]);
    }

    /// The round trip the key path rests on: what the private half signs over
    /// this connection's challenge, the public half verifies.
    #[test]
    fn a_signature_verifies_against_the_key_that_made_it() {
        let key = SecretKey::generate();
        let nonce = test_nonce(0x11);
        let timestamp = 1_700_000_000i64;

        let signature = key.sign(&challenge_message(&nonce, timestamp));

        assert!(ed25519_verify(
            &key.public(),
            &nonce,
            timestamp,
            &signature.to_bytes()
        ));
    }

    /// Another device's key leaves the proof unproven — which is the whole of
    /// what registering a key under a device name means: only that device's
    /// signature opens that name.
    #[test]
    fn another_key_does_not_verify_it() {
        let device = SecretKey::generate();
        let stranger = SecretKey::generate();
        let nonce = test_nonce(0x11);
        let timestamp = 1_700_000_000i64;

        let signature = device.sign(&challenge_message(&nonce, timestamp));

        assert!(!ed25519_verify(
            &stranger.public(),
            &nonce,
            timestamp,
            &signature.to_bytes()
        ));
    }

    /// A signature over anything but this challenge is refused, whether the
    /// nonce, the timestamp or the signature bytes themselves were changed —
    /// this is what keeps an intercepted proof from being replayed onto
    /// another connection, or onto this one later.
    #[test]
    fn a_tampered_proof_is_refused() {
        let key = SecretKey::generate();
        let nonce = test_nonce(0x11);
        let timestamp = 1_700_000_000i64;
        let signature = key.sign(&challenge_message(&nonce, timestamp));
        let mut flipped = signature.to_bytes();
        flipped[0] ^= 0x01;

        // 63 bytes, where a signature is 64: a `Vec` that lost its last byte
        // on the way has to read as "not proof", not as a panic.
        let mut short = signature.to_bytes().to_vec();
        short.pop();

        assert!(
            !ed25519_verify(
                &key.public(),
                &test_nonce(0x22),
                timestamp,
                &signature.to_bytes()
            ),
            "the same signature over a different challenge"
        );
        assert!(
            !ed25519_verify(&key.public(), &nonce, timestamp + 1, &signature.to_bytes()),
            "the same signature under a different timestamp"
        );
        assert!(
            !ed25519_verify(&key.public(), &nonce, timestamp, &flipped),
            "a signature with one bit changed"
        );
        assert!(
            !ed25519_verify(&key.public(), &nonce, timestamp, &short),
            "one byte short of a signature is not a signature"
        );
        assert!(
            !ed25519_verify(&key.public(), &nonce, timestamp, &[]),
            "no signature at all is not one"
        );
    }
}
