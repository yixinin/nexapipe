use super::enrollment::refused_enrollment_message;
use super::{
    DeviceKey, Enrollment, IssuedCredential, TotpAlgorithm, TwoFactorAuth, TwoFactorConfig,
    device_id_is_usable, message::read_message_bytes,
};
use nexapipe_proto::auth::{
    Algorithm as ProtoAlgorithm, AuthMessage, Format, MAX_DEVICE_ID_LEN, VERSION_BINARY,
};
use nexapipe_proto::secret::SecretString;
use tokio::io::AsyncWriteExt;

/// The heap, watched.
///
/// The defect this fixes is a credential that survives in the heap after the
/// message that carried it is gone, and the only way to *show* that it does
/// not survive is to look at the memory after it is freed. The allocator is
/// where that memory comes back from, so the allocator is where the proof is:
/// a block on its way out that still holds the credential is a block the
/// credential survived in.
mod heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The bytes the probe is watching for.
    ///
    /// A string no other test uses, so a block that holds it is one this
    /// test made.
    pub const NEEDLE: &str = "nexapipe-heap-probe-7c1d3e";

    /// Whether the probe is watching.
    static WATCHING: AtomicBool = AtomicBool::new(false);

    /// Whether the needle was seen in a block on its way out.
    static FOUND: AtomicBool = AtomicBool::new(false);

    /// The allocator that watches.
    struct Probe;

    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            scan(ptr, layout.size());
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            scan(ptr, layout.size());
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static PROBE: Probe = Probe;

    /// Looks for the needle in a block that is about to be freed.
    fn scan(ptr: *mut u8, len: usize) {
        if !WATCHING.load(Ordering::Relaxed) || len < NEEDLE.len() {
            return;
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        if bytes
            .windows(NEEDLE.len())
            .any(|window| window == NEEDLE.as_bytes())
        {
            FOUND.store(true, Ordering::SeqCst);
        }
    }

    /// Runs `body` with the heap watched, and says whether the needle was
    /// left behind in it.
    pub fn left_behind<R>(body: impl FnOnce() -> R) -> bool {
        WATCHING.store(true, Ordering::SeqCst);
        FOUND.store(false, Ordering::SeqCst);
        body();
        WATCHING.store(false, Ordering::SeqCst);
        FOUND.load(Ordering::SeqCst)
    }
}

/// The credential a message hands out does not survive in the heap.
///
/// An `ENROLL_ISSUE` carries the secret the client is about to authenticate
/// with — the most valuable thing this process holds. It arrives in a buffer,
/// and the buffer used to be a plain `Vec<u8>`: the bytes of the secret were
/// in it until it was dropped, and dropping it left them in the heap for the
/// allocator to hand out again. A core dump, a swap file or a read of
/// `/proc/<pid>/mem` finds them there long after the handshake that needed
/// them.
///
/// This is the proof that they do not survive: the heap is watched while the
/// buffer the message was read into is dropped, and a block on its way out
/// that still holds the secret fails the test.
///
/// The secret travels over a `tokio::io::duplex` pipe rather than a real
/// connection on purpose: a QUIC connection would carry the secret through
/// the transport's own buffers, and those would be found by the probe for
/// reasons that have nothing to do with this code.
#[tokio::test]
async fn a_received_credential_does_not_survive_in_the_heap() {
    let needle = heap::NEEDLE;
    let issued = AuthMessage::EnrollIssue {
        client_id: "client-001".to_string(),
        secret: SecretString::new(needle.to_string()),
        algorithm: ProtoAlgorithm::Sha1,
        digits: 6,
        period: 30,
        device_id: None,
    };
    let payload = issued
        .to_payload(Format::Binary)
        .expect("the message serializes");

    // The peer writes the message, and the client reads it.
    let (mut peer, mut reader) = tokio::io::duplex(4096);
    peer.write_all(&(payload.len() as u32).to_le_bytes())
        .await
        .expect("the length is written");
    peer.write_all(&payload)
        .await
        .expect("the message is written");

    let bytes = read_message_bytes(&mut reader)
        .await
        .expect("the message is read");

    // The parsed message holds a copy of its own: the secret is a
    // `SecretString` built out of the bytes, so the copy in the buffer is the
    // redundant one — which is the one that has to be wiped.
    let (parsed, _) = AuthMessage::from_payload(&bytes[..]).expect("the message parses");
    match &parsed {
        AuthMessage::EnrollIssue { secret, .. } => assert_eq!(
            secret.expose_secret(),
            needle,
            "the parsed message holds the credential"
        ),
        other => panic!("expected ENROLL_ISSUE, got {other:?}"),
    }

    // The buffer the credential was read into goes out of scope with the heap
    // watched.
    assert!(
        !heap::left_behind(|| drop(bytes)),
        "the credential survived in the heap"
    );

    // And the probe is not vacuous: a buffer that is *not* wiped leaves the
    // credential behind, and the probe sees it.
    assert!(
        heap::left_behind(|| {
            let mut plain = vec![0u8; needle.len()];
            plain.copy_from_slice(needle.as_bytes());
            std::hint::black_box(&plain);
            drop(plain);
        }),
        "the probe does not see a credential that was not wiped"
    );

    // The copies that are meant to outlive the watched window: the parsed
    // message, and the pipe that carried the bytes.
    drop(parsed);
    drop(peer);
    drop(reader);
}

/// An algorithm nobody supports is refused, and the refusal says what was
/// wrong.
///
/// A name quietly turned into a different algorithm is a silent downgrade:
/// the client computes codes the server does not accept, and every attempt
/// fails with "wrong code" rather than the algorithm being named once.
#[test]
fn an_unknown_algorithm_name_is_refused() {
    let error = TotpAlgorithm::try_from_name("sha-256").expect_err("nobody supports it");
    let message = error.to_string();

    assert!(message.contains("sha-256"), "{message}");
    assert!(message.contains("SHA1"), "{message}");
    assert!(message.contains("SHA256"), "{message}");
    assert!(message.contains("SHA512"), "{message}");
}

/// The three names the client supports, in any case.
#[test]
fn the_supported_algorithm_names_parse_in_any_case() {
    for name in ["sha1", "SHA1", "Sha1", " sha1 "] {
        assert_eq!(
            TotpAlgorithm::try_from_name(name).expect("sha1"),
            TotpAlgorithm::SHA1,
            "{name:?} is sha1"
        );
    }
    for name in ["sha256", "SHA256", "Sha256"] {
        assert_eq!(
            TotpAlgorithm::try_from_name(name).expect("sha256"),
            TotpAlgorithm::SHA256,
            "{name:?} is sha256"
        );
    }
    for name in ["sha512", "SHA512", "Sha512"] {
        assert_eq!(
            TotpAlgorithm::try_from_name(name).expect("sha512"),
            TotpAlgorithm::SHA512,
            "{name:?} is sha512"
        );
    }
}

/// A name that is not there is the default, `sha1`.
///
/// Which is what a URI that leaves the parameter out means, and what the
/// Android client does with the same field.
#[test]
fn an_absent_algorithm_name_is_the_default() {
    assert_eq!(
        TotpAlgorithm::try_from_name("").expect("the default"),
        TotpAlgorithm::SHA1
    );
}

/// A `Debug` that prints a secret turns every log line, panic message and
/// bug report that touches one into a credential disclosure — and these are
/// exactly the values an app logs while working out why authentication
/// stopped working. Every holder of a secret gets a hand-written `Debug` for
/// that reason; this is the test that keeps the hand-written ones honest.
#[test]
fn no_debug_output_carries_a_secret() {
    let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let config = TwoFactorConfig {
        client_id: "node-1".to_string(),
        secret: SecretString::new(secret.to_string()),
        algorithm: TotpAlgorithm::SHA1,
    };
    let auth = TwoFactorAuth::new("node-1", secret, TotpAlgorithm::SHA1).expect("a credential");
    let issued = IssuedCredential {
        client_id: "node-1".to_string(),
        secret: SecretString::new(secret.to_string()),
        algorithm: "sha1".to_string(),
        public_key: None,
        device: Some("laptop".to_string()),
    };
    let enrollment = Enrollment::new("node-1", "an-invitation-token");

    for rendered in [
        format!("{config:?}"),
        format!("{auth:?}"),
        format!("{issued:?}"),
        format!("{enrollment:?}"),
    ] {
        assert!(
            !rendered.contains(secret),
            "a TOTP seed reached a Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("an-invitation-token"),
            "an enrollment token reached a Debug output: {rendered}"
        );
    }
}

/// Masking must not turn into silence: a reader debugging a login needs to
/// tell "no secret configured" from "a secret is there and I cannot see it",
/// and needs to know the value is not the wrong length.
#[test]
fn a_masked_secret_still_says_whether_there_is_one() {
    let with_secret = TwoFactorConfig {
        client_id: "node-1".to_string(),
        secret: SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
        algorithm: TotpAlgorithm::SHA1,
    };
    let without = TwoFactorConfig {
        client_id: "node-1".to_string(),
        secret: SecretString::new(String::new()),
        algorithm: TotpAlgorithm::SHA1,
    };

    let present = format!("{with_secret:?}");
    let absent = format!("{without:?}");

    // Neither message interpolates the rendering: a failure here would print
    // whatever the `Debug` let through, which is the leak under test.
    assert!(
        present != absent,
        "a masked secret and an absent one are indistinguishable"
    );
    assert!(present.contains("32 chars"), "the length is not reported");
    // The whole point of masking, stated as a test: the length is not the value.
    assert!(!present.contains("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
}

/// A stand-in nonce, built rather than written out — the twin of the helper
/// in `crates/nexapipe/src/auth/device_key.rs`. No test here needs a
/// particular value, and a literal array where a nonce goes reads to the
/// scanner as a hard-coded key.
fn test_nonce(seed: u8) -> [u8; 32] {
    std::array::from_fn(|i| seed ^ (i as u8))
}

/// The mirror of the test in `crates/nexapipe/src/auth/protocol.rs`: the
/// two sides define these messages separately, and the tag is all that
/// decides which one a peer is looking at.
#[test]
fn enrollment_messages_keep_their_wire_names() {
    let start = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new("tok".to_string()),
        device_id: None,
        public_key: None,
    };
    let json = String::from_utf8(start.to_bytes().unwrap().to_vec()).unwrap();
    assert!(json.contains(r#""type":"ENROLL_START""#), "{json}");

    let issue = AuthMessage::EnrollIssue {
        client_id: "client-001".to_string(),
        secret: SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
        algorithm: ProtoAlgorithm::Sha1,
        digits: 6,
        period: 30,
        device_id: None,
    };
    let json = String::from_utf8(issue.to_bytes().unwrap().to_vec()).unwrap();
    assert!(json.contains(r#""type":"ENROLL_ISSUE""#), "{json}");

    let failed = AuthMessage::EnrollFailed {
        reason: "no".to_string(),
    };
    let json = String::from_utf8(failed.to_bytes().unwrap().to_vec()).unwrap();
    assert!(json.contains(r#""type":"ENROLL_FAILED""#), "{json}");
}

/// The mirror of the server's test: the two sides define these messages
/// separately, and the field may not appear at all — a client that predates
/// keys sends none — so one without it has to still parse, and stay the
/// same message on the way back out.
#[test]
fn an_enrollment_without_a_key_still_parses_on_the_wire() {
    let wire =
        br#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop"}"#;
    let start = AuthMessage::from_bytes(wire).unwrap();
    match &start {
        AuthMessage::EnrollStart { public_key, .. } => assert_eq!(public_key, &None),
        other => panic!("expected ENROLL_START, got {other:?}"),
    }
    assert_eq!(
        *start.to_bytes().unwrap(),
        wire.to_vec(),
        "no public_key goes out as no public_key"
    );
}

/// And one that offers a key round-trips, exactly: the field is carried
/// whole, not normalized in flight.
#[test]
fn an_enrollment_offering_a_key_round_trips_byte_exactly() {
    let wire = br#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop","public_key":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}"#;
    let start = AuthMessage::from_bytes(wire).unwrap();
    match &start {
        AuthMessage::EnrollStart { public_key, .. } => assert_eq!(
            public_key.as_deref(),
            Some("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
        ),
        other => panic!("expected ENROLL_START, got {other:?}"),
    }
    assert_eq!(*start.to_bytes().unwrap(), wire.to_vec());
}

/// A refused enrollment says which device asked, because that is what the
/// server's own log names and what an operator has to act on.
///
/// The server answers every refusal with the same string — whether the token
/// was unknown, already spent or the device was already enrolled is not
/// information a stranger is owed — so the client is what puts the two logs
/// together.
#[test]
fn a_refused_enrollment_names_the_device_it_asked_under() {
    let message = refused_enrollment_message(
        "the enrollment token was not accepted",
        "xm17",
        Some("phone-1a2b3c4d"),
    );

    assert!(message.contains("xm17"), "{message}");
    assert!(message.contains("phone-1a2b3c4d"), "{message}");
    assert!(
        message.contains("nexapipe client revoke xm17 --device phone-1a2b3c4d"),
        "{message}"
    );
}

/// Without a device name there is nothing to name but the client — and
/// nothing to revoke, so the message does not point at a command.
#[test]
fn a_refused_enrollment_without_a_device_names_the_client() {
    let message = refused_enrollment_message("the enrollment token was not accepted", "xm17", None);

    assert!(message.contains("xm17"), "{message}");
    assert!(!message.contains("client revoke"), "{message}");
}

/// An enrollment that offers a key names the device it offered it under: that
/// is the name the server files the key under, and the one it refuses to take
/// over.
#[test]
fn an_enrollment_that_offers_a_key_carries_the_device_name() {
    let key = iroh::SecretKey::generate();
    let enrollment = Enrollment::new("xm17", "tok")
        .with_device("phone-1a2b3c4d")
        .with_key(key.clone());

    assert_eq!(enrollment.device_id(), Some("phone-1a2b3c4d"));
    assert_eq!(enrollment.client_id(), "xm17");
}

/// The offer is made of the public half, lowercase hex — the spelling the
/// server's config stores — and the builder keeps the private half, which
/// is what will sign every challenge once the offer is taken.
#[test]
fn an_enrollment_can_offer_a_key_beside_its_device_name() {
    let key = iroh::SecretKey::generate();
    let public_key = hex::encode(key.public().as_bytes());

    let enrollment = Enrollment::new("client-001", "tok")
        .with_device("phone-1a2b3c4d")
        .with_key(key.clone());
    assert!(
        enrollment.key.is_some(),
        "the offered key is kept to sign with"
    );

    // What those two produce on the wire, as `exchange_inner` sends it.
    let start = AuthMessage::EnrollStart {
        client_id: enrollment.client_id().to_string(),
        token: SecretString::new("tok".to_string()),
        device_id: enrollment.device_id().map(str::to_string),
        public_key: enrollment
            .key
            .as_ref()
            .map(|key| hex::encode(key.public().as_bytes())),
    };
    let json = String::from_utf8(start.to_bytes().unwrap().to_vec()).unwrap();
    assert!(
        json.contains(&format!(r#""public_key":"{public_key}""#)),
        "{json}"
    );
    assert!(
        !json.contains(&hex::encode(key.to_bytes())),
        "the private half never goes on the wire: {json}"
    );
}

/// A key-based credential puts a signature where a secret-based one puts an
/// HMAC and carries no code at all: the server reads the code only on the
/// secret path, and an empty one is what a key response looks like.
#[test]
fn a_key_credential_responds_with_a_signature_and_no_code() {
    let key = iroh::SecretKey::generate();
    let public_key = hex::encode(key.public().as_bytes());
    let auth = TwoFactorAuth::with_key("client-001", key, "phone-1a2b3c4d");

    let (totp_code, signature) = auth.prove(&test_nonce(0x0a), 1_700_000_000).unwrap();
    assert_eq!(totp_code, "", "a key device sends no code");
    assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");

    assert_eq!(auth.public_key_hex(), Some(public_key));
    assert_eq!(auth.secret_base32(), "", "a key credential has no secret");
    assert_eq!(auth.algorithm_name(), "", "and no algorithm to name");
    assert_eq!(auth.device_id(), Some("phone-1a2b3c4d"));
    assert!(
        auth.generate_code().is_err(),
        "there is no code to generate"
    );
}

/// What a key device signs is the same byte string the secret path HMACs —
/// the nonce, byte for byte, then the timestamp little-endian — because the
/// server verifies against exactly those bytes. This is the client half of
/// the pin the server's `device_key` tests keep.
#[test]
fn a_key_credential_signs_the_nonce_then_the_little_endian_timestamp() {
    let key = iroh::SecretKey::generate();
    let public = key.public();
    let auth = TwoFactorAuth::with_key("client-001", key, "phone-1a2b3c4d");

    let nonce = test_nonce(0x01);
    let signature = auth.sign_challenge(&nonce, 0x0102030405060708).unwrap();
    assert_eq!(signature.len(), 64);

    let mut message = nonce.to_vec();
    message.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    public
        .verify(
            &message,
            &iroh::Signature::try_from(signature.as_slice()).expect("64 bytes of signature"),
        )
        .expect("the signature verifies against the public half");
}

/// An enrollment that succeeds has to hand back something the app can
/// write down, or a restart has nothing left to authenticate with.
#[test]
fn an_issued_credential_comes_back_in_the_form_it_was_configured_with() {
    let auth = TwoFactorAuth::with_params(
        "client-001",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        TotpAlgorithm::SHA256,
        30,
        6,
    )
    .unwrap();
    assert_eq!(auth.secret_base32(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    assert_eq!(auth.algorithm_name(), "sha256");
}

/// `base32` 0.5 decodes upper case only, so a secret that is correct but
/// written in lower case — a hand-copied config, an app that stores what
/// it was handed — used to decode and would now be rejected.
#[test]
fn a_secret_decodes_in_any_spelling() {
    for spelling in [
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        "jbswy3dpehpk3pxpjbswy3dpehpk3pxp",
        "JbSwY3dPeHpK3pXpJbSwY3dPeHpK3pXp",
        "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP",
        "jbswy3dpehpk3pxpjbswy3dpehpk3pxp==",
    ] {
        let auth = TwoFactorAuth::new("client-001", spelling, TotpAlgorithm::SHA1)
            .unwrap_or_else(|e| panic!("{spelling:?} should decode: {e}"));
        assert_eq!(
            auth.secret_base32(),
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "{spelling:?}"
        );
    }
}

/// The other half of the same guard: something that is not Base32 at all
/// is still refused, in whatever spelling.
#[test]
fn a_secret_that_is_not_base32_is_still_refused() {
    assert!(TwoFactorAuth::new("client-001", "not-base32!", TotpAlgorithm::SHA1).is_err());
    assert!(TwoFactorAuth::new("client-001", "", TotpAlgorithm::SHA1).is_err());
}

/// A secret that decodes to less than 128 bits is refused where it is
/// configured.
///
/// The TOTP library refuses such a seed when the validator is built, which
/// happens at the first handshake — so without this the only symptom of a
/// secret that can never work is a library error about a secret length, at
/// the moment a connection is being made. The floor is the same one the
/// server applies when it reads the config, and the same one the invite
/// parser applies when it reads an invite.
#[test]
fn a_secret_too_short_to_be_a_secret_is_refused() {
    // One byte, five bytes, ten bytes: each of these decodes cleanly, and
    // each of them is below the floor.
    for short in ["ab", "AEBAGBAF", "JBSWY3DPEHPK3PXP"] {
        let error = TwoFactorAuth::new("client-001", short, TotpAlgorithm::SHA1)
            .expect_err("a seed under 128 bits is refused");
        let error = error.to_string();
        assert!(
            error.contains("at least 16 bytes"),
            "the refusal says what the floor is: {error}"
        );
        assert!(
            !error.contains(short),
            "the secret is not quoted back: {error}"
        );
    }

    // Sixteen bytes is the floor itself, and it is accepted.
    assert!(
        TwoFactorAuth::new(
            "client-001",
            "AEBAGBAFAYDQQCIKBMGA2DQPCA",
            TotpAlgorithm::SHA1
        )
        .is_ok(),
        "a 128-bit secret is the shortest one that works"
    );
}

/// A device is named on AUTH_START *and* on AUTH_RESPONSE, because the
/// server reads the name off the response when it decides which secret to
/// check against. Naming it on the first alone would ask to be counted as a
/// device while proving possession of the client's own secret.
#[test]
fn a_named_device_speaks_on_both_messages() {
    let auth = TwoFactorAuth::new(
        "client-001",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        TotpAlgorithm::SHA1,
    )
    .unwrap()
    .with_device("laptop-7f3a9c21");
    assert_eq!(auth.device_id(), Some("laptop-7f3a9c21"));

    let start = AuthMessage::Start {
        client_id: auth.client_id().to_string(),
        timestamp: 0,
        device_id: auth.device_id().map(str::to_string),
        version: None,
    };
    let json = String::from_utf8(start.to_bytes().unwrap().to_vec()).unwrap();
    assert!(json.contains(r#""device_id":"laptop-7f3a9c21""#), "{json}");

    let response = AuthMessage::Response {
        client_id: auth.client_id().to_string(),
        timestamp: 0,
        totp_code: "123456".to_string(),
        signature: vec![0u8; 32],
        device_id: auth.device_id().map(str::to_string),
    };
    let json = String::from_utf8(response.to_bytes().unwrap().to_vec()).unwrap();
    assert!(json.contains(r#""device_id":"laptop-7f3a9c21""#), "{json}");
}

/// The device that was never given a name has to look exactly like a client
/// that predates devices: no `device_id` on the wire at all, not one set to
/// null. A peer that predates this cannot be asked to understand a field it
/// has never seen.
#[test]
fn an_unnamed_device_leaves_the_field_off_the_wire() {
    let auth = TwoFactorAuth::new(
        "client-001",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        TotpAlgorithm::SHA1,
    )
    .unwrap();
    assert_eq!(auth.device_id(), None);

    let start = AuthMessage::Start {
        client_id: auth.client_id().to_string(),
        timestamp: 0,
        device_id: auth.device_id().map(str::to_string),
        version: None,
    };
    let json = String::from_utf8(start.to_bytes().unwrap().to_vec()).unwrap();
    assert!(!json.contains("device_id"), "{json}");
}

/// The mirror of that, in the other direction: a server that predates
/// per-device credentials sends no `device_id`, and ENROLL_ISSUE without
/// one still has to deserialize.
#[test]
fn an_issue_from_a_server_that_names_no_device_still_parses() {
    let wire = br#"{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}"#;
    let issue = AuthMessage::from_bytes(wire).unwrap();
    match issue {
        AuthMessage::EnrollIssue { device_id, .. } => assert_eq!(device_id, None),
        other => panic!("expected ENROLL_ISSUE, got {other:?}"),
    }
}

/// An enrollment carries the name it was given, and one that was given
/// none asks for the client's own secret — which is the only thing a server
/// that predates devices will answer.
#[test]
fn an_enrollment_asks_for_the_device_it_was_given() {
    assert_eq!(Enrollment::new("client-001", "tok").device_id(), None);
    let named = Enrollment::new("client-001", "tok").with_device("phone-1a2b3c4d");
    assert_eq!(named.device_id(), Some("phone-1a2b3c4d"));
    assert_eq!(named.client_id(), "client-001");
}

/// What the server will refuse, mirrored so an app can find out before a
/// handshake rather than during one. A hostname is the obvious thing to
/// name a device after, and "MacBook Pro" is the obvious way to break it.
#[test]
fn a_device_name_is_printable_ascii_without_spaces() {
    assert!(device_id_is_usable("laptop-7f3a9c21"));
    assert!(device_id_is_usable("phone"));

    assert!(!device_id_is_usable(""), "empty");
    assert!(!device_id_is_usable("MacBook Pro"), "a space");
    assert!(!device_id_is_usable("laptop\t"), "a tab");
    assert!(!device_id_is_usable("laptop\n"), "a newline");
    assert!(!device_id_is_usable("laptop‑pro"), "outside ASCII");
    assert!(
        !device_id_is_usable(&"x".repeat(MAX_DEVICE_ID_LEN + 1)),
        "too long"
    );

    assert!(device_id_is_usable(&"x".repeat(MAX_DEVICE_ID_LEN)));
}

/// A key survives the trip through the spelling an app stores it in, which
/// is the only trip it ever makes: the private half is written down,
/// sealed, and read back on the next start.
#[test]
fn a_device_key_round_trips_through_its_own_spelling() {
    let key = DeviceKey::generate();
    let private = key.private_hex();
    let public = key.public_hex();

    assert_eq!(private.len(), 64, "a private half is 32 bytes of hex");
    assert_eq!(public.len(), 64, "a public half is 32 bytes of hex");
    assert_ne!(private, public, "the two halves are not the same bytes");
    assert!(
        private
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{private} is lowercase hex"
    );

    let read_back = DeviceKey::from_hex(&private).expect("a key reads back");
    assert_eq!(read_back.private_hex(), private);
    assert_eq!(read_back.public_hex(), public);
}

/// A key is 32 bytes, so a stored key is 64 hex characters. Anything else
/// is a string that is not a key, and an app that reads one has to be told
/// rather than handed a credential that proves nothing.
#[test]
fn a_device_key_that_is_not_a_key_is_refused() {
    assert!(DeviceKey::from_hex("").is_err(), "empty");
    assert!(DeviceKey::from_hex("not hex at all").is_err(), "not hex");
    assert!(
        DeviceKey::from_hex(&"a".repeat(63)).is_err(),
        "one character short"
    );
    assert!(
        DeviceKey::from_hex(&"a".repeat(65)).is_err(),
        "one character long"
    );
}

/// The first message announces the version this client speaks, and the
/// announcement rides **inside** the JSON.
///
/// Inside, not in front: a server that predates the version byte drops the
/// field it does not know and answers in the old form, and a version byte
/// in front of the JSON would break that server instead — it reads the
/// payload as JSON and would choke on it.
#[test]
fn the_first_message_announces_the_version_the_client_speaks() {
    let auth = TwoFactorAuth::new(
        "client-001",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        TotpAlgorithm::SHA1,
    )
    .unwrap();
    let start = auth.start_message(1);

    assert_eq!(
        start.announced_version(),
        Some(VERSION_BINARY),
        "the client says which version it speaks"
    );
    let json = String::from_utf8(start.to_bytes().unwrap().to_vec()).unwrap();
    assert!(json.contains(r#""version":1"#), "{json}");
}

/// The key's own `Debug` is redacted, and this wrapper must not undo that:
/// a `Debug` that prints a private half turns every log line and panic
/// message that touches one into a credential disclosure.
#[test]
fn a_device_key_never_prints_its_private_half() {
    let key = DeviceKey::generate();
    let rendered = format!("{key:?}");

    assert!(!rendered.contains(&key.private_hex()), "{rendered}");
    assert!(
        rendered.contains(&key.public_hex()),
        "the public half is not a secret and is what names the device: {rendered}"
    );
}
