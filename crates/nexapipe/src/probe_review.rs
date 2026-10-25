//! Throwaway probes for the review. Not committed.
#![cfg(test)]

use crate::auth::otpauth::{normalize_secret, OtpAuthUri};
use crate::auth::{AuthConfig, ClientAuth, TotpValidator, Verified};
use nexapipe_proto::secret::SecretString;

#[test]
fn probe_base32_decode_of_short_secrets() {
    for s in ["A", "AB", "ABC", "JBSWY3DPEHPK3PXP", "AA", "===="] {
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s);
        println!("base32 {s:?} -> {decoded:?}");
    }
}

#[test]
fn probe_normalize_secret_short_and_huge() {
    for s in ["A", "AB", "", "  ", "JBSWY3DPEHPK3PXP"] {
        println!("normalize {s:?} -> {:?}", normalize_secret(s).map(|x| x.as_str().to_string()));
    }
    let huge = "A".repeat(1_000_000);
    let t = std::time::Instant::now();
    let n = normalize_secret(&huge);
    println!("huge -> len {:?} in {:?}", n.map(|x| x.as_str().len()), t.elapsed());
}

#[test]
fn probe_otpauth_uri_acceptance_matrix() {
    let cases: Vec<(&str, &str, &str, u32, u32)> = vec![
        ("NexaPipe", "c", "A", 6, 30),          // 1-char secret
        ("NexaPipe", "c", "AA", 6, 30),         // 2-char secret
        ("NexaPipe", "c", "JBSWY3DPEHPK3PXP", 6, 30),
        ("NexaPipe", "c", "JBSWY3DPEHPK3PXP", 11, 30), // digits > 10
        ("NexaPipe", "c", "JBSWY3DPEHPK3PXP", 10, 30), // digits == 10
        ("NexaPipe", "c", "JBSWY3DPEHPK3PXP", 6, 0),   // period == 0
        ("NexaPipe", "c", "JBSWY3DPEHPK3PXP", 0, 30),  // digits == 0
    ];
    for (issuer, id, secret, digits, period) in cases {
        match OtpAuthUri::new(issuer, id, secret, "sha1", digits, period) {
            Ok(u) => println!(
                "ACCEPTED secret={secret:?} digits={digits} period={period} -> uri={}",
                u.to_uri()
            ),
            Err(e) => println!("rejected secret={secret:?} digits={digits} period={period}: {e}"),
        }
    }
}

#[test]
fn probe_algorithm_allow_list() {
    for alg in [
        "sha1", "SHA1", "sha256", "SHA256", "sha512", "SHA512", "SHA256X", "sha1x", "sha1 ",
        " sha1", "sha-1", "SHA1\n", "sha1sha1", "md5", "sha3",
    ] {
        match OtpAuthUri::new("NexaPipe", "c", "JBSWY3DPEHPK3PXP", alg, 6, 30) {
            Ok(u) => println!("ACCEPTED algorithm={alg:?} -> {}", u.algorithm),
            Err(_) => println!("rejected algorithm={alg:?}"),
        }
    }
}

#[test]
fn probe_client_decode_secret_empty_key() {
    let client = ClientAuth {
        secret: SecretString::new("A".to_string()),
        created_at: String::new(),
        allow_hosts: None,
        allow_ports: None,
        allow_ports_strict: false,
        pending_enrollment: None,
        devices: Default::default(),
        unnamed_device_allowed: true,
        last_used: None,
        last_used_step: None,
        failed_attempts: 0,
        locked_until: None,
        enrollment_failed_attempts: 0,
        enrollment_locked_until: None,
    };
    match client.decode_secret() {
        Ok(b) => println!("decode_secret(\"A\") -> {} bytes: {:?}", b.as_slice().len(), b.as_slice()),
        Err(e) => println!("decode_secret(\"A\") -> error {e}"),
    }
}

#[test]
fn probe_verify_response_with_degenerate_secret() {
    let client = ClientAuth {
        secret: SecretString::new("A".to_string()),
        created_at: String::new(),
        allow_hosts: None,
        allow_ports: None,
        allow_ports_strict: false,
        pending_enrollment: None,
        devices: Default::default(),
        unnamed_device_allowed: true,
        last_used: None,
        last_used_step: None,
        failed_attempts: 0,
        locked_until: None,
        enrollment_failed_attempts: 0,
        enrollment_locked_until: None,
    };
    let mut config = AuthConfig::default();
    config.enabled = true;
    config.clients.insert("alice".to_string(), client);
    let validator = TotpValidator::new(&config);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let sig = nexapipe_proto::auth::hmac_challenge(&[], b"nonce", now).unwrap();
    let verdict = validator.verify_response("alice", None, b"nonce", now, &sig, "000000");
    println!("degenerate-secret verdict: {verdict:?}");
    let _ = Verified::WrongCode;
}

#[test]
fn probe_step_replay_semantics() {
    let mut config = AuthConfig::default();
    config.enabled = true;
    config.clients.insert("alice".to_string(), ClientAuth {
        secret: SecretString::new("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
        created_at: String::new(),
        allow_hosts: None,
        allow_ports: None,
        allow_ports_strict: false,
        pending_enrollment: None,
        devices: Default::default(),
        unnamed_device_allowed: true,
        last_used: None,
        last_used_step: None,
        failed_attempts: 0,
        locked_until: None,
        enrollment_failed_attempts: 0,
        enrollment_locked_until: None,
    });
    println!("step 100 first  -> {:?}", config.accept_step("alice", None, 100));
    println!("step 100 again  -> {:?}", config.accept_step("alice", None, 100));
    println!("step 99  (old)  -> {:?}", config.accept_step("alice", None, 99));
    println!("step 101        -> {:?}", config.accept_step("alice", None, 101));
}
