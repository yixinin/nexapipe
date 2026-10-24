//! The runtime 2FA state, kept beside the configuration instead of inside it.
//!
//! The configuration file is the operator's: they wrote it, they read it, they
//! keep it in version control, and a comment in it is a comment they wrote.
//! The counters a running server keeps — how many times a client mistyped a
//! code, until when it is locked out, when it was last seen — are none of
//! that. They are what the server learned while it was running, and they have
//! to survive a restart for a lockout to mean anything.
//!
//! Writing them into the configuration file made one file carry two things
//! that disagree about who owns it, and it had a cost beyond tidiness: the
//! file's modification time moved every time a client mistyped a code, and the
//! configuration watcher watches exactly that. A lockout was therefore a
//! configuration reload — the routes rebuilt and the health checks restarted,
//! because a stranger typed a code wrong.
//!
//! So the counters live in their own file, beside the configuration, and named
//! after it: `config.state.toml` next to `config.toml`. The shape is the same
//! on purpose: an operator who opens `config.state.toml` next to
//! `config.toml` sees the same client and device names in both, and a mistake
//! in one is a mistake in the other. The contents are not the same: only the
//! counters, and nothing an operator wrote.
//!
//! The name comes from the configuration's own name and not from the
//! directory it happens to sit in, so two configurations in one directory
//! have two state files. `config.toml` and `config.prod.toml` keep their
//! counters apart, instead of sharing one set of lockouts and one set of TOTP
//! step memories — a client that mistyped a code against the production
//! server walked the staging server's lockout too, and a code used against
//! one was refused against the other.
//!
//! A deployment that predates that rule keeps its state in `state.toml`, in
//! the configuration's own directory. That file is read when the state's own
//! file is not there yet, so an upgrade does not start the server with an
//! empty memory: no lockouts, and no memory of the TOTP steps that were
//! already used.
//!
//! What is in the configuration file stays there. The three keys
//! (`failed_attempts`, `locked_until`, `last_used`) are still read from it, so
//! a deployment that was counting in the configuration file before this
//! existed keeps its lockouts; they are simply no longer written there, and
//! the state file is what decides once it has an entry for that client.

use super::config::{AuthConfig, ClientAuth};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The file the runtime state lives in, beside the configuration file.
///
/// The name comes from the configuration's own name, so two configurations in
/// one directory have two state files: a configuration in
/// `/etc/nexapipe/config.toml` puts its state in
/// `/etc/nexapipe/config.state.toml`, and `/etc/nexapipe/config.prod.toml`
/// puts its state in `/etc/nexapipe/config.prod.state.toml`. One name for
/// both of them meant one state file for both of them, and a state file
/// holds the lockout counters and the TOTP step memories — so a client that
/// mistyped a code against the production server walked the staging server's
/// lockout too, and a code used against one was refused against the other.
///
/// The rule is the configuration's name with `state` in it: the file name
/// without its extension, then `.state.toml`. A configuration with no file
/// name of its own — no path at all, or the current directory — keeps the
/// old answer, `state.toml` beside it.
pub fn path_for(config_path: &str) -> PathBuf {
    let path = Path::new(config_path);
    match path.file_name() {
        Some(name) => {
            let stem = Path::new(name).file_stem().unwrap_or(name);
            path.with_file_name(format!("{}.state.toml", stem.to_string_lossy()))
        }
        None => state_beside(path),
    }
}

/// The legacy name: `state.toml` in the configuration's own directory.
///
/// This is where a deployment that predates the naming rule keeps its
/// counters, and it is what [`load`] reads when the state's own file is not
/// there yet.
fn legacy_path(path: &Path) -> Option<PathBuf> {
    let legacy = state_beside(path);
    (legacy != path).then_some(legacy)
}

/// `state.toml` beside `path`.
///
/// The directory is the one the path is in, and the current directory when
/// the path has none of its own.
fn state_beside(path: &Path) -> PathBuf {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent.join("state.toml"),
        None => PathBuf::from("state.toml"),
    }
}

/// The runtime state of every client the server has counted.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeState {
    /// The counters, per client.
    #[serde(default)]
    pub clients: HashMap<String, ClientState>,
}

/// What the server knows about one client's authentication.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientState {
    /// How many times in a row the client got it wrong.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub failed_attempts: u32,
    /// When the lockout runs out, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<u64>,
    /// How many times in a row a guess at the pending enrollment token was
    /// wrong.
    ///
    /// The enrollment's own counter, kept apart from `failed_attempts` for the
    /// reason [`crate::auth::ClientAuth::enrollment_failed_attempts`] gives: a
    /// client id is not a secret, so a stranger who knows one must not be able
    /// to lock the client's own devices out of authenticating.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub enrollment_failed_attempts: u32,
    /// When the enrollment lockout runs out, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_locked_until: Option<u64>,
    /// The fingerprint of the pending enrollment token the two counters above
    /// were paid for.
    ///
    /// The counters belong to a **token**, not to the client: a guess at one
    /// invite says nothing about the next one, and a token that was rotated
    /// away must not hand its count to the token that replaced it. The file
    /// says which token paid, so the file and the configuration can be
    /// compared on the next start and the counters can be left behind when
    /// the two no longer name the same token.
    ///
    /// A digest rather than the token: the token is a credential, and the
    /// state file is not where credentials go.
    ///
    /// `None` means the file does not say — a state file written before this
    /// rule existed. Such a file keeps its counters, so that an upgrade does
    /// not hand every lockout back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token_fingerprint: Option<String>,
    /// When the client last authenticated, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<u64>,
    /// The last TOTP step the client's own secret was accepted on.
    ///
    /// The step, not the code: a code changes every thirty seconds, and
    /// RFC 6238 §5.2 asks a verifier to remember the **step** so that the
    /// same code cannot be used twice.
    ///
    /// This is the **unnamed** device's memory — the client answering with
    /// its own secret. A named device keeps its own, under its own entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_step: Option<u64>,
    /// The per-device stamps.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub devices: HashMap<String, DeviceState>,
}

/// What the server knows about one device of a client.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceState {
    /// When the device last authenticated, as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<u64>,
    /// The last TOTP step the device's code was accepted on.
    ///
    /// The step, not the code: a code changes every thirty seconds, and
    /// RFC 6238 §5.2 asks a verifier to remember the **step** so that the
    /// same code cannot be used twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_step: Option<u64>,
}

/// A zero counter is not written: a state file that accumulated
/// `failed_attempts = 0` lines for every client that ever existed would say
/// less than one that says nothing.
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// The fingerprint of an enrollment token.
///
/// A digest, not the token: the state file says which token its enrollment
/// counters were paid for, and it says it without writing a second copy of a
/// credential down. SHA-256, cut to sixteen bytes — enough that two tokens do
/// not share one, and short enough that the file does not grow a line per
/// client.
fn token_fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(token.as_bytes());
    hex::encode(&digest[..16])
}

/// The fingerprint of the token a client's enrollment counters were paid for.
///
/// `None` when the client is not waiting to enroll, or when the counters say
/// nothing: a fingerprint without a counter behind it binds nothing.
fn enrollment_fingerprint(client: &ClientAuth) -> Option<String> {
    if client.enrollment_failed_attempts == 0 && client.enrollment_locked_until.is_none() {
        return None;
    }
    client
        .pending_enrollment
        .as_ref()
        .map(|token| token_fingerprint(token.expose_secret()))
}

/// The file on disk, in the shape it is written.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StateFile {
    /// The same section the configuration file uses, so the two read alike.
    #[serde(default)]
    auth: StateSection,
}

/// The `[auth]` section of the state file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StateSection {
    /// The per-client counters.
    #[serde(default)]
    clients: HashMap<String, ClientState>,
}

/// Reads the runtime state.
///
/// A file that is not there is an empty state, not an error: this is the
/// first start of a deployment that has never counted anything, and it is the
/// normal state of a deployment whose state file was removed by an operator
/// who wanted the lockouts gone.
///
/// A file that is there and cannot be read **is** an error, and the server
/// refuses to start on it. A state file that cannot be parsed is a state
/// whose lockouts are unknown, and a server that starts anyway is a server
/// that has just reset every lockout it had — which is exactly what an
/// attacker who can damage one file wants. The message says which file and
/// what to do about it, because an operator who cannot start their proxy
/// needs a way forward rather than a refusal.
pub fn load(path: &Path) -> anyhow::Result<RuntimeState> {
    let Some((path, content)) = read_state_file(path)? else {
        return Ok(RuntimeState::default());
    };

    let file: StateFile = toml::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "the 2FA state {} cannot be read ({e}); fix it or remove it to start without the \
             lockouts it holds",
            path.display()
        )
    })?;

    Ok(RuntimeState {
        clients: file.auth.clients,
    })
}

/// The file the state is read from, and its content.
///
/// The state's own file first, and the legacy `state.toml` beside it when
/// that one is not there yet — the file a deployment that predates the naming
/// rule has. The counters it holds are the counters the server had before
/// the upgrade, so an upgrade does not hand every client a fresh start: the
/// lockouts stay, and so does the memory of the TOTP steps that were already
/// used.
///
/// The legacy file is read and not written. The state is written to the file
/// named after the configuration from then on, and the legacy file is left
/// where it is: another configuration in the same directory may still be
/// counting on it, and taking it away could take a lockout away from a
/// server that has not migrated yet.
fn read_state_file(path: &Path) -> anyhow::Result<Option<(PathBuf, String)>> {
    if let Some(content) = read_optional(path)? {
        return Ok(Some((path.to_path_buf(), content)));
    }

    let Some(legacy) = legacy_path(path) else {
        return Ok(None);
    };
    Ok(read_optional(&legacy)?.map(|content| (legacy, content)))
}

/// The file's content, or `None` when the file is not there.
fn read_optional(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => anyhow::bail!("cannot read the 2FA state {}: {e}", path.display()),
    }
}

/// Writes the runtime state.
///
/// The file is the one named after the configuration, so two configurations
/// in one directory do not write over each other's counters.
///
/// The write is a temporary file and a rename, like the configuration's, so a
/// process killed in the middle of it leaves the old state rather than a
/// half-written one — a half-written state file would not parse, and the
/// server refuses to start on one.
///
/// The mode is `0600`, like the configuration's: the file says which clients
/// are locked out and when they were last seen, which is not a secret but is
/// not the business of every local account either.
pub fn save(path: &Path, state: &RuntimeState) -> anyhow::Result<()> {
    let file = StateFile {
        auth: StateSection {
            clients: state.clients.clone(),
        },
    };
    let contents = toml::to_string_pretty(&file)
        .map_err(|e| anyhow::anyhow!("cannot render the 2FA state: {e}"))?;

    crate::config::write_config_file(&path.to_string_lossy(), &contents)
}

/// The counters of every client and device in `config`.
///
/// This is what gets written: the credentials, the host lists and the
/// enrollment tokens stay where they are, and only the counters travel.
///
/// A client the server has never counted is left out. The snapshot carries
/// every client the configuration knows about, and writing all of them would
/// fill the state file with empty tables for clients that never mistyped a
/// code. A device is left out on the same grounds — a stamp is the only thing
/// a device has.
pub fn snapshot(config: &AuthConfig) -> RuntimeState {
    let mut clients = HashMap::with_capacity(config.clients.len());
    for (id, client) in &config.clients {
        let mut devices = HashMap::with_capacity(client.devices.len());
        for (name, device) in &client.devices {
            // A device that has neither stamp is not written at all. A device
            // that has only the **step** is: the memory of the step it
            // accepted is what refuses the second use of a code, and a server
            // that forgot it over a restart would accept one.
            if device.last_used.is_none() && device.last_used_step.is_none() {
                continue;
            }
            devices.insert(
                name.clone(),
                DeviceState {
                    last_used: device.last_used,
                    last_used_step: device.last_used_step,
                },
            );
        }

        let state = ClientState {
            failed_attempts: client.failed_attempts,
            locked_until: client.locked_until,
            enrollment_failed_attempts: client.enrollment_failed_attempts,
            enrollment_locked_until: client.enrollment_locked_until,
            enrollment_token_fingerprint: enrollment_fingerprint(client),
            last_used: client.last_used,
            last_used_step: client.last_used_step,
            devices,
        };
        if is_empty(&state) {
            continue;
        }
        clients.insert(id.clone(), state);
    }
    RuntimeState { clients }
}

/// Whether a client has nothing worth writing down.
fn is_empty(state: &ClientState) -> bool {
    state.failed_attempts == 0
        && state.locked_until.is_none()
        && state.enrollment_failed_attempts == 0
        && state.enrollment_locked_until.is_none()
        && state.last_used.is_none()
        && state.last_used_step.is_none()
        && state.devices.is_empty()
}

/// Moves the counters in `state` onto `config`.
///
/// A client the state file has no entry for keeps the counters it was loaded
/// with. That is the migration: a deployment that counted in the
/// configuration file before the state file existed still holds its lockouts,
/// and the first time the server counts that client again the state file
/// gains an entry for it and takes over.
///
/// A client the state file has but the configuration does not is ignored: the
/// operator removed it, and a counter nobody can authenticate against is
/// nothing to keep.
///
/// The **enrollment** counters are the ones that need a second look. They
/// were paid for a token, and the file says which one; when the configuration
/// names a different token — or none — the count belongs to an invite that no
/// longer exists, and it is left behind rather than handed to the invite that
/// replaced it. A file that does not say which token it means is a file
/// written before the rule existed, and it keeps its counters: an upgrade must
/// not hand every lockout back.
pub fn apply(state: &RuntimeState, config: &mut AuthConfig) {
    for (id, client) in &mut config.clients {
        let Some(client_state) = state.clients.get(id) else {
            continue;
        };
        client.failed_attempts = client_state.failed_attempts;
        client.locked_until = client_state.locked_until;
        if enrollment_counters_belong_to_this_token(client_state, client) {
            client.enrollment_failed_attempts = client_state.enrollment_failed_attempts;
            client.enrollment_locked_until = client_state.enrollment_locked_until;
        }
        client.last_used = client_state.last_used;
        client.last_used_step = client_state.last_used_step;

        for (name, device) in &mut client.devices {
            if let Some(device_state) = client_state.devices.get(name) {
                device.last_used = device_state.last_used;
                device.last_used_step = device_state.last_used_step;
            }
        }
    }
}

/// Whether the enrollment counters in the file are the ones this client owes.
///
/// The file says which token paid for them; the client says which token it is
/// waiting to enroll with. The two have to be the same token, or the counters
/// are about an invite that is gone.
///
/// A file that does not say which token it means — one written before the
/// fingerprint was recorded — keeps its counters. The alternative would reset
/// every lockout a deployment holds the first time it is upgraded, which is
/// the one thing a lockout is not allowed to do.
fn enrollment_counters_belong_to_this_token(state: &ClientState, client: &ClientAuth) -> bool {
    let Some(recorded) = &state.enrollment_token_fingerprint else {
        return true;
    };
    let Some(pending) = client.pending_enrollment.as_ref() else {
        // The client is not waiting to enroll at all, so the invite the
        // counters were paid for is gone.
        return false;
    };
    recorded == &token_fingerprint(pending.expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::ClientAuth;

    fn client(
        failed_attempts: u32,
        locked_until: Option<u64>,
        last_used: Option<u64>,
    ) -> ClientAuth {
        ClientAuth {
            secret: nexapipe_proto::secret::SecretString::new(
                "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
            ),
            created_at: "0".to_string(),
            allow_hosts: None,
            allow_ports: None,
            allow_ports_strict: false,
            pending_enrollment: None,
            devices: HashMap::new(),
            unnamed_device_allowed: true,
            last_used,
            last_used_step: None,
            failed_attempts,
            locked_until,
            enrollment_failed_attempts: 0,
            enrollment_locked_until: None,
        }
    }

    /// A client that is waiting to enroll, with the counters the guesses at
    /// that token cost.
    fn client_waiting_for(token: &str, enrollment_failed_attempts: u32) -> ClientAuth {
        let mut client = client(0, None, None);
        client.pending_enrollment =
            Some(nexapipe_proto::secret::SecretString::new(token.to_string()));
        client.enrollment_failed_attempts = enrollment_failed_attempts;
        client
    }

    /// The step memory survives a write and a read.
    ///
    /// The state file is what carries it, and a server that forgot it over a
    /// restart would accept the second use of a code — which is the whole
    /// point of remembering it.
    #[test]
    fn the_step_memory_survives_a_write_and_a_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        let mut alice = client(0, None, None);
        alice.devices.insert(
            "laptop".to_string(),
            crate::auth::DeviceAuth {
                secret: nexapipe_proto::secret::SecretString::new(
                    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
                ),
                public_key: None,
                created_at: "0".to_string(),
                last_used: None,
                last_used_step: None,
            },
        );
        config.clients.insert("alice".to_string(), alice);

        // The client authenticates: the client's own secret on one step, and
        // the named device on the same one.
        config.accept_step("alice", None, 100);
        config.accept_step("alice", Some("laptop"), 100);

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let state = load(&path).expect("the file reads back");

        let mut restored = AuthConfig::default();
        let mut alice = client(0, None, None);
        alice.devices.insert(
            "laptop".to_string(),
            crate::auth::DeviceAuth {
                secret: nexapipe_proto::secret::SecretString::new(
                    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
                ),
                public_key: None,
                created_at: "0".to_string(),
                last_used: None,
                last_used_step: None,
            },
        );
        restored.clients.insert("alice".to_string(), alice);
        apply(&state, &mut restored);

        // Both memories came back, so both refuse a step behind the one they
        // accepted.
        assert_eq!(
            restored.accept_step("alice", None, 99),
            crate::auth::config::StepVerdict::Refused,
            "the client's own memory survived"
        );
        assert_eq!(
            restored.accept_step("alice", Some("laptop"), 99),
            crate::auth::config::StepVerdict::Refused,
            "the device's memory survived"
        );
    }

    #[test]
    fn a_state_that_is_not_there_is_an_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let state = load(&path).expect("a file that is not there is not an error");
        assert!(state.clients.is_empty());
    }

    #[test]
    fn a_state_that_cannot_be_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        std::fs::write(&path, "this is not TOML at all: \"\n").unwrap();
        let error = load(&path).expect_err("a broken state file refuses the start");
        assert!(
            error.to_string().contains("state.toml"),
            "the message names the file: {error}"
        );
    }

    #[test]
    fn the_counters_survive_a_write_and_a_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config.clients.insert(
            "alice".to_string(),
            client(2, Some(1700000000), Some(1699999999)),
        );

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let state = load(&path).expect("the read succeeds");

        let alice = &state.clients["alice"];
        assert_eq!(alice.failed_attempts, 2);
        assert_eq!(alice.locked_until, Some(1700000000));
        assert_eq!(alice.last_used, Some(1699999999));
    }

    #[test]
    fn a_zero_counter_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(0, None, None));

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("failed_attempts"),
            "a zero counter says nothing: {on_disk}"
        );
        assert!(!on_disk.contains("locked_until"), "{on_disk}");
        assert!(!on_disk.contains("last_used"), "{on_disk}");
    }

    #[test]
    fn the_state_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(1, None, None));

        save(&path, &snapshot(&config)).expect("the write succeeds");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the state file is private: {mode:o}");
        }
    }

    /// The state file is named after the configuration file.
    ///
    /// The name is the configuration's own, so an operator who sees
    /// `config.prod.state.toml` next to `config.prod.toml` knows what it
    /// belongs to without reading the source.
    #[test]
    fn the_state_file_is_named_after_the_configuration() {
        assert_eq!(
            path_for("/etc/nexapipe/config.toml"),
            PathBuf::from("/etc/nexapipe/config.state.toml")
        );
        assert_eq!(
            path_for("/etc/nexapipe/config.prod.toml"),
            PathBuf::from("/etc/nexapipe/config.prod.state.toml")
        );
        assert_eq!(path_for("config.toml"), PathBuf::from("config.state.toml"));
    }

    /// A configuration with no file name of its own keeps the old name.
    #[test]
    fn a_configuration_with_no_file_name_keeps_the_old_name() {
        assert_eq!(path_for(""), PathBuf::from("state.toml"));
        assert_eq!(path_for("."), PathBuf::from("state.toml"));
        assert_eq!(path_for("/"), PathBuf::from("state.toml"));
    }

    /// Two configurations in one directory have two state files.
    ///
    /// One state file for both of them meant one set of lockout counters and
    /// one set of TOTP step memories for two servers that were never meant to
    /// know about each other: a client that mistyped a code against the
    /// production server walked the staging server's lockout too.
    #[test]
    fn two_configurations_in_one_directory_have_two_state_files() {
        assert_ne!(
            path_for("/etc/nexapipe/config.toml"),
            path_for("/etc/nexapipe/config.prod.toml")
        );
    }

    /// The state path of a `config.toml` in `dir`.
    fn state_path_in(dir: &Path) -> PathBuf {
        let config = dir.join("config.toml").to_string_lossy().into_owned();
        path_for(&config)
    }

    /// The legacy state file is read when the state's own file is not there
    /// yet.
    ///
    /// This is the file a deployment that predates the naming rule has, and
    /// an upgrade that ignored it would start the server with an empty
    /// memory: every lockout reset, and a TOTP code that was already used
    /// accepted again.
    #[test]
    fn the_legacy_state_file_is_read_when_the_new_one_is_not_there_yet() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("state.toml"),
            "[auth.clients.alice]\nfailed_attempts = 3\nlocked_until = 4102444800\n",
        )
        .unwrap();

        let state_path = state_path_in(dir.path());
        assert_eq!(state_path, dir.path().join("config.state.toml"));

        let state = load(&state_path).expect("the legacy state file reads");
        let alice = &state.clients["alice"];
        assert_eq!(alice.failed_attempts, 3, "the lockout survived the upgrade");
        assert_eq!(alice.locked_until, Some(4102444800));
    }

    /// The step memory survives the upgrade.
    ///
    /// The state file is what refuses the second use of a code, so an
    /// upgrade that forgot it would accept a code that was already used.
    #[test]
    fn the_step_memory_survives_the_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("state.toml"),
            "[auth.clients.alice]\nlast_used_step = 100\n",
        )
        .unwrap();

        let state = load(&state_path_in(dir.path())).expect("the legacy state file reads");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(0, None, None));
        apply(&state, &mut config);

        assert_eq!(config.clients["alice"].last_used_step, Some(100));
        assert_eq!(
            config.accept_step("alice", None, 99),
            crate::auth::config::StepVerdict::Refused,
            "a code that was already used is still refused"
        );
    }

    /// The state's own file wins over the legacy one.
    ///
    /// The legacy file is what the deployment had before the upgrade; once
    /// the state has a file of its own, that is the answer.
    #[test]
    fn the_new_state_file_wins_over_the_legacy_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("state.toml"),
            "[auth.clients.alice]\nfailed_attempts = 3\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.state.toml"),
            "[auth.clients.alice]\nfailed_attempts = 1\n",
        )
        .unwrap();

        let state = load(&state_path_in(dir.path())).expect("the state file reads");

        assert_eq!(state.clients["alice"].failed_attempts, 1);
    }

    /// The state is written to the file named after the configuration, and the
    /// legacy file is left alone.
    ///
    /// Another configuration in the same directory may still be counting on
    /// the legacy file, and taking it away could take a lockout away from a
    /// server that has not migrated yet.
    #[test]
    fn the_state_is_written_to_the_file_named_after_the_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("state.toml");
        std::fs::write(&legacy, "[auth.clients.alice]\nfailed_attempts = 3\n").unwrap();

        let state_path = state_path_in(dir.path());

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(1, None, None));

        save(&state_path, &snapshot(&config)).expect("the write succeeds");

        let on_disk = std::fs::read_to_string(&state_path).unwrap();
        assert!(on_disk.contains("failed_attempts = 1"), "{on_disk}");
        assert_eq!(
            std::fs::read_to_string(&legacy).unwrap(),
            "[auth.clients.alice]\nfailed_attempts = 3\n",
            "the legacy file is left as it was"
        );
    }

    #[test]
    fn a_client_the_state_does_not_know_keeps_its_loaded_counters() {
        // The migration: a deployment that counted in the configuration file
        // keeps its lockout until the state file has an entry for it.
        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(3, Some(1700000000), None));

        apply(&RuntimeState::default(), &mut config);

        let alice = &config.clients["alice"];
        assert_eq!(alice.failed_attempts, 3);
        assert_eq!(alice.locked_until, Some(1700000000));
    }

    #[test]
    fn the_state_wins_over_the_loaded_counters() {
        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(3, Some(1700000000), None));

        let mut state = RuntimeState::default();
        state.clients.insert(
            "alice".to_string(),
            ClientState {
                failed_attempts: 0,
                locked_until: None,
                enrollment_failed_attempts: 0,
                enrollment_locked_until: None,
                enrollment_token_fingerprint: None,
                last_used: Some(1699999999),
                last_used_step: None,
                devices: HashMap::new(),
            },
        );

        apply(&state, &mut config);

        let alice = &config.clients["alice"];
        assert_eq!(alice.failed_attempts, 0);
        assert_eq!(alice.locked_until, None);
        assert_eq!(alice.last_used, Some(1699999999));
    }

    #[test]
    fn a_client_the_configuration_does_not_have_is_ignored() {
        let mut config = AuthConfig::default();
        let mut state = RuntimeState::default();
        state.clients.insert(
            "gone".to_string(),
            ClientState {
                failed_attempts: 9,
                locked_until: None,
                enrollment_failed_attempts: 0,
                enrollment_locked_until: None,
                enrollment_token_fingerprint: None,
                last_used: None,
                last_used_step: None,
                devices: HashMap::new(),
            },
        );

        apply(&state, &mut config);

        assert!(
            config.clients.is_empty(),
            "a client the operator removed stays removed: {:?}",
            config.clients
        );
    }

    /// The file says which token its enrollment counters were paid for.
    ///
    /// Without that, a rotated token inherits the count of the one it
    /// replaced, and the file cannot tell the two apart on the next start.
    #[test]
    fn the_file_says_which_token_the_enrollment_counters_were_paid_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client_waiting_for("old-token", 5));

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let state = load(&path).expect("the file reads back");

        let alice = &state.clients["alice"];
        assert_eq!(alice.enrollment_failed_attempts, 5);
        assert_eq!(
            alice.enrollment_token_fingerprint,
            Some(token_fingerprint("old-token")),
            "the file names the token the count was paid for"
        );
    }

    /// The token itself is not written down.
    ///
    /// The fingerprint says which token the counters belong to; the token is a
    /// credential, and the state file is not where credentials go.
    #[test]
    fn the_file_does_not_carry_the_token_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client_waiting_for("old-token", 5));

        save(&path, &snapshot(&config)).expect("the write succeeds");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("old-token"), "{on_disk}");
    }

    /// The counters a token was paid for do not follow the token that
    /// replaced it.
    ///
    /// This is the whole point: the operator rotates the invite, and the new
    /// invite starts with nothing spent on it — even across a restart, which
    /// is where the file's half of the counters used to come back from.
    #[test]
    fn the_counters_do_not_follow_a_replaced_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client_waiting_for("old-token", 5));

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let state = load(&path).expect("the file reads back");

        // The operator rotated the invite while the server was not running.
        let mut rotated = AuthConfig::default();
        rotated
            .clients
            .insert("alice".to_string(), client_waiting_for("new-token", 0));

        apply(&state, &mut rotated);

        assert_eq!(
            rotated.clients["alice"].enrollment_failed_attempts, 0,
            "the new invite starts with nothing spent on it"
        );
    }

    /// The counters stay with the token they were paid for.
    ///
    /// The other half of the rule: a client that is still waiting to enroll
    /// with the same token keeps its lockout.
    #[test]
    fn the_counters_stay_with_the_token_they_were_paid_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client_waiting_for("the-token", 3));

        save(&path, &snapshot(&config)).expect("the write succeeds");
        let state = load(&path).expect("the file reads back");

        let mut restored = AuthConfig::default();
        restored
            .clients
            .insert("alice".to_string(), client_waiting_for("the-token", 0));

        apply(&state, &mut restored);

        assert_eq!(
            restored.clients["alice"].enrollment_failed_attempts, 3,
            "the lockout survives the restart"
        );
    }

    /// A file that does not say which token it means keeps its counters.
    ///
    /// A state file written before the fingerprint was recorded says nothing,
    /// and the alternative would reset every lockout a deployment holds the
    /// first time it is upgraded — which is the one thing a lockout is not
    /// allowed to do.
    #[test]
    fn a_file_that_does_not_say_keeps_its_counters() {
        let mut state = RuntimeState::default();
        state.clients.insert(
            "alice".to_string(),
            ClientState {
                failed_attempts: 0,
                locked_until: None,
                enrollment_failed_attempts: 4,
                enrollment_locked_until: Some(1700000000),
                enrollment_token_fingerprint: None,
                last_used: None,
                last_used_step: None,
                devices: HashMap::new(),
            },
        );

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client_waiting_for("some-token", 0));

        apply(&state, &mut config);

        assert_eq!(
            config.clients["alice"].enrollment_failed_attempts, 4,
            "an upgrade does not hand every lockout back"
        );
        assert_eq!(
            config.clients["alice"].enrollment_locked_until,
            Some(1700000000)
        );
    }

    /// The counters of an invite that is gone do not come back.
    ///
    /// The token was spent, or the operator withdrew the invite: either way
    /// there is no invite left to lock out, and the count that was paid for it
    /// has nothing to say about the client.
    #[test]
    fn the_counters_of_an_invite_that_is_gone_do_not_come_back() {
        let mut state = RuntimeState::default();
        state.clients.insert(
            "alice".to_string(),
            ClientState {
                failed_attempts: 0,
                locked_until: None,
                enrollment_failed_attempts: 4,
                enrollment_locked_until: Some(1700000000),
                enrollment_token_fingerprint: Some(token_fingerprint("old-token")),
                last_used: None,
                last_used_step: None,
                devices: HashMap::new(),
            },
        );

        let mut config = AuthConfig::default();
        config
            .clients
            .insert("alice".to_string(), client(0, None, None));

        apply(&state, &mut config);

        assert_eq!(config.clients["alice"].enrollment_failed_attempts, 0);
        assert_eq!(config.clients["alice"].enrollment_locked_until, None);
    }
}
