//! The credential half of the configuration file.
//!
//! The shapes here are the ones on disk, which are not the shapes the server
//! holds: the file says when a client was enrolled and the server says what it
//! enrolled, and the two are translated into each other.

use crate::toml_zeroize::ZeroizedValue;

use nexapipe_proto::secret::SecretString;

use serde::Deserialize;

use std::collections::HashMap;

use std::path::Path;

use super::*;

/// Authentication config in TOML format.
///
/// Unknown keys are refused here, and only here. This is the one section where
/// a typo is a security change rather than a lost setting: `enable = true`
/// instead of `enabled` left 2FA off with nothing in the log to say so, since
/// serde drops what it does not recognise and the default for `enabled` is
/// false. Every other section stays lenient, the way a config that has carried
/// a stray key for years expects.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthTomlConfig {
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    pub algorithm: Option<String>,
    pub time_step: Option<u32>,
    pub digits: Option<u32>,
    pub window: Option<u32>,
    pub max_attempts: Option<u32>,
    pub lockout_duration: Option<u64>,
    pub clients: Option<HashMap<String, ClientAuthToml>>,
}

/// One `[auth.clients.<id>]` entry.
///
/// Unknown keys are refused for the same reason as in [`AuthTomlConfig`]: a
/// misspelled `allow_host` is not "no restriction", but that is what it
/// quietly became.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthToml {
    /// A [`SecretString`]: the seed is a credential from the moment the file
    /// is read, and the file format is unchanged by the wrapper.
    pub secret: SecretString,
    pub created_at: Option<String>,
    /// Host patterns this client may reach; `None` means every route. Folded
    /// into the client's [`crate::auth::ClientAcl`] when a connection
    /// authenticates.
    pub allow_hosts: Option<Vec<String>>,
    /// Ports this client may reach; `None` means every port.
    ///
    /// The other half of `allow_hosts`: a host is a name, a port is a service
    /// on that name, and a client that may have the name does not
    /// automatically get every service on it.
    pub allow_ports: Option<Vec<u16>>,
    /// Whether `allow_ports` is checked against the port the request is served
    /// from rather than the one the client names.
    ///
    /// Off by default: turning it on changes what an existing configuration
    /// allows, so an operator opts in.
    pub allow_ports_strict: Option<bool>,
    /// A one-time enrollment token outstanding for this client, written by
    /// `--generate-invite --registration` and cleared by whoever spends it. Not
    /// written back by `save_auth_state`: it belongs to the operator, not to
    /// the runtime.
    pub pending_enrollment: Option<SecretString>,
    /// `[auth.clients.<id>.devices.<name>]` — credentials issued to individual
    /// devices, each with a secret of its own so one can be dropped without
    /// rotating the others. Absent means this client has never issued one, and
    /// every device then shares the `secret` above.
    pub devices: Option<HashMap<String, DeviceAuthToml>>,
    /// Whether a peer that names no device may still answer with the `secret`
    /// above. Defaults to `true`, which is the only spelling a client that
    /// predates the device table can authenticate under.
    pub unnamed_device_allowed: Option<bool>,
    /// Runtime counters, read here so a lockout survives a restart.
    ///
    /// The server writes these to its own state file now, beside this one, and
    /// not here — see [`crate::auth::state`]. They are still read from this
    /// file, so a deployment that counted here before the state file existed
    /// keeps its lockouts; the state file takes over once it has an entry for
    /// this client.
    pub failed_attempts: Option<u32>,
    pub locked_until: Option<u64>,
    pub last_used: Option<u64>,
}

/// One `[auth.clients.<id>.devices.<name>]` entry.
///
/// Unknown keys are refused for the same reason as in [`ClientAuthToml`]. There
/// is no `allow_hosts` here on purpose: what a client may reach is answered by
/// the client's entry alone, and a second place to say it is a second place for
/// it to disagree.
///
/// One of `secret` and `public_key` has to be set and the other has to not be,
/// which the loader enforces where the operator can see which entry it is
/// about; both fields are `Option` so that either spelling parses far enough to
/// be told what is wrong with it.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthToml {
    pub secret: Option<SecretString>,
    /// The device's Ed25519 public key, hex: the credential of a device that
    /// signs its handshake instead of answering with a TOTP code.
    pub public_key: Option<String>,
    pub created_at: Option<String>,
    /// Read here so "when did this device last connect" survives a restart.
    ///
    /// The stamp is written to the server's state file, beside the
    /// configuration, and not here — see [`crate::auth::state`].
    pub last_used: Option<u64>,
}

/// Checks a credential sidecar file's permissions before its secret becomes
/// live.
///
/// These files hold one secret and nothing else — the endpoint key a
/// `secret_key_file` / `NEXAPIPE_IROH_SECRET_KEY_FILE` points at, a relay
/// token file, or the admin IPC token — so there is no "nothing live in it
/// yet" half-way case, as the old config-file gate had: a file another
/// account can read or write is refused outright. `config.toml` itself is deliberately no
/// longer checked: operator-edited bind mounts are commonly 0644, and the
/// credentials now belong in a sidecar like this one or in the environment.
/// A file that cannot be stat'ed is not this function's problem: the caller
/// has already read it to get here.
#[cfg(unix)]
pub fn check_credential_file_permissions(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{path} is readable or writable by other accounts (mode {mode:o}) and holds a \
             credential; run `chmod 600 {path}`"
        );
    }
    Ok(())
}

/// No file modes to inspect outside Unix, so there is nothing to refuse.
#[cfg(not(unix))]
pub fn check_credential_file_permissions(_path: &str) -> anyhow::Result<()> {
    Ok(())
}

impl ProxyConfig {
    /// Load config and extract auth settings from TOML
    pub fn load_with_auth(path: &str) -> anyhow::Result<(Self, Option<crate::auth::AuthConfig>)> {
        // The file can hold the 2FA seeds in the clear, so the text it is read
        // into is wiped when it goes out of scope.
        let content = SecretString::new(std::fs::read_to_string(path)?);

        // Parse the base config
        let mut base: Self = parse_config(content.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
        base.resolve_external_credentials(Path::new(path).parent())?;

        // No `[auth]` section: there is nothing to read out of one, and the
        // tree that holds it does not have to be built. The top-level parse
        // already knows whether the section is there.
        if base.auth.is_none() {
            return Ok((base, None));
        }

        // Try to parse auth section separately
        // Note `toml::from_str`, not `str::parse`: `Value::from_str` reads a
        // single TOML *value*, so it rejects a whole document with "unexpected
        // content, expected nothing" and silently leaves 2FA disabled.
        let mut auth_config = match toml::from_str::<toml::Value>(content.expose_secret()) {
            Ok(toml_value) => {
                // The tree is a copy of the file in plain strings, the seeds
                // included, and it is dropped on every way out of here — the
                // error paths as much as the successful one. A guard wipes it
                // on the way instead of leaving it to the allocator.
                let mut toml_value = ZeroizedValue::new(toml_value);
                // Moved out of the tree rather than borrowed out of it: a
                // clone is a second copy of the seeds, and the section that is
                // moved hands its strings to the zeroizing fields the parse
                // fills.
                let auth_section = toml_value
                    .table_mut()
                    .and_then(|table| table.remove("auth"));
                if let Some(auth_section) = auth_section {
                    let auth_toml: AuthTomlConfig = auth_section
                        .try_into()
                        .map_err(|e| anyhow::anyhow!("Failed to parse auth config: {}", e))?;

                    let mut clients = HashMap::new();
                    if let Some(clients_toml) = auth_toml.clients {
                        for (id, client_toml) in clients_toml {
                            // An empty token compares equal to an empty
                            // ENROLL_START — see `conn::enroll_client` — so
                            // `pending_enrollment = ""` would hand a fresh
                            // secret to anybody who asks. Refused at load time
                            // rather than read as "no enrollment outstanding":
                            // the way to close an enrollment is to delete the
                            // key, and a blank one is a typo with a wide door
                            // behind it.
                            if client_toml
                                .pending_enrollment
                                .as_ref()
                                .map(|token| token.expose_secret().as_str())
                                == Some("")
                            {
                                anyhow::bail!(
                                    "[auth.clients.{id}]: pending_enrollment is empty; delete the \
                                     key instead of setting it to \"\""
                                );
                            }
                            // An allow-hosts entry is a host pattern, and a
                            // loose one authorizes more than it names: the same
                            // refusal a route's `host_pattern` gets.
                            for host in client_toml.allow_hosts.iter().flatten() {
                                if let Some(why) = crate::routes::pattern_error(host) {
                                    anyhow::bail!(
                                        "[auth.clients.{id}]: allow_hosts entry {host:?} {why}"
                                    );
                                }
                            }
                            // A port of zero is not a port a client can ask
                            // for: no flow arrives from it and no request names
                            // it, so an entry that lists it authorizes nothing
                            // and looks like it authorizes something.
                            if let Some(ports) = &client_toml.allow_ports
                                && ports.contains(&0)
                            {
                                anyhow::bail!(
                                    "[auth.clients.{id}]: allow_ports contains port 0; no client \
                                     ever asks for it, so that entry can never match"
                                );
                            }
                            // A name in this table is a credential's whole
                            // identity: it is what the device sends, what the
                            // log line for every outcome carries, and what an
                            // operator names when revoking one. An empty one
                            // is not a name — the unnamed device is what the
                            // client's own `secret` is for.
                            //
                            // The two fields that follow are one credential
                            // spelled two ways — a TOTP seed the device shares
                            // with the server, or the public half of a key pair
                            // it keeps the other half of — and a device answers
                            // with exactly one of them. Both, or neither, is a
                            // config that does not say how the device proves
                            // itself, refused here where the operator can see
                            // which entry it is.
                            let mut devices = HashMap::new();
                            for (device_id, device_toml) in client_toml.devices.unwrap_or_default()
                            {
                                if device_id.is_empty() {
                                    anyhow::bail!(
                                        "[auth.clients.{id}.devices]: a device needs a name; a \
                                         client's own `secret` is the credential of the device \
                                         that has none"
                                    );
                                }
                                if !crate::auth::is_presentable_device_id(&device_id) {
                                    anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: a device name is \
                                         printable ASCII of at most {} characters — it is written \
                                         into the log line for everything that happens to it",
                                        crate::auth::MAX_DEVICE_ID_LEN
                                    );
                                }
                                // `secret = ""` is read as no secret at all:
                                // an empty one is not a credential, and an
                                // entry left holding only that is refused
                                // below like one that has nothing.
                                let secret =
                                    device_toml.secret.filter(|s| !s.expose_secret().is_empty());
                                match (&secret, &device_toml.public_key) {
                                    (None, None) => anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: no `secret` and \
                                         no `public_key`; a device answers with one of the two, \
                                         and an empty secret is not one"
                                    ),
                                    (Some(_), Some(_)) => anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: both a `secret` \
                                         and a `public_key`; a device answers with one \
                                         credential, and two are two answers to disagree about"
                                    ),
                                    (None, Some(public_key)) => {
                                        // Checked where the key would otherwise
                                        // first be used: at a handshake, where
                                        // a bad key and a wrong one are the
                                        // same refusal.
                                        if let Err(why) = crate::auth::parse_public_key(public_key)
                                        {
                                            anyhow::bail!(
                                                "[auth.clients.{id}.devices.{device_id}]: {why}"
                                            );
                                        }
                                    }
                                    (Some(_), None) => {}
                                }
                                devices.insert(
                                    device_id,
                                    crate::auth::DeviceAuth {
                                        secret: secret.unwrap_or_default(),
                                        public_key: device_toml.public_key,
                                        created_at: device_toml.created_at.unwrap_or_else(
                                            crate::auth::config::default_created_at,
                                        ),
                                        last_used: device_toml.last_used,
                                        last_used_step: None,
                                    },
                                );
                            }
                            clients.insert(
                                id,
                                crate::auth::ClientAuth {
                                    secret: client_toml.secret,
                                    created_at: client_toml
                                        .created_at
                                        .unwrap_or_else(crate::auth::config::default_created_at),
                                    allow_hosts: client_toml.allow_hosts,
                                    allow_ports: client_toml.allow_ports,
                                    allow_ports_strict: client_toml
                                        .allow_ports_strict
                                        .unwrap_or(false),
                                    pending_enrollment: client_toml.pending_enrollment,
                                    devices,
                                    unnamed_device_allowed: client_toml
                                        .unnamed_device_allowed
                                        .unwrap_or(true),
                                    last_used: client_toml.last_used,
                                    last_used_step: None,
                                    // The step memory is not in the config
                                    // file: it is a counter, and the counters
                                    // live in the state file beside it.
                                    failed_attempts: client_toml.failed_attempts.unwrap_or(0),
                                    locked_until: client_toml.locked_until,
                                    enrollment_failed_attempts: 0,
                                    enrollment_locked_until: None,
                                },
                            );
                        }
                    }

                    // Refused rather than guessed. Both ends of the handshake
                    // read the same config, so a name nobody supports does not
                    // fail on one side and the other: the deployment just runs
                    // weaker than the operator wrote, and nothing says so.
                    let algorithm = match auth_toml.algorithm.as_deref().map(str::trim) {
                        None | Some("") | Some("sha1") | Some("SHA1") => {
                            crate::auth::TotpAlgorithm::SHA1
                        }
                        Some("sha256") | Some("SHA256") => crate::auth::TotpAlgorithm::SHA256,
                        Some("sha512") | Some("SHA512") => crate::auth::TotpAlgorithm::SHA512,
                        Some(other) => anyhow::bail!(
                            "algorithm {other:?} is not a TOTP algorithm; expected \"sha1\" \
                             (the default), \"sha256\" or \"sha512\""
                        ),
                    };

                    let time_step = auth_toml.time_step.unwrap_or(30);
                    let digits = auth_toml.digits.unwrap_or(6);
                    let window = auth_toml.window.unwrap_or(1);
                    validate_totp_parameters(time_step, digits, window)?;

                    let auth = crate::auth::AuthConfig {
                        enabled: auth_toml.enabled.unwrap_or(false),
                        issuer: auth_toml
                            .issuer
                            .unwrap_or_else(|| crate::auth::DEFAULT_ISSUER.to_string()),
                        algorithm,
                        time_step,
                        digits,
                        window,
                        clients,
                        max_attempts: auth_toml.max_attempts.unwrap_or(5),
                        lockout_duration: auth_toml.lockout_duration.unwrap_or(300),
                    };
                    // A seed that cannot work is a configuration error, and
                    // this is where it is found: the seed is decoded lazily
                    // otherwise, so it would surface as a failed login at the
                    // operator's first attempt.
                    crate::auth::config::validate_seeds(&auth)?;
                    Some(auth)
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        // The counters the server counted live in their own file now, beside
        // this one. They are moved onto the configuration the caller gets, so
        // everything downstream — the connection layer, the admin view, the
        // client list — reads one answer and does not have to know which file
        // it came from.
        //
        // A state file that cannot be read stops the load: the lockouts it
        // holds are unknown, and a server that started anyway would have just
        // reset every one of them.
        if let Some(auth) = auth_config.as_mut() {
            let state_path = crate::auth::state::path_for(path);
            let state = crate::auth::state::load(&state_path)?;
            crate::auth::state::apply(&state, auth);
        }

        Ok((base, auth_config))
    }

    /// Writes `secret` under `[auth.clients.<client_id>]` of the config file at
    /// `path`, creating `[auth]` and `[auth.clients]` when they are missing.
    ///
    /// The document is edited as TOML instead of being re-serialized from a
    /// `ProxyConfig`, so comments, key order and the layout of every other
    /// section survive — which is the whole point, this edits the file a human
    /// wrote. `force` is what allows an existing secret to be replaced: a device
    /// that already imported the old one stops authenticating the instant it
    /// changes, so callers keep the existing secret unless told otherwise.
    ///
    /// `[auth] enabled` is deliberately left alone: flipping it on would turn
    /// 2FA on for every client, not just the one being enrolled.
    pub fn write_client_secret(
        path: &str,
        client_id: &str,
        secret: &str,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        with_config_lock(path, || {
            Self::write_client_secret_unlocked(path, client_id, secret, force)
        })
    }

    fn write_client_secret_unlocked(
        path: &str,
        client_id: &str,
        secret: &str,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        let mut doc = read_config_document(path, "secret not written")?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;

        let replaced = client.contains_key("secret");
        if replaced && !force {
            anyhow::bail!("client \"{client_id}\" already has a secret in {path}");
        }
        client.insert("secret", toml_edit::value(secret));

        write_config_document(path, doc)?;

        Ok(if replaced {
            ClientSecretWrite::Replaced
        } else {
            ClientSecretWrite::Added
        })
    }

    /// Records a one-time enrollment token for `client_id`.
    ///
    /// Any token already outstanding is replaced, which is how an invitation
    /// that never arrived gets revoked: generate another one and the old link
    /// stops working. The client's secret is left alone — enrollment does not
    /// touch it until a token is actually spent.
    ///
    /// The client has to exist: a `[auth.clients.<id>]` section with a token and
    /// no secret would fail to load.
    pub fn write_pending_enrollment(
        path: &str,
        client_id: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::write_pending_enrollment_unlocked(path, client_id, token)
        })
    }

    fn write_pending_enrollment_unlocked(
        path: &str,
        client_id: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        let mut doc = read_config_document(path, "token not written")?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;
        if !client.contains_key("secret") {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] secret in {path}; \
                 run --generate-2fa {client_id} first"
            );
        }

        client.insert("pending_enrollment", toml_edit::value(token));

        write_config_document(path, doc)
    }

    /// Spends the token: writes the issued `secret` and drops
    /// `pending_enrollment`, so the same link cannot enroll twice.
    ///
    /// Both keys are written in one pass on purpose. A secret on disk with the
    /// token still beside it would leave the window open for a second device to
    /// trade the same link for the same credential.
    pub fn complete_enrollment(path: &str, client_id: &str, secret: &str) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::complete_enrollment_unlocked(path, client_id, secret)
        })
    }

    fn complete_enrollment_unlocked(
        path: &str,
        client_id: &str,
        secret: &str,
    ) -> anyhow::Result<()> {
        let mut doc = read_config_document(path, "enrollment not saved")?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;

        client.insert("secret", toml_edit::value(secret));
        client.remove("pending_enrollment");

        write_config_document(path, doc)
    }

    /// Spends the token for one named device: writes that device's own
    /// credential into `[auth.clients.<id>.devices.<name>]` and drops
    /// `pending_enrollment`, leaving the client's `secret` as it was.
    ///
    /// The material is whichever the enrollment turned on: a secret the server
    /// generated, or the public key the device offered in ENROLL_START.
    ///
    /// The client's secret is deliberately untouched. It is the credential of
    /// the device that has no name — every device that enrolled before this
    /// table existed — so rotating it is what re-enrolls all of them at once,
    /// and an enrollment that names a device is the one case where that is
    /// known not to be what was asked for. [`Self::complete_enrollment`] is
    /// still the answer for an enrollment that names none, and still rotates it.
    ///
    /// Both keys move in one pass, for the reason given there: a secret on disk
    /// with the token still beside it would leave the window open for a second
    /// device to trade the same link for the same credential.
    ///
    /// The entry lands where [`Self::write_device_credential`] puts one: both
    /// writers go through `device_table` and `device_entry`, so a device
    /// that spent a token and one an operator wrote by hand are the same shape
    /// on disk.
    pub fn complete_device_enrollment(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
    ) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::complete_device_enrollment_unlocked(path, client_id, device, material)
        })
    }

    fn complete_device_enrollment_unlocked(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
    ) -> anyhow::Result<()> {
        let mut doc = read_config_document(path, "enrollment not saved")?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;

        let devices = device_table(client, client_id, path)?;
        devices.insert(device, device_entry(material, path)?);

        client.remove("pending_enrollment");

        write_config_document(path, doc)
    }

    /// Writes one device's credential — a TOTP secret or a public key — under
    /// `[auth.clients.<client_id>.devices.<device>]`, which is what gives one
    /// device of a client a credential of its own.
    ///
    /// The client's own `secret` is deliberately left alone: it is the
    /// credential of the device that names none, so rotating it re-enrolls
    /// every unnamed device at once, and issuing one device a credential of its
    /// own is exactly the case where that is known not to be what was asked
    /// for.
    ///
    /// `force` is what allows an existing device to be issued another one, for
    /// the reason [`Self::write_client_secret`] needs it: a device already
    /// using the old credential stops authenticating the moment it changes.
    /// Replacing one kind with the other has to go through `force` the same
    /// way — a device that answered with a code and now answers with a
    /// signature is as enrolled-out as one whose secret changed.
    ///
    /// What it writes is the entry [`Self::complete_device_enrollment`] writes
    /// when a device spends a token — one shape on disk, reached the same way.
    /// The two differ only in what has to be true first: an enrollment has a
    /// token to spend, and this has an operator, who has to say `--force`
    /// before an existing credential is replaced.
    ///
    /// The client has to be there first — a device table under a client with no
    /// secret of its own is a config that will not load.
    pub fn write_device_credential(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        with_config_lock(path, || {
            Self::write_device_credential_unlocked(path, client_id, device, material, force)
        })
    }

    fn write_device_credential_unlocked(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        // The name becomes a key in this file and the subject of every log line
        // about the device, so it is checked here rather than on its way into
        // either. An empty one is not a name: the unnamed device is what the
        // client's own `secret` is for.
        if !crate::auth::is_presentable_device_id(device) {
            anyhow::bail!(
                "device name {device:?} is printable ASCII of at most {} characters — it is a key \
                 in {path} and the subject of every log line about it",
                crate::auth::MAX_DEVICE_ID_LEN
            );
        }

        let mut doc = read_config_document(path, "secret not written")?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;
        if !client.contains_key("secret") {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] secret in {path}; \
                 run --generate-2fa {client_id} first"
            );
        }

        let devices = device_table(client, client_id, path)?;
        let replaced = devices.contains_key(device);
        if replaced && !force {
            anyhow::bail!(
                "device \"{device}\" of client \"{client_id}\" already has a credential in {path}"
            );
        }

        devices.insert(device, device_entry(material, path)?);

        write_config_document(path, doc)?;

        Ok(if replaced {
            ClientSecretWrite::Replaced
        } else {
            ClientSecretWrite::Added
        })
    }
    /// Drops one device's credential: `[auth.clients.<client_id>.devices.<device>]`.
    ///
    /// Revoking is a delete and not a rotation, because a deleted entry is the
    /// one thing the handshake reads as "this device has no credential" — the
    /// same answer a device that never enrolled gets, so what happened cannot be
    /// told apart from outside. The client's own `secret` is left alone: it
    /// belongs to the device that names none, and a client with one is not
    /// revoked by dropping a device that named itself.
    pub fn remove_device(path: &str, client_id: &str, device: &str) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::remove_device_unlocked(path, client_id, device)
        })
    }

    fn remove_device_unlocked(path: &str, client_id: &str, device: &str) -> anyhow::Result<()> {
        let mut doc = read_config_document(path, "nothing revoked")?;

        // Not `sub_table`: revoking must never create the thing it is about to
        // delete, and an absent section is the operator naming something that
        // is not there, which is worth saying.
        let clients = auth_clients(doc.as_table_mut());
        let Some(clients) = clients else {
            anyhow::bail!("{path} has no [auth.clients] table, nothing revoked");
        };
        let Some(client) = clients
            .get_mut(client_id)
            .and_then(|item| item.as_table_like_mut())
        else {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] section in {path}, \
                 nothing revoked"
            );
        };
        let Some(devices) = client
            .get_mut("devices")
            .and_then(|item| item.as_table_like_mut())
        else {
            anyhow::bail!("client \"{client_id}\" has no devices in {path}, nothing revoked");
        };
        if devices.remove(device).is_none() {
            anyhow::bail!(
                "client \"{client_id}\" has no device \"{device}\" in {path}; its devices are {}",
                device_names(devices)
            );
        }

        write_config_document(path, doc)
    }

    /// Drops a client and every device under it: all of
    /// `[auth.clients.<client_id>]`.
    pub fn remove_client(path: &str, client_id: &str) -> anyhow::Result<()> {
        with_config_lock(path, || Self::remove_client_unlocked(path, client_id))
    }

    fn remove_client_unlocked(path: &str, client_id: &str) -> anyhow::Result<()> {
        let mut doc = read_config_document(path, "nothing revoked")?;

        let clients = auth_clients(doc.as_table_mut());
        let Some(clients) = clients else {
            anyhow::bail!("{path} has no [auth.clients] table, nothing revoked");
        };
        if clients.remove(client_id).is_none() {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] section in {path}, \
                 nothing revoked"
            );
        }

        write_config_document(path, doc)
    }
}

/// The `[auth.clients]` table of `doc`, when the document has one.
///
/// Shared by the two revoking writers, which must find the table without ever
/// creating it: a revoke that invented an empty `[auth.clients]` to delete from
/// would leave the file changed while reporting that nothing was revoked.
pub(crate) fn auth_clients(doc: &mut toml_edit::Table) -> Option<&mut dyn toml_edit::TableLike> {
    doc.get_mut("auth")
        .and_then(|item| item.as_table_like_mut())
        .and_then(|auth| auth.get_mut("clients"))
        .and_then(|item| item.as_table_like_mut())
}

/// The names of the devices in `devices`, for the message a revoke leaves
/// behind when it is asked for one that is not there.
pub(crate) fn device_names(devices: &dyn toml_edit::TableLike) -> String {
    let mut names: Vec<&str> = devices.iter().map(|(name, _)| name).collect();
    names.sort_unstable();
    if names.is_empty() {
        return "none".to_string();
    }
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `[auth.clients.<client_id>.devices]` as a table, created when it is missing.
///
/// Where a device's credential goes, for both of the writers that put one
/// there: the enrollment that spends a token, and the operator CLI behind
/// [`ProxyConfig::write_device_credential`]. One table either way, so a device
/// that enrolled and one that was handed a credential by hand are the same
/// shape on disk, and the handshake does not have to know which of the two it
/// is.
///
/// Not `sub_table`, which makes an implicit table: a device added under one
/// would be written as `devices.laptop = { … }` on a line of the client's own
/// section, and a table that says what it holds reads better than a dotted key
/// that does not.
pub(crate) fn device_table<'a>(
    client: &'a mut dyn toml_edit::TableLike,
    client_id: &str,
    path: &str,
) -> anyhow::Result<&'a mut dyn toml_edit::TableLike> {
    let item = match client.entry("devices") {
        toml_edit::Entry::Occupied(entry) => entry.into_mut(),
        toml_edit::Entry::Vacant(entry) => {
            entry.insert(toml_edit::Item::Table(toml_edit::Table::new()))
        }
    };
    item.as_table_like_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "{path}: [auth.clients.{client_id}.devices] is not a table, the device secret was \
             not written"
        )
    })
}

/// What [`ProxyConfig::write_client_secret`] did to the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSecretWrite {
    /// A `[auth.clients.<id>]` section was added, creating `[auth]` if needed.
    Added,
    /// The client already had a secret, and it was replaced.
    Replaced,
}

/// `parent[key]` as a table, creating it when it is missing.
///
/// A table created here is implicit: it is left out of the output while it holds
/// nothing of its own, so a config with no `[auth]` at all gains the one leaf
/// section instead of two empty headers above it.
pub(crate) fn sub_table<'a>(
    parent: &'a mut dyn toml_edit::TableLike,
    key: &str,
    path: &str,
) -> anyhow::Result<&'a mut dyn toml_edit::TableLike> {
    let item = match parent.entry(key) {
        toml_edit::Entry::Occupied(entry) => entry.into_mut(),
        toml_edit::Entry::Vacant(entry) => {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            entry.insert(toml_edit::Item::Table(table))
        }
    };
    item.as_table_like_mut()
        .ok_or_else(|| anyhow::anyhow!("{path}: [{key}] is not a table, secret not written"))
}
