export type ConnectionType = 'ticket' | 'endpoint_id';

export type RelayMode = 'pinned' | 'default' | 'disabled' | 'custom';

export type LoadBalancingStrategy = 'round_robin' | 'random';

export type TwoFactorAlgorithm = 'sha1' | 'sha256' | 'sha512';

/**
 * How the proxy is forwarding traffic. Mirrors `ProxyModeKind` in `src-tauri/src/status.rs`,
 * serialized in snake_case; `starting` and `stopped` describe the absence of a live mode, and
 * `unknown` is the absence of an answer — the state could not be read, so it is not known.
 */
export type ProxyMode = 'tun' | 'local_proxy' | 'starting' | 'stopped' | 'unknown';

/**
 * What the service manager reports about the system service. Mirrors `ServiceState` in
 * `src-tauri/src/service/platform.rs`, serialized in snake_case. This is *not* the same question
 * as `is_service_running`, which asks whether the daemon answers on the IPC port: an installed but
 * unstarted service is `stopped`, not absent.
 */
export type ServiceState = 'not_installed' | 'stopped' | 'running';

/**
 * The 2FA credentials one endpoint is reached with.
 *
 * Kept per node rather than once per client because every server has its own `[auth].clients`
 * entry: a single shared pair is what forced a second server to be given the first one's secret.
 * A node without credentials performs no handshake, which is also how one client mixes servers
 * that demand 2FA with ones that do not.
 */
export interface NodeTwoFactor {
  clientId: string;
  secret: string;
  algorithm: TwoFactorAlgorithm;
  /**
   * Which device of this client this secret belongs to.
   *
   * Absent is the device that was never given a name — the one that answers with the client's own
   * secret, and the only kind there was before a client could have several. Present is a name the
   * server filed this secret under, so sending it is what makes the handshake check the right
   * one: without it a server holding several devices cannot tell which of them is speaking, and
   * revoking one of them rotates all of them.
   */
  device?: string;
}

/**
 * A one-time enrollment token, which is what a `--registration` invite carries instead of a
 * secret.
 *
 * It is spent by the first connection that uses it — the server answers with the real
 * credential and rotates the client's secret in the same step — so a node holding a token is
 * a node that has not been issued credentials yet. Whatever comes back has to be written into
 * `twoFactor`: the token cannot be spent twice, so a restart that still only holds the invite
 * has nothing left to authenticate with.
 */
export interface EnrollmentToken {
  clientId: string;
  token: string;
  /**
   * The name this device asks to be enrolled under. Absent asks for the client's own secret,
   * which is the only thing a server that predates per-device credentials will answer.
   */
  device?: string;
}

/** What the server issued for a spent token: the credentials to keep from here on. */
export interface IssuedCredential {
  clientId: string;
  secret: string;
  algorithm: TwoFactorAlgorithm;
  /**
   * The device the secret was filed under, which is the name to send from here on. Absent when
   * the server answered an enrollment that named no device.
   */
  device?: string | null;
  /**
   * The public half of the device key this credential was issued as, as 64 hex characters.
   *
   * Absent for a credential that is a secret, and that is how the two kinds are told apart: a key
   * credential has an empty secret and an empty algorithm, and this is the only thing that says
   * which key it is.
   */
  publicKey?: string | null;
}

export interface NodeConfig {
  id: string;
  connectionType: ConnectionType;
  ticket: string;
  endpointId: string;
  domains: string[];
  /**
   * Cosmetic label, set only when the node came from an invite that named itself. Nothing routes
   * on it and it is never sent to the backend: the UI falls back to "Node N" when it is absent.
   */
  name?: string;
  /** Credentials for this endpoint alone. Absent means no handshake for this server. */
  twoFactor?: NodeTwoFactor;
  /**
   * A token to spend instead of presenting credentials. Cleared once the issued secret has
   * landed in `twoFactor`, so a node is never left holding both.
   */
  enrollment?: EnrollmentToken;
  /**
   * This machine's own Ed25519 key for this endpoint, as 64 hex characters.
   *
   * A property of the *device* rather than of the credential: the same key is offered by the
   * enrollment that spends the token and signs every handshake after it, so it exists before
   * there is a credential to sign with.
   *
   * In memory only, like the secret beside it: the shape that is persisted strips it, and the
   * encrypted store holds the only other copy.
   */
  deviceKey?: string;
  /**
   * The public half of that key, as 64 hex characters.
   *
   * Not a secret — the server holds the same one — so it is part of the persisted shape, and it
   * is what the app shows to name the key an operator has on file.
   */
  publicKey?: string;
}

/**
 * What the machine's DNS is asked to do.
 *
 * - `scoped` — only the configured domains resolve through the tunnel; the machine's own
 *   names, and another tunnel's, keep resolving where they always did. The default.
 * - `global` — every query on the machine goes to the tunnel's resolver.
 * - `none` — the machine's DNS is not touched at all. The tunnel's own resolver still runs,
 *   so a PAC file or a hosts entry can point at it.
 *
 * The strategy is never changed behind the user's back: a machine that cannot be scoped
 * refuses the tunnel and says so, rather than having its whole DNS replaced.
 */
export type DnsStrategy = 'scoped' | 'global' | 'none';

export interface ProxyConfig {
  nodes: NodeConfig[];
  domains: string[];
  localAddr: string;
  dnsAddr: string;
  upstreamDns: string;
  /**
   * What the machine's DNS is asked to do. See {@link DnsStrategy}.
   *
   * Absent in a payload written before the setting existed, and the default fills it in:
   * `scoped`, the strategy that leaves the machine's own names alone.
   */
  dnsStrategy: DnsStrategy;
  loadBalancing: LoadBalancingStrategy;
  tunName: string;
  /**
   * Forwarding mode: `true` requests TUN, `false` the local proxy. TUN is gated on the service
   * being installed (see docs/ui-refactor-plan.md §5.12) and is never chosen implicitly.
   */
  useTun: boolean;
  /** Execution backend: in-process, or through the installed system service. */
  useService: boolean;
  relayMode: RelayMode;
  relayUrl: string;
  /** Bearer token for a custom relay that requires one. */
  relayAuthToken: string;
  /**
   * The name this machine answers as, once per installation rather than once per server: the
   * device is the machine, and every node belongs to it.
   *
   * Generated on first run and kept, because a name that changed would leave the server holding
   * an entry for a device that no longer exists — a credential nobody can revoke by name. Empty
   * until it has been generated; see `ensureDeviceId`.
   */
  deviceId: string;
}

/** The persisted shape: user config plus the schema version the migration chain walks. */
export interface PersistedConfig extends ProxyConfig {
  version: number;
}

export interface ProxyStatus {
  running: boolean;
  mode: ProxyMode;
}

/**
 * How a node currently reaches its backend, as reported by iroh at runtime: `unknown` means
 * connected but no path selected yet.
 *
 * Deliberately *not* derived from the relay mode in the config, and not from the node being a
 * ticket either — those say what is allowed, this says what actually happened.
 */
export type LinkKind = 'direct' | 'relay' | 'unknown';

/** Mirrors `EndpointLink` in `src-tauri/src/status.rs`. */
export interface EndpointLink {
  /**
   * The ticket or endpoint ID exactly as the node was configured, so the UI can match a link to
   * the node it belongs to. A ticket is opaque here, so the resolved ID alone would not do.
   */
  connection: string;
  /** The backend's endpoint ID; a ticket resolves to the node it names. */
  endpointId: string;
  link: LinkKind;
  /**
   * The round-trip time of the path carrying the traffic, in milliseconds. `null` while iroh has
   * no sample — which is not a round trip of zero.
   */
  rttMs: number | null;
}

/** How one configured node answered its last probe. Mirrors `NodeHealthStatus` in `src-tauri/src/status.rs`. */
export interface NodeHealth {
  /**
   * The ticket or endpoint ID exactly as the node was configured — the same key `EndpointLink`
   * carries, so a link and a health reading for one node can be paired.
   */
  connection: string;
  /** Whether it answered. False before the first probe has run: unasked means unanswered. */
  reachable: boolean;
  /** Probes in a row that have failed. Zero while it answers. */
  consecutiveFailures: number;
  /**
   * How long it has been down, in seconds. `null` while it answers, and `null` when it has
   * never answered — which is not "down for no time at all".
   */
  downForSecs: number | null;
  /** How long ago it was last probed, in seconds. `null` before the first probe. */
  sinceLastProbeSecs: number | null;
}

/**
 * What one node has carried, as a pair of cumulative byte counters and a flow count. Mirrors
 * `NodeTrafficStatus` in `src-tauri/src/status.rs`.
 *
 * Every byte figure is cumulative since the counters started, which in practice means since the
 * proxy did: nothing crossing here divides by anything, because a rate is two readings and a
 * division and this is polled.
 *
 * A node the backend has nothing to say about has *no entry at all* rather than one full of
 * zeroes — see `NodeTrafficStatus`, and `trafficFor` in the proxy store, which answers `null` for
 * it.
 */
export interface NodeTraffic {
  /**
   * The ticket or endpoint ID exactly as the node was configured — the same key `EndpointLink`
   * and `NodeHealth` carry, so a volume, a link and a health reading for one node can be paired.
   */
  connection: string;
  /** Bytes this machine has put into the tunnel towards this node. Cumulative. */
  sent: number;
  /** Bytes that have come back from it. Cumulative. */
  received: number;
  /** Flows open through it right now. The only figure here that goes down. */
  active: number;
}

/**
 * Every node's counters added together.
 *
 * Nothing on the backend reports this — it is the sum of what `NodeTraffic` already carries, so
 * the total on screen cannot disagree with the per-node figures beside it.
 *
 * `null` while there is nothing to add up, which is not the same as a total of zero: no counters
 * have been read yet, and printing `0 B` would read as a tunnel that connects and moves nothing.
 */
export interface TrafficTotals {
  sent: number;
  received: number;
  active: number;
}

/**
 * Bytes per second in each direction, as two totals and a division.
 *
 * Deliberately computed here and not on the backend: the counters there are cumulative and
 * deliberately hold no rate (see `crates/nexapipe-client/src/traffic.rs`), and every consumer
 * already polls, so a second clock in Rust would have nothing to say that two samples do not.
 *
 * `up` is towards the backends, `down` is what comes back — the same direction [`NodeTraffic`]
 * counts them in, so a total and a rate can be read side by side.
 */
export interface TrafficRate {
  up: number;
  down: number;
}

/**
 * One connection the proxy has open right now. Mirrors `ActiveFlow` in `src-tauri/src/status.rs`.
 *
 * `kind` arrives as a string rather than a union because the list of doors a connection can come
 * in by belongs to the client library, and a second vocabulary for it in the shell would be a
 * second place to change when one is added. The names are the same ones `flow::FlowKind` prints.
 *
 * `connection` is `null` when a flow reaches a backend this configuration does not name, which
 * is not the same as a flow with no node: it has one, this app just does not configure it.
 */
export interface ActiveFlow {
  /** Stable while the flow is open, and never reused after it ends. */
  id: number;
  /** The ticket or endpoint ID exactly as the node was configured. */
  connection: string | null;
  /** The backend's endpoint ID. */
  endpointId: string;
  /** `http` | `connect` | `websocket` | `tls` | `tun_tcp` | `tun_udp`. */
  kind: string;
  /** Where the bytes are going, as the client named it. `null` when it never said. */
  target: string | null;
  /** Where they came from. `null` when the socket did not say. */
  source: string | null;
  /** Whole seconds since the flow opened. */
  openForSecs: number;
  /** Bytes this machine has put into the tunnel through this flow. Cumulative. */
  sent: number;
  /** Bytes that have come back through it. Cumulative. */
  received: number;
}

/**
 * One page of open connections. Mirrors `ActiveFlowPage` in `src-tauri/src/status.rs`.
 *
 * `total` is how many are open and `flows` is how many of them are here: the backend caps the
 * list, and a page that printed `flows.length` as the number of connections would be quietly
 * under-reporting a busy tunnel.
 */
export interface ActiveFlowPage {
  flows: ActiveFlow[];
  total: number;
  limit: number;
}

/**
 * The 2FA half of an invite *as it is shown*. Mirrors `InviteTotpPayload` in
 * `src-tauri/src/lib.rs`, which deliberately carries no secret: an invite is shown to be
 * recognised, and the secret stays a credential after the connection it authorises is set up.
 * `algorithm` is already lowercase, which is what a node's `twoFactor.algorithm` holds.
 */
export interface InviteTotp {
  clientId: string;
  algorithm: TwoFactorAlgorithm;
  issuer: string;
}

/**
 * The enrollment half of an invite *as it is shown*: which client the token is pending for, and
 * nothing else. The token itself never reaches the renderer — `acceptInvite` files it.
 */
export interface InviteEnrollment {
  clientId: string;
}

/**
 * A parsed `nexapipe://` invite. Mirrors `InvitePayload` in `src-tauri/src/lib.rs`, which gets it
 * from the one parser in `crates/nexapipe-client/src/provisioning.rs` — the UI never parses an
 * invite itself, so a code printed by the server reads the same here as it does on Android.
 *
 * Everything a surface could print, and nothing a surface should not: the connection string is
 * the mask Rust produced, and neither a TOTP secret nor an enrollment token is in here at all.
 */
export interface InvitePayload {
  /** `endpoint` for a bare Node ID, `ticket` for an address-bearing ticket. */
  kind: 'endpoint' | 'ticket';
  /** The Node ID, or the ticket, as `credentials::mask` renders it. */
  targetMasked: string;
  name?: string;
  domains: string[];
  relay?: string;
  totp?: InviteTotp;
  /**
   * A one-time enrollment token (`--registration` invites). Mutually exclusive with `totp`:
   * the parser refuses a code carrying both, so the UI never has to pick a winner.
   */
  enrollment?: InviteEnrollment;
}

/**
 * What `acceptInvite` answers: which node the invite belongs to, and everything about it that is
 * not a credential. Mirrors `InviteAccepted` in `src-tauri/src/lib.rs`.
 *
 * `nodeId` is an existing node's when one already held this connection string, so importing the
 * same invite twice tops a node up instead of adding a second one pointing at the same backend —
 * a comparison the renderer cannot make any more, because it no longer holds the string.
 */
export interface InviteAccepted {
  nodeId: string;
  /** `ticket` or `endpoint_id`, which is what `connectionType` calls them. */
  connectionType: ConnectionType;
  existing: boolean;
  name?: string;
  domains: string[];
  relay?: string;
  totp?: InviteTotp;
  enrollment?: InviteEnrollment;
  /**
   * The public half of the device key this node will enroll with, as 64 hex characters.
   *
   * Absent for an invite that hands out a secret rather than a token. The private
   * half never crosses this boundary: it is filed in the encrypted store and read
   * from there when a connection needs it.
   */
  publicKey?: string;
}

/**
 * The credential door, as a surface sees it. Mirrors `gate::Status` in `src-tauri/src/gate.rs`.
 *
 * `msRemaining` is what lets the UI run its own countdown: the window is a duration rather than a
 * flag, so the page that drew it has to be the one that watches it run out.
 */
export interface GateStatus {
  /** Whether credentials may be shown right now. */
  unlocked: boolean;
  /** Milliseconds left in the window; zero when it is shut. */
  msRemaining: number;
  /** Whether this machine can confirm the user at all. */
  canAuthenticate: boolean;
  /** Whether the UI has to collect a password before it can ask. */
  needsPassword: boolean;
}

/**
 * A failure crossing the Rust/frontend boundary, as produced by `AppError` in
 * `src-tauri/src/error.rs`. `code` is stable and is looked up as `error.<code>` in the locale
 * files; `detail` is a raw English diagnostic meant for the log, never the headline message.
 */
export interface AppError {
  code: string;
  detail?: string;
}
