/**
 * Runtime proxy state and actions (docs/ui-refactor-plan.md §5.7, §5.12).
 *
 * This store owns the `invoke()` orchestration that used to live inside `ProxyStatusControl.vue`
 * (D12) — the component rendered state it did not own, and could only tell the store about a
 * status change after the fact.
 *
 * The two orthogonal concerns are kept apart and named explicitly:
 *   - **execution backend** (`config.useService`): in-process, or the installed system service
 *   - **forwarding mode** (`config.useTun`): TUN, or the local proxy
 *
 * TUN is gated on the service being installed (§5.12): without it the app runs the local proxy,
 * and asking for TUN anyway fails with `proxy.tun_unavailable` rather than quietly forwarding
 * traffic a different way.
 */
import { computed, ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import type {
  AppError,
  EndpointLink,
  LinkKind,
  NodeConfig,
  NodeHealth,
  NodeTraffic,
  ProxyMode,
  ProxyStatus,
  TrafficRate,
  TrafficTotals,
} from '../types';
import { relayTokenToSend, useConfigStore } from './config';
import { usePrefsStore } from './prefs';
import { isBackgroundLaunch } from '../api/autostart';
import { setTrayStatus } from '../api/tray';
import { takeIssuedCredential } from '../api/invite';
import { translate } from '../i18n';
import { useToast } from '../composables/useToast';

/** How long a start may take before the UI calls it a failure. */
const START_TIMEOUT_MS = 25_000;
const POLL_INTERVAL_MS = 250;

/**
 * How often the status is re-read while nothing is being asked of the backend.
 *
 * Faster while starting (the first route install usually takes a second or two) and while
 * running, because that is when the answer can change without the user doing anything: the
 * service can die, and iroh can promote a relayed path to a direct one at any moment.
 */
const POLL_RUNNING_MS = 3_000;
const POLL_STARTING_MS = 1_000;
const POLL_STOPPED_MS = 5_000;
/** After this many consecutive failures the poll slows down instead of hammering a dead backend. */
const POLL_BACKOFF_MS = 10_000;
const FAILURES_BEFORE_BACKOFF = 3;

/**
 * How often the service gate is re-read on its own.
 *
 * `serviceRunning` decides whether TUN is offered at all, and installing from Settings changed it
 * without ever telling this store — the Connect page kept its "install service" button and a
 * disabled toggle until the app was restarted. It is slower than the status poll because asking
 * costs a process (`sc.exe query` / `systemctl is-active`) rather than a local IPC read, and
 * installation is a rare, deliberate act.
 */
const SERVICE_POLL_MS = 10_000;

/**
 * How many consecutive service reads have to come back unanswered before the answer is believed.
 *
 * The IPC read has deadlines of its own — half a second to connect and five to be answered — and
 * a busy machine misses them while the service is alive and well. One missed deadline is not a
 * fact about the service: believing it turns TUN off, loses the setting across the next launch,
 * and invites a reinstall of a service that was never broken. Several misses in a row are.
 */
const SERVICE_FAILURES_BEFORE_TRUST = 3;

const status = ref<ProxyStatus>({ running: false, mode: 'stopped' });
/**
 * The local Node ID, masked — `get_node_id_display` is what the poll reads.
 *
 * A mask is what every surface in the app needs: the string is printed, and it is the name this
 * machine answers to on the network. The whole of it is only ever fetched on purpose, by
 * `revealNodeId`, when the user asked to copy it somewhere.
 */
const nodeId = ref('');
const busy = ref(false);
const startupError = ref<AppError | null>(null);
const serviceRunning = ref(false);

/**
 * Whether the service has stopped answering, as far as the reads have shown.
 *
 * False while the answer is still unknown: the first read that misses its deadline says the
 * service did not answer *then*, not that it is gone. Only several misses in a row are believed,
 * and every read that answered clears the count.
 */
const serviceUnanswered = ref(false);

/**
 * Which build the service says it is.
 *
 * `null` when the service did not answer that question and something explains the silence: the
 * IPC was up and the service refused it, or the service has stopped answering altogether. That
 * is the drift a reinstall fixes. `undefined` while nothing is known yet — a read that timed out
 * says the service did not answer *this time*, and nothing about the build, so nothing is
 * claimed about it.
 */
const serviceVersion = ref<string | null | undefined>(undefined);

/**
 * Consecutive service reads that came back unanswered. Cleared by every read that answered.
 *
 * Not reactive state: it is a count, not an answer, and nothing on screen is drawn from it.
 */
let serviceReadFailures = 0;

/**
 * What the service manager says about the service: not registered, registered and down, or
 * registered and up.
 *
 * A third question from the IPC, which answers whether something is *answering* — and the
 * two only agree when the service is the build this app expects.
 */
const serviceState = ref<'not_installed' | 'stopped' | 'running'>('not_installed');

/**
 * The service is registered with the service manager.
 *
 * Installed and answering are different facts: the install button disappears as soon as the
 * unit exists, while TUN stays gated on the IPC connection actually being usable. A registered
 * service that is merely stopped still offers a control of its own — starting it — which is
 * neither installing it again nor reinstalling it.
 */
const serviceInstalled = computed(() => serviceState.value !== 'not_installed');

/**
 * The service is registered and running but did not answer this build.
 *
 * The combination an upgrade leaves behind: the job is still there, running the build it
 * was started with, while the app beside it is a newer one that cannot talk to it. Nothing
 * is wrong with the service as far as the service manager is concerned, so the drift stays
 * invisible unless the two answers are compared.
 *
 * Not the same as "the service is not running": that is a service that is down, and this is
 * one that is up and speaking a language the app does not speak. And not the same as a read
 * that timed out either: that says the service did not answer *this time*, and nothing about
 * the build, so it is no evidence of a drift and must not raise the banner that offers to
 * reinstall the service.
 */
const serviceStale = computed(
  () => serviceState.value === 'running' && serviceVersion.value === null,
);

/**
 * How each node is currently reaching its backend, filled in from the Rust side while the proxy
 * is up. Empty whenever nothing is running, which is what keeps a stale icon off the screen.
 */
const endpointLinks = ref<EndpointLink[]>([]);

/**
 * Whether each configured node answered its last probe, filled in from the Rust side while the
 * proxy is up. Empty whenever nothing is running, so a stopped proxy shows no health at all
 * rather than the reading it had when it stopped.
 */
const nodeHealth = ref<NodeHealth[]>([]);

/**
 * What each node has carried since the counters started, filled in from the Rust side while the
 * proxy is up. Empty whenever nothing is running: the counters reset with the proxy, so keeping
 * the last reading around would present this session's figures as though they were the previous
 * one's.
 *
 * A node that is *absent* from this list is not a node at zero — it is one nothing has been handed
 * a connection for, and it is drawn without figures rather than with a `0 B`. See `trafficFor`.
 */
const nodeTraffic = ref<NodeTraffic[]>([]);

/**
 * Every node's counters added together, and how fast they are moving.
 *
 * Both are answers to the question the per-node list raises and cannot answer: the list says
 * which backend carried what, and what a tunnel is *for* is the sum. Rates are the second half
 * of the same question — a total of 300 MiB says very different things about a tunnel that has
 * been up for a minute and one that has been up for a day.
 *
 * `totals` is `null` while there is nothing to add up, on the same terms as `nodeTraffic`: no
 * counters have been read, which is not the same as a total of zero.
 */
const totals = computed<TrafficTotals | null>(() => {
  const list = nodeTraffic.value;
  if (list.length === 0) return null;

  let sent = 0;
  let received = 0;
  let active = 0;
  for (const entry of list) {
    sent += entry.sent;
    received += entry.received;
    active += entry.active;
  }
  return { sent, received, active };
});
const rate = ref<TrafficRate | null>(null);

/**
 * The reading the rate is measured from: the previous totals and when they were taken.
 *
 * A rate is two readings and a division, so the first one has nothing to be divided against and
 * honestly reports no rate at all rather than zero — a tunnel that has just started is moving
 * bytes, and `0 B/s` would say it is not.
 */
let rateSample: { sent: number; received: number; atMs: number } | null = null;

/**
 * Forgets the reading a rate would be measured from.
 *
 * Called when the proxy's run changes, because the counters reset with it: a rate taken across a
 * restart would divide this session's bytes by an interval that includes the previous one's, and
 * a total that has gone *down* is a new count from zero rather than a negative rate.
 */
function resetRateSample(): void {
  rateSample = null;
  rate.value = null;
}

/**
 * How fast the totals are moving, from the reading just taken and the one before it.
 *
 * Measured over the time between the two samples and not over the poll interval: the poll is a
 * chain of `setTimeout`s whose wait depends on what the previous read returned, so "3 seconds" is
 * only ever roughly true, and dividing by the interval it actually was is the difference between
 * a rate and a guess dressed up as one.
 */
function sampleRate(): void {
  const current = totals.value;
  if (!current) {
    resetRateSample();
    return;
  }

  const atMs = Date.now();
  const previous = rateSample;
  rateSample = { sent: current.sent, received: current.received, atMs };

  // The first reading of a run has nothing to be divided against.
  if (!previous) {
    rate.value = null;
    return;
  }

  const seconds = (atMs - previous.atMs) / 1000;
  // Two readings in the same millisecond divide by zero. The rate already on screen is the last
  // thing measured, and is nearer the truth than anything computed from this pair.
  if (seconds <= 0) return;

  // Counters only ever go up inside one run. A lower reading means the proxy restarted between
  // the two samples, so there is no interval these numbers describe — which is not a negative
  // rate, and not a slow one either.
  if (current.sent < previous.sent || current.received < previous.received) {
    rate.value = null;
    return;
  }

  rate.value = {
    up: (current.sent - previous.sent) / seconds,
    down: (current.received - previous.received) / seconds,
  };
}

/**
 * Set when the last few status reads failed, so the UI can admit the numbers on screen may be
 * out of date rather than presenting them with the same confidence as a live reading.
 */
const stale = ref(false);

/** What the last start asked for, so the mode that comes back can be checked against it. */
const requestedMode = ref<ProxyMode | null>(null);

const { config, updateConfig, completeEnrollment } = useConfigStore();
const toast = useToast();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isAppError(value: unknown): value is AppError {
  return typeof value === 'object' && value !== null && typeof (value as AppError).code === 'string';
}

/**
 * Writes the connection state onto the tray icon.
 *
 * The tray is the app's only always-on surface: a window nobody opened is a
 * window nobody is looking at, and the icon is where the state is written down.
 *
 * The words are the user's language, so they are resolved here rather than in
 * the backend — the same arrangement the menu labels use.
 *
 * A failure is its own word rather than the same one as "not connected": the
 * two mean different things to the user — one is a switch that is off, the
 * other is a switch that was turned on and did not work — and the tray is the
 * only place a start nobody watched can say so.
 *
 * Infallible: a tray that cannot be written to is still a working tray, and a
 * failed write must not become a failed status read.
 */
async function writeTrayStatus(): Promise<void> {
  const state = status.value;
  const text = state.running
    ? translate('tray.connected')
    : state.mode === 'starting'
      ? translate('tray.connecting')
      : startupError.value
        ? translate('tray.failed')
        : // The state could not be read. The tray is the app's only always-on surface, so it
          // must not claim the tunnel is down when this process cannot see it either.
          state.mode === 'unknown'
          ? translate('tray.unknown')
          : translate('tray.disconnected');

  try {
    await setTrayStatus(text);
  } catch (error) {
    console.error('[proxy] the tray status could not be written:', error);
  }
}

/**
 * The tray writes, one after another.
 *
 * Each write is a round trip to the backend, and two of them in flight at once
 * can arrive in the other order — the older state landing last, so the tray
 * says "connected" about a tunnel that is down. The queue makes the order the
 * order the states happened in.
 *
 * The state is read when a write *begins*, not when it is queued: a write
 * that was queued for an older state would otherwise put the old words on the
 * tray after the new ones.
 */
let trayWrite: Promise<void> = Promise.resolve();

function queueTrayStatus(): Promise<void> {
  trayWrite = trayWrite.then(writeTrayStatus, writeTrayStatus);
  return trayWrite;
}

/** Reads the status (and, while running, the node ID). Returns whether the read succeeded. */
async function refresh(): Promise<boolean> {
  try {
    const result = await invoke<ProxyStatus>('get_proxy_status', {
      useService: config.useService,
    });
    // Assigned only when it has moved. `waitForStart` reads this several times a
    // second, and every result is a fresh object, so writing it unconditionally
    // re-rendered the whole page four times a second for an answer that had not
    // changed — which is what left the main thread too busy to keep a spinner
    // turning. `running` and `mode` are the whole of `ProxyStatus`.
    if (result.running !== status.value.running || result.mode !== status.value.mode) {
      // Bumped on the transition, not on every answer: starting and stopping are the moments a
      // reply about the previous run can still be on its way. See `session`.
      if (result.running !== status.value.running) {
        session += 1;
        // The counters reset with the run, so a rate measured across the boundary would divide
        // this run's bytes by an interval that includes the last one's. See `sampleRate`.
        resetRateSample();
      }
      status.value = result;
      void queueTrayStatus();
    }
    if (result.running) {
      // Not awaited: the Node ID is a display value, and a caller that only needs to know
      // whether the proxy is up — `waitForStart` above all — should not wait another backend
      // round trip for it. The guard inside drops an answer the next run has outlived.
      void refreshNodeId();
    } else {
      // Cleared only when there is something to clear: a fresh `[]` is a new
      // array, and every one of them invalidated the link badges.
      nodeId.value = '';
      if (endpointLinks.value.length > 0) endpointLinks.value = [];
      if (nodeHealth.value.length > 0) nodeHealth.value = [];
      if (nodeTraffic.value.length > 0) nodeTraffic.value = [];
    }
    return true;
  } catch (error) {
    // A status read is a background poll; a toast on every failure would be noise. The start
    // path reports its own failures, and the console keeps the trail.
    console.error('[proxy] failed to read status:', error);
    return false;
  }
}

/**
 * Reads how every node is currently reaching its backend.
 *
 * Infallible: an empty answer means "nothing is connected", which the UI renders by drawing no
 * link at all — a failure here must never become a red error over an otherwise healthy proxy.
 */
async function refreshEndpointLinks(): Promise<void> {
  const asked = session;
  try {
    const links = await invoke<EndpointLink[]>('get_endpoint_links', {
      useService: config.useService,
    });
    if (asked !== session) return;
    endpointLinks.value = links;
  } catch (error) {
    console.debug('[proxy] endpoint links unavailable:', error);
    if (asked !== session) return;
    endpointLinks.value = [];
  }
}

/**
 * Reads whether every node answered its last probe.
 *
 * Infallible for the same reason the links are: an empty answer means "nothing has been probed",
 * and a failure here must never become an error over an otherwise healthy proxy.
 */
async function refreshNodeHealth(): Promise<void> {
  const asked = session;
  try {
    const health = await invoke<NodeHealth[]>('get_node_health', {
      useService: config.useService,
    });
    if (asked !== session) return;
    nodeHealth.value = health;
  } catch (error) {
    console.debug('[proxy] node health unavailable:', error);
    if (asked !== session) return;
    nodeHealth.value = [];
  }
}

/**
 * Reads what every node has carried.
 *
 * Infallible for the same reason the links are: an empty answer means "nothing has moved yet",
 * and a failure here must never become an error over an otherwise healthy proxy.
 */
async function refreshNodeTraffic(): Promise<void> {
  const asked = session;
  try {
    const traffic = await invoke<NodeTraffic[]>('get_node_traffic', {
      useService: config.useService,
    });
    if (asked !== session) return;
    nodeTraffic.value = traffic;
    sampleRate();
  } catch (error) {
    console.debug('[proxy] node traffic unavailable:', error);
    if (asked !== session) return;
    nodeTraffic.value = [];
    // No reading, so nothing to measure from either. The rate is left as it was rather than
    // zeroed: it is the last thing that was actually measured, and a dropped poll is not a
    // tunnel that stopped moving.
  }
}

/**
 * The runtime link kind of a node, or null when nothing is connected to it — the normal answer
 * before the proxy is started.
 *
 * Keyed on the connection string exactly as it was configured, which is what the backend echoes
 * back: a ticket is opaque here, so the resolved endpoint ID alone would not match.
 */
function linkKindFor(node: NodeConfig): LinkKind | null {
  const connection = node.connectionType === 'ticket' ? node.ticket : node.endpointId;
  if (!connection) return null;
  return endpointLinks.value.find((link) => link.connection === connection)?.link ?? null;
}

/**
 * The round-trip time of the path carrying a node's traffic, in milliseconds, or null when
 * iroh has no sample — a path that has just opened, or one it cannot measure.
 *
 * Null is not zero: a node whose latency has not been measured yet says so, rather than
 * claiming to be instantaneous.
 *
 * Keyed on the connection string, the same key `linkKindFor` looks its own answer up by.
 */
function rttFor(node: NodeConfig): number | null {
  const connection = node.connectionType === 'ticket' ? node.ticket : node.endpointId;
  if (!connection) return null;
  return endpointLinks.value.find((link) => link.connection === connection)?.rttMs ?? null;
}

/**
 * What the last probe of a node found, or null when nothing has probed it — the normal answer
 * before the proxy is started, and for the first probe interval after it is.
 *
 * Keyed on the connection string, the same key `linkKindFor` looks its own answer up by.
 */
function healthFor(node: NodeConfig): NodeHealth | null {
  const connection = node.connectionType === 'ticket' ? node.ticket : node.endpointId;
  if (!connection) return null;
  return nodeHealth.value.find((health) => health.connection === connection) ?? null;
}

/**
 * What one node has carried, or `null` when the backend has said nothing about it.
 *
 * `null` covers three cases that look identical here and are worth keeping distinct in prose:
 * nothing is running, the node has not been handed a connection yet, and the last poll failed. In
 * every one of them the honest thing to draw is no figures at all, not a row of zeroes.
 *
 * Keyed on the connection string, the same key `linkKindFor` and `healthFor` look their own
 * answers up by.
 *
 * Nothing here subtracts one reading from another: the counters are cumulative and reset when the
 * proxy restarts, so a figure that came back lower is simply a new count from zero — which is why
 * the page prints totals and never a difference.
 */
function trafficFor(node: NodeConfig): NodeTraffic | null {
  const connection = node.connectionType === 'ticket' ? node.ticket : node.endpointId;
  if (!connection) return null;
  return nodeTraffic.value.find((traffic) => traffic.connection === connection) ?? null;
}

async function refreshNodeId(): Promise<void> {
  const asked = session;
  try {
    const id = await invoke<string>('get_node_id_display', {
      useService: config.useService,
    });
    if (asked !== session) return;
    nodeId.value = id;
  } catch (error) {
    // Not running, or the node has not published an ID yet — both are normal, not reportable.
    if (asked !== session) return;
    nodeId.value = '';
    console.debug('[proxy] node id unavailable:', error);
  }
}

/**
 * The Node ID in full, for the user to copy into a server's `[peers] allow`.
 *
 * Deliberately not the value on screen: the poll reads a mask, and asking for the whole string is
 * a request the backend can see and refuse. Callers get `null` rather than a rejection when the
 * proxy is not up, so a copy button can stay quiet about it.
 */
async function revealNodeId(): Promise<string | null> {
  try {
    return await invoke<string>('reveal_node_id', { useService: config.useService });
  } catch (error) {
    console.error('[proxy] failed to reveal the node id:', error);
    return null;
  }
}

/** Reads the failure `start_proxy` recorded after it had already returned, if any. */
async function readStartupError(): Promise<AppError | null> {
  try {
    const result = await invoke<AppError | null>('get_startup_error');
    return isAppError(result) ? result : null;
  } catch (error) {
    console.error('[proxy] failed to read startup error:', error);
    return null;
  }
}

/**
 * Waits for the start to settle: `starting` until the manager reaches a live mode, or back to
 * `stopped` when it gave up. Bounded, unlike the previous fixed 1s + 2s sleeps, so a slow start
 * (iroh endpoint bind + first route install) is no longer reported as a failure.
 */
async function waitForStart(): Promise<void> {
  const deadline = Date.now() + START_TIMEOUT_MS;
  let sawStarting = false;

  while (Date.now() < deadline) {
    await refresh();

    if (status.value.running) return;

    if (status.value.mode === 'starting') {
      sawStarting = true;
    } else if (sawStarting) {
      // It was starting and is not any more, without ever reporting a live mode: it failed.
      return;
    }

    await sleep(POLL_INTERVAL_MS);
  }
}

async function start(): Promise<void> {
  if (busy.value) return;

  busy.value = true;
  startupError.value = null;

  const backendNodes = config.nodes
    .filter((node) => node.ticket || node.endpointId)
    .map((node) => ({
      connection_type: node.connectionType,
      ticket: node.connectionType === 'ticket' ? node.ticket : '',
      endpoint_id: node.connectionType === 'endpoint_id' ? node.endpointId : '',
      domains: node.domains,
      // Per node, not per client: each server has its own [auth].clients entry.
      two_factor_client_id: node.twoFactor?.clientId ?? null,
      two_factor_secret: node.twoFactor?.secret ?? null,
      two_factor_algorithm: node.twoFactor?.algorithm ?? null,
      // Which device of this client the secret belongs to. Absent is the unnamed device,
      // which answers with the client's own secret — the shape every server understood
      // before a client could have several.
      two_factor_device: node.twoFactor?.device ?? null,
      // This machine's own Ed25519 key for this endpoint. A property of the device
      // rather than of the credential: the same key is offered by the enrollment
      // that spends the token and signs every handshake after it.
      device_key: node.deviceKey ?? null,
      // A registration invite's token, spent on the first connection of this run.
      enrollment_client_id: node.enrollment?.clientId ?? null,
      enrollment_token: node.enrollment?.token ?? null,
      // The name to be enrolled under: without it the server issues the client's own
      // secret, and this machine is one device it cannot revoke on its own.
      enrollment_device: node.enrollment?.device ?? null,
    }));

  const wantTun = config.useTun;
  requestedMode.value = wantTun ? 'tun' : 'local_proxy';

  try {
    await invoke('start_proxy', {
      nodes: backendNodes,
      domains: config.domains,
      localAddr: config.localAddr,
      dnsAddr: config.dnsAddr,
      upstreamDns: config.upstreamDns,
      // What the machine's DNS is asked to do. Sent by name so the backend can refuse a
      // spelling it does not know, rather than quietly picking one.
      dnsStrategy: config.dnsStrategy,
      loadBalancing: config.loadBalancing,
      tunName: config.tunName,
      useService: config.useService,
      useTun: wantTun,
      relayMode: config.relayMode,
      relayUrl: config.relayUrl,
      // The token goes to the relay it was issued for and to no other: the
      // backend cannot know which relay issued a token, so the answer is
      // given here, where the relay being configured is known.
      relayAuthToken: relayTokenToSend(
        { token: config.relayAuthToken, relay: config.relayAuthTokenRelay },
        config.relayUrl,
      ),
    });

    await waitForStart();
    // A fresh session means fresh paths, and fresh counters: read them now instead of waiting out
    // the poll, which otherwise leaves the link badges empty for the first few seconds after every
    // start. Not awaited: the start is over the moment the status says it is, and these only fill
    // the dashboard — awaiting them here is what kept the button spinning after it had already
    // turned into "stop". All three are infallible, and each drops an answer the next run has
    // outlived.
    if (status.value.running) {
      void refreshEndpointLinks();
      void refreshNodeHealth();
      void refreshNodeTraffic();
    }

    if (!status.value.running) {
      // Only read the recorded failure when the start did not succeed: it is never cleared, so a
      // stale entry from an earlier attempt must not be reported as this one's.
      const recorded = await readStartupError();
      startupError.value = recorded ?? { code: 'proxy.start_failed' };
      toast.error(recorded ?? { code: 'proxy.start_failed' }, 'error.proxy.start_failed');
      // The tray says so too: a start nobody watched has only the tray to say so.
      void queueTrayStatus();
      return;
    }

    // Read before anything else can fail the start: a spent token is gone, and the credential
    // it bought is the only copy this process will ever see.
    await collectIssuedCredential();

    // The mode that actually came up must match what was asked for (§5.12 rule 4). A mismatch
    // means something downgraded the request — surface it instead of showing a green light.
    if (status.value.mode !== requestedMode.value) {
      toast.warning(
        translate('connect.modeMismatch', {
          // "Unknown" is not a mode: it is the absence of an answer, and it is said the same
          // way the rest of the app says it.
          mode:
            status.value.mode === 'unknown'
              ? translate('status.unknown')
              : translate(`mode.${status.value.mode}`),
        }),
      );
      return;
    }

    toast.success(translate('connect.started'));
  } catch (error) {
    // A failure with no structured error still is a failure: recorded as the generic code
    // rather than as nothing, so the tray can say "connection failed" instead of "not
    // connected" — the two mean different things to the user.
    startupError.value = isAppError(error) ? error : { code: 'proxy.start_failed' };
    toast.error(error, 'error.proxy.start_failed');
    void queueTrayStatus();
  } finally {
    busy.value = false;
  }
}

/**
 * Stores the credential the server issued for an enrollment token, if one was spent.
 *
 * A token is spent by the first connection that presents it, so this has to run right after a
 * successful start: without it the secret exists only in the backend process's memory, and the
 * next launch falls back to an invite the server has already forgotten.
 */
async function collectIssuedCredential(): Promise<void> {
  try {
    const credential = await takeIssuedCredential(config.useService);
    if (!credential) return;
    const node = completeEnrollment(credential);
    if (node) {
      toast.success(translate('invite.enrolled', { client: credential.clientId }));
    } else {
      // Nothing was waiting for it: dropping the credential is the safe outcome, but losing a
      // secret silently is not, so it is said out loud.
      console.warn('[proxy] a credential was issued but no node was enrolling');
    }
  } catch (error) {
    console.error('[proxy] failed to read the enrolled credential:', error);
  }
}

async function stop(): Promise<void> {
  if (busy.value) return;

  busy.value = true;
  try {
    await invoke('stop_proxy', { useService: config.useService });
    await refresh();
    toast.success(translate('connect.stopped'));
  } catch (error) {
    toast.error(error, 'error.proxy.stop_failed');
  } finally {
    busy.value = false;
  }
}

/**
 * Whether the system service is answering. Polled rather than assumed: it gates the TUN toggle
 * (§5.12 rule 3), and the answer changes when the service is installed, uninstalled, or dies.
 *
 * Three answers are read together, because they only mean something next to each other: whether
 * something is answering on the IPC port, what the service manager says about the service, and
 * which build the service says it is.
 *
 * A read that comes back empty is a question that was not answered, not an answer. The IPC read
 * has deadlines of its own, so one such read is not acted on: it would turn TUN off, lose the
 * setting across the next launch, and invite a reinstall of a service that was never broken.
 * Several of them in a row are.
 */
async function refreshServiceRunning(): Promise<void> {
  const [running, state, version] = await Promise.all([
    invoke<boolean>('is_service_running').catch((error) => {
      console.error('[proxy] failed to query the service:', error);
      return false;
    }),
    invoke<'not_installed' | 'stopped' | 'running'>('get_service_status').catch(() => {
      // The service manager is unavailable; treat the service as absent for install controls.
      return 'not_installed' as const;
    }),
    // Which build the service says it is. `null` is an answer too: a service that will not say
    // which build it is, whether because it is gone or because it speaks another protocol.
    invoke<string | null>('get_service_version').catch((error) => {
      console.debug('[proxy] the service did not report its version:', error);
      return null;
    }),
  ]);

  // Nothing answered on the IPC port this time. Whether the service is *gone* is a different
  // question, and one missed deadline does not answer it, so the answer is only believed once it
  // has been repeated. Every read that answered clears the count.
  if (running) {
    serviceReadFailures = 0;
    serviceRunning.value = true;
    serviceUnanswered.value = false;
  } else {
    serviceReadFailures += 1;
    if (serviceReadFailures >= SERVICE_FAILURES_BEFORE_TRUST) {
      serviceRunning.value = false;
      serviceUnanswered.value = true;
    }
    // Otherwise the state is unknown, and the last answer stands: the service is not known to be
    // gone, and nothing is claimed about it.
  }

  // The same question about the build, and the same rule: a read that answers is believed at
  // once. A read that does not is believed only when something else explains the silence —
  // either the IPC worked in this same round trip, so the service refused the question, or the
  // service has stopped answering altogether. A read that timed out while the IPC was up says
  // nothing about the build, so nothing is claimed about it.
  if (version !== null) {
    serviceVersion.value = version;
  } else if (running || serviceUnanswered.value) {
    serviceVersion.value = null;
  }

  // Installed and answering are different facts: the install button disappears as soon as the
  // unit exists, while TUN stays gated on the IPC connection actually being usable. Which of
  // the two says "running" is kept as well, because the service manager saying "running" while
  // nothing answers is what an upgrade leaves behind.
  serviceState.value = state;

  // TUN cannot run without the service, so an uninstalled service must not leave a latent
  // request behind (rule 3): the toggle flips back off and says why. Only once the reads have
  // shown that the service has stopped answering, though — one missed deadline must not cost the
  // user the setting.
  if (serviceUnanswered.value && config.useTun) {
    updateConfig({ useTun: false });
    toast.warning(translate('connect.tunUnavailableServiceGone'));
  }
}

/**
 * How long a service action may take before the panel stops waiting for it to show up.
 *
 * Covers a start that is still binding its IPC listener and an install that has to move a copy
 * under Program Files first. Past this the panel reads what is there, so a service that really
 * is in a one-sided state still says so.
 */
const SERVICE_SETTLE_TIMEOUT_MS = 10_000;

/**
 * The state a service action is heading towards, as the two answers this app can get would
 * describe it: "answering" is registered and answering, "quiet" is registered and not, and
 * "absent" is not registered at all.
 */
type ServiceTarget = 'answering' | 'quiet' | 'absent';

function serviceReached(
  state: 'not_installed' | 'stopped' | 'running',
  answering: boolean,
  target: ServiceTarget,
): boolean {
  switch (target) {
    case 'answering':
      return state === 'running' && answering;
    case 'quiet':
      return state !== 'running' && !answering;
    case 'absent':
      return state === 'not_installed' && !answering;
  }
}

/**
 * Waits until both service answers agree with the action that just finished, then re-reads
 * them once.
 *
 * A successful action is not over when the command returns: the service manager accepts it
 * first, and the process it accepted may still be on its way up (or down). Reading in that
 * window pairs a fresh answer with a stale one — "running" from the manager and no version
 * from the IPC — and every surface draws that as a service that is out of date. Which pair is
 * the settled one depends on the action, so the caller names the target rather than a single
 * boolean.
 *
 * Bounded: a service that genuinely fails to come up must still leave a panel that says so,
 * so after the deadline the state as found is what gets shown — and if the two answers still
 * disagree then, that is a real signal rather than a transition. The answer says whether the
 * target was actually reached, so a caller does not report success for a command whose effect
 * never showed up. A failed action does not call this at all: its error is already on screen,
 * and waiting would only delay the state it left.
 */
async function settleService(target: ServiceTarget): Promise<boolean> {
  const deadline = Date.now() + SERVICE_SETTLE_TIMEOUT_MS;
  let reached = false;
  while (Date.now() < deadline) {
    const [answering, state] = await Promise.all([
      // A full IPC exchange, not a bare connect: "answering" means the service can answer
      // requests, which is what the version read below needs.
      invoke<boolean>('is_service_running').catch(() => false),
      invoke<'not_installed' | 'stopped' | 'running'>('get_service_status').catch(
        () => 'not_installed' as const,
      ),
    ]);
    if (serviceReached(state, answering, target)) {
      reached = true;
      break;
    }
    await sleep(250);
  }
  await refreshServiceRunning();
  return reached;
}

/**
 * Sets the forwarding mode. Refuses to persist TUN while the service is not installed — the
 * toggle is disabled in that state, and a persisted request that cannot be honoured is worse
 * than none.
 *
 * Turning TUN on also moves the proxy into the service. It is not a preference being fiddled
 * with behind the user's back: creating a virtual network card needs rights this app does not
 * ask for at startup, so the only process that can run TUN is the one that runs elevated, and a
 * TUN request left on the unprivileged backend fails with `proxy.tun_unavailable` every time.
 */
function setUseTun(enabled: boolean): void {
  if (enabled && !serviceRunning.value) {
    // Three different refusals, because they have three different ways out: install a service
    // that is not there, start one that is installed and down, reinstall one that is there but
    // running a build this app cannot talk to. Telling somebody to "install it first" about a
    // service that is already installed sends them looking for the wrong thing.
    if (serviceStale.value) {
      toast.warning(translate('connect.tunServiceStale'));
    } else if (serviceState.value === 'stopped') {
      toast.warning(translate('connect.tunServiceStopped'));
    } else {
      toast.warning(translate('connect.tunRequiresService'));
    }
    return;
  }

  if (enabled && !config.useService) {
    updateConfig({ useService: true, useTun: true });
    toast.info(translate('connect.tunSwitchedBackend'));
    return;
  }

  updateConfig({ useTun: enabled });
}

/* -- polling --------------------------------------------------------------------------------- */

/**
 * Replaces the manual "Refresh Status" button: the status, the node ID and every node's link kind
 * are re-read on a timer, so a service that dies, or a path iroh promotes from relay to direct,
 * shows up on its own within a few seconds.
 *
 * The timer is a chain of `setTimeout`s rather than a fixed `setInterval`: the interval depends
 * on the state the previous read returned, and a slow backend must not have requests piled onto
 * it while one is still in flight.
 */
let pollTimer: ReturnType<typeof setTimeout> | null = null;
let servicePollTimer: ReturnType<typeof setTimeout> | null = null;
let inFlight = false;
let consecutiveFailures = 0;
/**
 * Which run of the proxy the numbers below describe.
 *
 * Bumped whenever the proxy starts or stops. Every read takes the value it had when it asked and
 * drops the answer if it has moved since, because a request that was already in flight when `stop()`
 * ran comes back with the totals from before it — and writing those back was how a stopped session
 * kept reporting traffic: `stopped` clears the counters, the reply lands a moment later and
 * refills them, and the dashboard shows bytes moving across a tunnel that is down until some later
 * poll happens to clear them again. Starting is the same argument in the other direction: whatever
 * a previous session was carrying is not this session's history.
 *
 * Not a lock and not an abort: the request still completes, because cancelling an `invoke` is not
 * something this layer can do. What is refused is writing its answer.
 */
let session = 0;

function nextInterval(): number {
  if (consecutiveFailures >= FAILURES_BEFORE_BACKOFF) return POLL_BACKOFF_MS;
  if (status.value.mode === 'starting') return POLL_STARTING_MS;
  return status.value.running ? POLL_RUNNING_MS : POLL_STOPPED_MS;
}

async function pollOnce(): Promise<void> {
  if (inFlight) return;
  inFlight = true;
  try {
    const ok = await refresh();
    consecutiveFailures = ok ? 0 : consecutiveFailures + 1;
    stale.value = !ok && consecutiveFailures >= FAILURES_BEFORE_BACKOFF;
    if (status.value.running) {
      await refreshEndpointLinks();
      await refreshNodeHealth();
      await refreshNodeTraffic();
    }
  } finally {
    inFlight = false;
  }
}

function schedulePoll(): void {
  if (pollTimer !== null) return;
  const wait = nextInterval();
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    await pollOnce();
    schedulePoll();
  }, wait);
}

/**
 * The service gate has its own slow timer rather than riding the status poll: installing,
 * uninstalling or crashing the service is not something this store is told about, and a folded
 * laptop comes back to a different answer than the one it left with.
 */
function scheduleServicePoll(): void {
  if (servicePollTimer !== null) return;
  servicePollTimer = setTimeout(async () => {
    servicePollTimer = null;
    await refreshServiceRunning();
    scheduleServicePoll();
  }, SERVICE_POLL_MS);
}

/** Starts both polls. Idempotent: the shell calls it once, and so can a page. */
function startPolling(): void {
  schedulePoll();
  scheduleServicePoll();
}

function stopPolling(): void {
  if (pollTimer !== null) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  if (servicePollTimer !== null) {
    clearTimeout(servicePollTimer);
    servicePollTimer = null;
  }
}

/**
 * Forces an immediate re-read and re-arms the timers.
 *
 * Used when the app regains focus: a laptop that just woke up has been showing whatever the
 * status was before it slept, and waiting out the interval to find out is the wrong default.
 */
async function refreshNow(): Promise<void> {
  // The service gate first: when the state it carries is stale, so is every button it enables.
  await refreshServiceRunning();
  await pollOnce();
  // Re-arm both timers: stopping clears the service poll too, and re-arming only the status one
  // would leave the TUN gate frozen at whatever it read last.
  stopPolling();
  startPolling();
}

export function useProxyStore() {
  return {
    status,
    nodeId,
    busy,
    startupError,
    serviceRunning,
    /** Whether the service has stopped answering, as far as the reads have shown. */
    serviceUnanswered,
    /** What the service manager says: not registered, registered and down, registered and up. */
    serviceState,
    serviceInstalled,
    /** Which build the service says it is; `null` when it did not answer that question. */
    serviceVersion,
    /** The service is registered and running but did not answer this build — a drift. */
    serviceStale,
    /** How each node is currently reaching its backend. */
    endpointLinks,
    /** Whether each node answered its last probe. */
    nodeHealth,
    /** What each node has carried since the counters started. */
    nodeTraffic,
    /** Every node's counters added together. `null` while nothing has been counted. */
    totals,
    /** How fast those totals are moving. `null` until two readings apart in time exist. */
    rate,
    /** The mode the last start asked for; compared against what actually runs. */
    requestedMode,
    /** True when the status could not be read for a while; the panel says so out loud. */
    stale,
    isRunning: computed(() => status.value.running),
    canStart: computed(() => config.nodes.some((node) => node.ticket || node.endpointId)),
    start,
    stop,
    refresh,
    refreshNow,
    refreshNodeId,
    revealNodeId,
    refreshServiceRunning,
    /** Settles after a service action before reading, so a transition is not drawn as drift. */
    settleService,
    setUseTun,
    linkKindFor,
    rttFor,
    healthFor,
    trafficFor,
    startPolling,
    stopPolling,
  };
}

/**
 * Writes the current state onto the tray icon again, in the current language.
 *
 * Called when the language changes: the tray's words are the user's language,
 * so they do not change on their own the way the menu's labels do not.
 */
export function refreshTrayStatus(): void {
  void queueTrayStatus();
}

/** Called once at startup by the shell, before the first status render. */
export async function initProxyState(): Promise<void> {
  await refreshServiceRunning();
  await refresh();
  // From here on the panel keeps itself up to date; nothing in the UI has to ask for a refresh.
  startPolling();
  // Written once here as well as on every change: the tray says what the state is from the
  // moment the app is up, rather than from the moment the state first moves.
  await queueTrayStatus();
  await autoConnectIfWanted();
}

/**
 * Brings the tunnel up by itself, when the user asked for that.
 *
 * Only for a launch the *machine* asked for. A launch the user made is a launch
 * the user is already looking at, and starting the tunnel under their hands
 * without being asked is not what "connect after login" says.
 *
 * Skipped when the tunnel is already up: the service keeps a tunnel it started
 * across a restart of the desktop app, and asking it for a second one would
 * replace a working tunnel with a new one.
 *
 * The failure is the tray's business rather than the window's. `start` reports
 * a failure with a toast, and nobody is watching a window the machine opened
 * — so the state is read back and written to the tray, which is the surface
 * that is always on screen.
 */
async function autoConnectIfWanted(): Promise<void> {
  if (!usePrefsStore().prefs.autoConnect) return;
  if (status.value.running) return;
  if (!(await isBackgroundLaunch())) return;

  // The status read above falls back to the desktop process when the service
  // cannot be reached, so "not running" here can mean "the service is down and
  // we do not know what it is doing" rather than "the tunnel is stopped". A
  // start on that guess would ask the service for a tunnel it may already
  // have, and a refusal would leave the machine unprotected for a reason
  // nobody can see. So the state is asked of the service directly.
  if (config.useService && !(await serviceReportsStopped())) {
    return;
  }

  await start();

  // `start` swallows its own failure and reports it with a toast, so the state
  // is read rather than caught: a failed automatic connection leaves the tunnel
  // down, and the tray has to say so.
  if (!status.value.running) {
    await queueTrayStatus();
  }
}

/**
 * Whether the service itself says the tunnel is down.
 *
 * Asked of the service rather than read from the status above: in service mode a
 * start is handed to the service, and a fallback answer is not a statement that
 * the service can take one. The fallback now reports "stopped" for a service
 * that is down, but starting in that state would run the tunnel here instead of
 * in the service — so the service has to be answering before its "stopped"
 * counts.
 *
 * `false` covers "the service is not answering", which is the honest answer
 * here: nothing is known, so nothing is started.
 */
async function serviceReportsStopped(): Promise<boolean> {
  try {
    if (!(await invoke<boolean>('is_service_running'))) return false;
    const result = await invoke<ProxyStatus>('get_proxy_status', { useService: true });
    // Running, starting and unknown are not statements that it is stopped, and a question that
    // is open must not be answered with "stopped": that answer is what starts a second tunnel
    // over a live one.
    return result.mode === 'stopped';
  } catch (error) {
    console.error('[proxy] the service did not report its status:', error);
    return false;
  }
}

/**
 * Called by the shell when the window becomes visible again.
 *
 * The poll keeps running while the app is in the background, but a machine that has been asleep
 * answers differently the moment it wakes, so the first thing to do is read, not wait.
 */
export function onAppFocused(): void {
  void refreshNow();
}
