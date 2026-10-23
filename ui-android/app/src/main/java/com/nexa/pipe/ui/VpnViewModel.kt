package com.nexa.pipe.ui

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.NodeTraffic
import com.nexa.pipe.PermissionManager
import com.nexa.pipe.R
import com.nexa.pipe.parseNodeTraffic
import com.nexa.pipe.SecretStore
import com.nexa.pipe.SettingsManager
import com.nexa.pipe.locale.AppStrings
import com.nexa.pipe.vpn.NexaVpnService
import com.nexa.pipe.vpn.UnderlyingNetworkSelector
import com.nexa.pipe.vpn.VpnSlot
import com.nexa.pipe.vpn.VpnTakeoverChoice
import com.nexa.pipe.vpn.VpnTakeoverDecision
import com.nexa.pipe.vpn.VpnTakeoverPolicy
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress

import kotlinx.serialization.Serializable

/**
 * The 2FA credentials of one endpoint.
 *
 * They belong to the endpoint, not to the app: every server keeps its own
 * `[auth].clients` table, so a second server either needs its own pair or has
 * to be handed the first one's secret. [secret] is only ever persisted in the
 * prefs file that backup excludes — see `SettingsManager`.
 */
@Serializable
data class NodeTwoFactor(
    val enabled: Boolean = true,
    val clientId: String = "",
    val secret: String = "",
    val algorithm: String = "sha1", // "sha1", "sha256", "sha512"
    /**
     * The device this credential was issued to, when the server said which.
     *
     * Null or blank means it is the client's shared secret rather than one
     * device's — what every pair saved before this existed is, and what the
     * field stays until the endpoint is enrolled under a name. The server
     * cannot revoke one device of a client through a credential nobody owns.
     */
    val device: String? = null,
    /**
     * The public half of this device's own key, when the credential is a key.
     *
     * Null for a credential that is a secret, and that is how the two are told
     * apart. The public half is not a secret — the server holds it too — so it
     * lives here, next to the credential it belongs to, and is shown so an
     * operator can tell which key a server has on file.
     *
     * The private half is the credential and never appears in this model: it is
     * sealed in the file backup excludes, and it is read from there when a
     * connection needs it. A model that is serialized into the backed-up
     * endpoint list is the wrong place for a half that must never leave the
     * device.
     */
    val publicKey: String? = null
)

/**
 * A one-time enrollment token, in place of credentials.
 *
 * The token is spent by the first connection, which answers with the secret this
 * device then keeps — and rotates the one the server held, so a code that leaked
 * on its way here stops working the moment it is used.
 */
@Serializable
data class NodeEnrollment(
    val clientId: String = "",
    val token: String = ""
)

@Serializable
data class NodeConfig(
    val nodeId: String,
    val domains: List<String> = emptyList(),
    val twoFactor: NodeTwoFactor? = null,
    /**
     * A token to spend instead of presenting credentials. Cleared once the
     * issued secret has landed in [twoFactor], so an endpoint never holds both.
     */
    val enrollment: NodeEnrollment? = null
)

/**
 * The bearer token of a custom relay, and the relay it was issued for.
 *
 * A token is issued by one relay and is good for that relay alone: it is a
 * bearer credential, and a relay that is handed a token it never issued
 * learns it — and can use it against the relay that did issue it. So the
 * token is kept together with the URL of the relay it belongs to, and that
 * URL is what decides whether the token may still be sent.
 *
 * The URL is the one the token was issued for, not the one in use: a mode
 * that does not use a relay URL at all leaves the token alone.
 */
data class RelayToken(
    /** The token itself. Empty when there is none. */
    val token: String = "",
    /** The URL of the relay the token was issued for. Empty when there is none. */
    val relayUrl: String = ""
)

/**
 * What a change of the relay configuration does to the token.
 *
 * Named rather than a nullable string, because "the token stays" and "the
 * token goes" are two different things and a caller has to say which one it
 * means. A parameter that defaulted to the stored token carried a credential
 * over to whatever relay came next — which is how an invite could take a
 * bearer token to a host of its choosing.
 */
sealed interface RelayTokenChange {
    /**
     * The token stays bound to the relay it was issued for.
     *
     * It is kept while that relay is the one being configured, and dropped
     * when the configuration names another relay: a token does not follow a
     * change of relay.
     */
    data object Bound : RelayTokenChange

    /**
     * The token goes, whatever the relay is.
     *
     * For a change that brings no token of its own: an invite names a relay
     * and carries no token for it, so the token this phone holds goes with
     * the import rather than travelling to the relay the invite names.
     */
    data object Drop : RelayTokenChange

    /** The token is this one, and it was issued for the relay being configured. */
    data class Set(val token: String) : RelayTokenChange
}

/**
 * The token that goes with a relay after a change of the configuration.
 *
 * The rule: a token belongs to the relay it was issued for, so it survives
 * only while that relay is the one being configured. An explicit token
 * belongs to the relay it comes with — that is where the user typed it — and
 * a change that brings no token of its own takes the stored one with it.
 *
 * The URL is compared trimmed, because that is how the native side reads it:
 * two spellings of one URL are one relay, and a token that goes to a
 * different spelling of the same relay goes to the same relay.
 */
internal fun relayTokenAfter(
    /** The URL of the relay being configured. */
    url: String,
    /** The token as it stands, and the relay it was issued for. */
    stored: RelayToken,
    /** What the change does to the token. */
    change: RelayTokenChange
): RelayToken {
    val token = when (change) {
        is RelayTokenChange.Set -> change.token
        RelayTokenChange.Drop -> ""
        RelayTokenChange.Bound ->
            if (stored.token.isNotBlank() && stored.relayUrl.trim() == url.trim()) {
                stored.token
            } else {
                ""
            }
    }
    return RelayToken(token = token, relayUrl = if (token.isBlank()) "" else url.trim())
}

/**
 * The token to hand to the native side for a relay.
 *
 * A token is sent to the relay it was issued for and to no other: one whose
 * relay is not the one being configured is not sent at all. The native side
 * has no way of knowing which relay issued a token, so the answer has to be
 * given here.
 */
internal fun relayTokenToSend(stored: RelayToken, url: String): String =
    if (stored.relayUrl.trim() == url.trim()) stored.token else ""

/**
 * Whether the tunnel of a start is up.
 *
 * The two things that say so, and only them: the service reported the
 * establish as done, and the service's own flag says a tunnel is there.
 *
 * The request being delivered says nothing — `startForegroundService()`
 * returns as soon as the request is delivered — and treating it as a tunnel
 * is what made the UI say "connected" over a tunnel that was never
 * established, and keep saying it when the establish failed.
 *
 * @param reportedUp what the service reported about the establish.
 * @param serviceActive whether the service says a tunnel is there.
 */
internal fun tunnelIsUp(reportedUp: Boolean, serviceActive: Boolean): Boolean =
    reportedUp && serviceActive

/**
 * Waits for the service to report whether the tunnel it was asked to build
 * came up.
 *
 * Bounded, because a service that says nothing at all must not leave the UI
 * saying "connecting" forever — and because a start nobody answered is not a
 * tunnel: the attempt is a failure and is retried like any other.
 *
 * @param outcome what the service will report about the start.
 * @param timeoutMs how long to wait for that report.
 * @param log where the line about a wait that ran out goes.
 * @return what the service reported: true when the tunnel is up.
 */
internal suspend fun awaitTunnelUp(
    outcome: CompletableDeferred<Boolean>,
    timeoutMs: Long,
    log: (String) -> Unit
): Boolean {
    return try {
        withTimeout(timeoutMs) { outcome.await() }
    } catch (e: TimeoutCancellationException) {
        // The service was asked and never answered. Not a cancellation of
        // the caller: the wait is over, and the attempt failed.
        log("The tunnel did not come up within ${timeoutMs}ms")
        false
    }
}

class VpnViewModel : ViewModel() {
    private val TAG = "VpnViewModel"
    private var settingsManager: SettingsManager? = null

    val isVpnRunning = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isIrohStarted = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isConnecting = kotlinx.coroutines.flow.MutableStateFlow(false)
    // Deliberately typed as an immutable List: mutating the published list in
    // place makes MutableStateFlow's equality check always succeed, so no
    // update is ever emitted and the UI never recomposes. Always assign a
    // brand-new list instead.
    val nodes = kotlinx.coroutines.flow.MutableStateFlow<List<NodeConfig>>(emptyList())
    val logMessages = kotlinx.coroutines.flow.MutableStateFlow<List<String>>(emptyList())
    val errorMessage = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    /**
     * A message for the user about something the settings did.
     *
     * Set when a change of the relay configuration dropped a credential: the
     * user has to know, because the relay that credential was issued for is
     * not the one this phone talks to any more — and only the user can enter
     * the token the new relay asks for.
     */
    val notice = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)

    /**
     * Takes the notice away once it has been shown.
     *
     * A message that is left behind is a message that is not shown the next
     * time it is raised: the same text twice is the same value, and a state
     * that does not change does not speak again.
     */
    fun clearNotice() {
        notice.value = null
    }
    val connectionStatusText = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    val vpnPermissionGranted = kotlinx.coroutines.flow.MutableStateFlow(false)
    val notificationPermissionGranted = kotlinx.coroutines.flow.MutableStateFlow(false)

    // Relay configuration. There is deliberately no "force relay" switch: iroh 1.0.1 exposes
    // no stable way to stop it promoting a connection to a direct path, so a switch that
    // claimed to would be a lie.
    val relayMode = kotlinx.coroutines.flow.MutableStateFlow("pinned") // "pinned", "default", "disabled", "custom"
    /**
     * The custom relay this phone is configured for.
     *
     * Kept whatever the mode is: the mode says whether that relay is in use,
     * and dropping the URL would lose the user's relay — and the token issued
     * for it — every time they looked at another mode.
     */
    val relayUrl = kotlinx.coroutines.flow.MutableStateFlow("")
    // Whether this device may ask n0 where a peer is. "n0" (the default) or
    // "none" — the second one costs the ability to reach a peer by Node ID
    // alone, because a ticket is what carries an address.
    val discoveryMode = kotlinx.coroutines.flow.MutableStateFlow("n0")
    /**
     * The bearer token of the custom relay, and the relay it was issued for.
     *
     * Never logged, and never sent to a relay other than the one it was
     * issued for — see [relayTokenToSend].
     */
    val relayToken = kotlinx.coroutines.flow.MutableStateFlow(RelayToken())

    /**
     * What this install calls itself when it authenticates.
     *
     * Generated once on the device and then kept: a server can only revoke, or
     * rate-limit, one device of a client if that device has a name of its own,
     * and a name that changed between runs would leave a stale row behind on
     * every single connect. Empty until [loadSettings] has run, which is also
     * what leaves nothing to send on a handshake made before then.
     */
    val deviceId = kotlinx.coroutines.flow.MutableStateFlow("")

    /**
     * Whether the credentials on this device are actually encrypted at rest.
     *
     * Refreshed wherever a credential is written, which is the only moment the
     * answer can change. `Sealed` before anything has been written is honest
     * rather than optimistic: nothing is stored in plaintext yet.
     */
    val credentialProtection =
        kotlinx.coroutines.flow.MutableStateFlow(SecretStore.Protection.Sealed)

    /**
     * Set when a credential is about to be written to a device that cannot
     * protect it. The write waits for the answer: nothing reaches storage
     * while this is true.
     */
    val plaintextConsentPending = kotlinx.coroutines.flow.MutableStateFlow(false)

    /**
     * Whether storing credentials in the clear has already been agreed to on
     * this device. Asked once rather than per credential — a device that cannot
     * seal one cannot seal the next either, and asking again on every write
     * would teach the user to stop reading the question.
     *
     * Mirrors what `SettingsManager` recorded rather than being the only copy:
     * a process that dies must not take the answer with it, because the next
     * launch would ask again about a decision this device already made.
     */
    private var plaintextAccepted = false

    /**
     * Whether this device can protect a credential, cached off the main
     * thread.
     *
     * The answer needs the keystore, and a keystore call is slow enough to be
     * felt as a dropped frame from a text field's `onValueChange`. It also
     * only changes when the keystore does, so it is probed once and kept
     * rather than asked per write.
     */
    @Volatile
    private var canProtectCached: Boolean? = null

    /**
     * What to do when another VPN app owns the slot, as the user last decided.
     *
     * [VpnTakeoverChoice.Ask] until one is made, and resettable from the
     * settings: a remembered Cancel is a decision to never use Nexa alongside
     * another VPN, which is not something the user should have to uninstall the
     * app to revisit.
     */
    val vpnTakeoverChoice =
        kotlinx.coroutines.flow.MutableStateFlow(VpnTakeoverChoice.Ask)

    /**
     * Whether the tunnel should come back on its own after a restart.
     *
     * Off until the user says otherwise: a proxy that reconnects without being
     * asked forwards traffic without being asked.
     */
    val autoConnectOnBoot = kotlinx.coroutines.flow.MutableStateFlow(false)

    /**
     * Whether the VPN permission was missing when the boot path last looked.
     *
     * Android does not promise that the permission survives a restart, so the
     * boot path checks rather than assumes. When it finds the permission gone
     * this says so, because a switch that is on and a tunnel that never comes
     * back is the kind of thing a user cannot act on without being told why.
     */
    val vpnConsentMissing = kotlinx.coroutines.flow.MutableStateFlow(false)

    /**
     * Records whether the tunnel should come back after a restart.
     *
     * Written straight away rather than through the settings queue: there is
     * no credential in it, and the queue exists to order keystore writes.
     */
    fun setAutoConnectOnBoot(enabled: Boolean) {
        autoConnectOnBoot.value = enabled
        settingsManager?.saveAutoConnectOnBoot(enabled)
        addLog("Reconnect after a restart: $enabled")
    }

    /**
     * What the tunnel reports per backend: the kind of path carrying its traffic and the
     * round-trip time of that path, both read off iroh's runtime state and refreshed while
     * the tunnel is up. Empty whenever nothing is connected, which is what keeps the UI from
     * drawing a stale icon after a disconnect.
     */
    val linkReadings = kotlinx.coroutines.flow.MutableStateFlow(LinkReadings())

    /**
     * What each backend has carried, keyed by endpoint ID: cumulative bytes since the proxy
     * was started, plus the flows open to it right now. Refreshed alongside [linkReadings], and
     * empty whenever nothing is connected, for the same reason.
     *
     * A node that is absent has carried nothing — the native side leaves those out instead of
     * reporting zeroes — so a caller showing per-node figures has to say "nothing yet" rather
     * than leave the gap looking like a backend that is down.
     */
    val traffic = kotlinx.coroutines.flow.MutableStateFlow<Map<String, NodeTraffic>>(emptyMap())

    /**
     * What every backend has carried together: [traffic] summed across the map.
     *
     * Derived, not read a second time — the native side is not asked for anything it does not
     * already report, and there is no way for the row on screen to disagree with the per-node
     * figures beside it.
     *
     * `null` while the map is empty, which is the same distinction [traffic] makes per node:
     * nothing has been counted yet, which is not the same as a total that happens to be zero.
     * A screen that drew `0 B` before the first byte would look like a tunnel that works and
     * carries nothing.
     */
    val totalTraffic: StateFlow<NodeTraffic?> =
        traffic
            .map { totals ->
                if (totals.isEmpty()) {
                    null
                } else {
                    NodeTraffic(
                        sent = totals.values.sumOf { it.sent },
                        received = totals.values.sumOf { it.received },
                        active = totals.values.sumOf { it.active },
                    )
                }
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    // 2FA lives on the endpoint now (`NodeConfig.twoFactor`): one server, one
    // pair of credentials. There is no app-wide setting left to publish here.

    // Serialize connect/disconnect so concurrent native calls cannot race.
    private val connectionMutex = Mutex()
    // Refreshes `linkReadings` while the tunnel is up: a connection can be upgraded from relay to
    // direct at any moment, so the icon has to be re-read rather than sampled once.
    private var linkPollJob: Job? = null
    // Keeps a handle on the connect coroutine so disconnect can cancel it
    // (JNI cannot be interrupted, but the next suspension point throws
    // CancellationException).
    private var connectJob: Job? = null

    /**
     * The device-key preparation still running, so a connect can wait for it.
     *
     * [updateNodeEnrollment] starts it because minting and sealing a key reach
     * the keystore and the JNI bridge, neither of which belongs on the main
     * thread the invite import runs on. The call that needs the key — the
     * connect that fills the native tables — joins this first. Chained rather
     * than replaced, so two enrollments in flight still reach the keystore one
     * at a time, which is the rule the settings writer keeps.
     */
    @Volatile
    private var deviceKeyPrep: Job? = null

    init {
        // Push channel from NexaVpnService: our VPN was revoked (or its
        // establishment was refused) because another VPN app (e.g. Clash)
        // took over the single VPN slot Android allows. Update the UI
        // immediately instead of waiting for the next syncVpnServiceState().
        NexaVpnService.setRevokedListener { reason ->
            viewModelScope.launch {
                if (isVpnRunning.value) {
                    // The counters belong to the session that just ended, and the poll that
                    // reads them belongs to it too: leaving either running would keep a total
                    // on screen under "Disconnected", which reads as a tunnel that is up and
                    // carrying bytes. See `refreshTraffic` — no total outlives its session.
                    stopLinkPolling()
                    isVpnRunning.value = false
                    errorMessage.value = reason
                    addLog("Tunnel revoked: $reason")
                }
            }
        }
        // The service telling us the session stopped working (a network switch it could not
        // recover from, or a backend it cannot reach on the new network). Reported while this
        // UI was in the background or not alive at all, so it is the only way the status card
        // stops claiming "Connected" over a tunnel that carries nothing.
        NexaVpnService.setBrokenListener { reason ->
            viewModelScope.launch {
                // The service clears `isServiceActive` when it tore the session down, and leaves
                // it set when the tunnel survived but nothing behind it answers — so this is how
                // "the session is over" is told apart from "the session is degraded". Only the
                // former drops back to Disconnected; reporting the latter as a disconnect would
                // send the user to reconnect a tunnel that is still up.
                if (!NexaVpnService.isServiceActive) {
                    stopLinkPolling()
                    isVpnRunning.value = false
                    isIrohStarted.value = false
                    addLog("Tunnel stopped working: $reason")
                } else {
                    addLog("Tunnel degraded: $reason")
                }
                errorMessage.value = reason
            }
        }
    }

    override fun onCleared() {
        NexaVpnService.setRevokedListener(null)
        NexaVpnService.setBrokenListener(null)
        stopLinkPolling()
        super.onCleared()
    }

    /**
     * Re-reads what the UI shows after it comes back to the foreground.
     *
     * Everything a session reports can change while this screen is not visible: the service
     * rebuilds the tunnel on a network switch, and it may give up and tear the session down.
     * Without a re-read the main page keeps showing whatever it last knew — an "old state"
     * that no longer matches the tunnel.
     */
    fun onForeground() {
        syncVpnServiceState()
        // A session that survived in the service also has to be reported again: this ViewModel
        // may have been created after connect() ran, in which case nothing is polling yet.
        if (isVpnRunning.value) startLinkPolling()
    }

    /**
     * Reads the current link type of every backend from the native side.
     *
     * Best-effort: a failed read leaves the last known values in place rather than emptying the
     * map, so a transient JNI hiccup does not make every icon disappear.
     *
     * Deliberately **not** gated on [isIrohStarted]. That flag lives in this ViewModel, so it is
     * false again as soon as the UI is recreated — which is exactly what a background switch or a
     * process restore does while the tunnel keeps running in the service. Gating on it emptied
     * the map for the rest of the session: the status card said "Connected" while the connection
     * type was never shown again. Whether anything is started is the native side's answer to
     * give, and it says so by returning null.
     */
    fun refreshLinkKinds() {
        if (!IrohProxy.isNativeLoaded()) {
            if (linkReadings.value.kinds.isNotEmpty()) linkReadings.value = LinkReadings()
            return
        }
        val raw = try {
            IrohProxy.nativeLinkKinds()
        } catch (e: Exception) {
            addLog("Could not read link types: ${e.message}")
            return
        }
        if (raw == null) {
            // Nothing has been started, or the endpoint group is gone: no link to report.
            if (linkReadings.value.kinds.isNotEmpty()) linkReadings.value = LinkReadings()
            return
        }
        linkReadings.value = parseLinkReadings(raw)
    }

    /**
     * Reads what each backend has carried from the native side.
     *
     * Best-effort, as [refreshLinkKinds] is: a failed read leaves the last known values in
     * place rather than zeroing every row. A null answer means nothing has been started — or
     * the endpoint group is gone — and clears the map, so no total survives the session it
     * was counted in.
     *
     * The read and the decoding stay on whichever dispatcher the caller was on — the polling
     * loop runs on [Dispatchers.IO], and a JNI call has no business on the main thread — but
     * the map itself is UI state, so it is published on [Dispatchers.Main]. Writing it from
     * the polling thread would work, because `MutableStateFlow.value` is thread-safe, and
     * would still be the wrong place to write it from.
     */
    suspend fun refreshTraffic() {
        if (!IrohProxy.isNativeLoaded()) {
            withContext(Dispatchers.Main) { traffic.value = emptyMap() }
            return
        }
        val raw = try {
            IrohProxy.nativeTraffic()
        } catch (e: Exception) {
            addLog("Could not read traffic counters: ${e.message}")
            return
        }
        val totals = if (raw == null) emptyMap() else parseNodeTraffic(raw)
        withContext(Dispatchers.Main) { traffic.value = totals }
    }

    /**
     * Starts re-reading what the tunnel reports per backend — the link type and what each one
     * has carried; no-op when a poll is already running.
     *
     * Public because `connect()` is not the only way a session comes to exist: the service
     * outlives a UI that was recreated in the background, and the ViewModel that wakes up with
     * it has to pick the reporting back up. See [onForeground].
     */
    fun startLinkPolling() {
        if (linkPollJob?.isActive == true) return
        linkPollJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                refreshLinkKinds()
                refreshTraffic()
                delay(LINK_POLL_INTERVAL_MS)
            }
        }
    }

    private fun stopLinkPolling() {
        linkPollJob?.cancel()
        linkPollJob = null
        linkReadings.value = LinkReadings()
        traffic.value = emptyMap()
    }

    companion object {
        // Timeout and retry parameters for a single connect attempt. iroh bind
        // can take up to 30s on a weak network, so the budget is generous.
        private const val MAX_CONNECT_ATTEMPTS = 3
        private const val ATTEMPT_TIMEOUT_MS = 60_000L
        private const val DISCONNECT_MUTEX_TIMEOUT_MS = 70_000L
        private val BACKOFF_MS = longArrayOf(0, 1_000, 2_000)

        // How long the UI waits for the service to report that the tunnel it
        // asked for is up. Generous, because the establish waits for Android
        // to register the VPN network and for the native side to take the
        // descriptor — and because this budget is only reached when the
        // service says nothing at all: a start that fails is reported, not
        // waited out.
        private const val TUNNEL_UP_TIMEOUT_MS = 60_000L

        // `error_vpn_taken_over` is what is shown when another proxy app (e.g.
        // Clash) owns the single tunnel slot Android allows per user.

        // Upper bound on the in-memory log buffer.
        private const val MAX_LOG_LINES = 100

        // How often the link type of each backend is re-read while connected. Short enough to
        // notice a relay -> direct upgrade without hammering the native side.
        private const val LINK_POLL_INTERVAL_MS = 5_000L
    }

    fun initSettings(context: android.content.Context) {
        if (settingsManager == null) {
            settingsManager = SettingsManager(context)
        }
    }

    fun loadSettings() {
        settingsManager?.let { manager ->
            val loadedNodes = manager.loadNodes()
            nodes.value = loadedNodes
            relayMode.value = manager.loadRelayMode()
            val loadedRelayUrl = manager.loadRelayUrl()
            relayUrl.value = loadedRelayUrl
            discoveryMode.value = manager.loadDiscoveryMode()
            // The token and the relay it was issued for are stored together,
            // so the URL it was saved with is the relay it belongs to.
            relayToken.value = RelayToken(
                token = manager.loadRelayAuthToken(),
                relayUrl = loadedRelayUrl
            )
            vpnTakeoverChoice.value = manager.loadVpnTakeoverChoice()
            autoConnectOnBoot.value = manager.autoConnectOnBoot()
            vpnConsentMissing.value = manager.vpnConsentMissing()
            deviceId.value = manager.deviceId()
            // Read after the load, because building a SettingsManager runs the
            // migration that re-seals whatever older versions left in plaintext —
            // on a device with a broken keystore that is the write that fails.
            credentialProtection.value = manager.credentialProtection()
            // An answer given in an earlier session is an answer about the
            // device, so it is read back rather than asked for again on the
            // first credential this launch writes.
            plaintextAccepted = manager.plaintextCredentialConsent()
            addLog("Settings loaded: ${loadedNodes.size} nodes, relay=${relayMode.value}")
        }
    }

    /**
     * One settings write, captured whole at the moment it was asked for.
     *
     * A snapshot rather than a re-read on the far side of the queue: this is
     * called between two keystrokes, and a write that re-read the state when
     * it finally ran would store whatever the field held by then rather than
     * what the user typed.
     */
    private data class SettingsWrite(
        val nodes: List<NodeConfig>,
        val relayMode: String,
        val relayUrl: String,
        val relayToken: String,
        val discoveryMode: String,
        /**
         * Set when the user has just answered the consent question, so the
         * re-queued write is the one thing allowed to store a credential in the
         * clear. Carried on the write rather than read from the ViewModel at
         * the moment it runs, because the answer and the write it applies to
         * have to be the same one.
         */
        val allowPlaintextOverride: Boolean = false
    )

    /**
     * Writes waiting to run.
     *
     * Conflated, so a burst of typing collapses to the last state rather than
     * a backlog of keystrokes: an older snapshot must never land after a newer
     * one and undo it. Drained by a single consumer below, which is what
     * orders the writes without every caller having to take a lock.
     */
    private val settingsWrites = Channel<SettingsWrite>(Channel.CONFLATED)

    /**
     * The write waiting on [plaintextConsentPending], kept so that accepting
     * stores the one that was asked about.
     *
     * Replaced rather than appended to when a later write also has to wait:
     * the user has by then moved on, and the newer state is the one they mean.
     */
    private var pendingCredentialWrite: SettingsWrite? = null

    /**
     * A connect that stopped to ask before spending an enrollment token.
     *
     * Held rather than resumed from the consent handler by closure: the
     * answer belongs to the device, this belongs to an attempt, and the
     * attempt is only worth continuing if it was the one that paused.
     */
    private var pendingConnect: Pair<Context, Boolean>? = null

    init {
        // The single writer. Every settings write goes through here, so the
        // keystore is only ever reached from one coroutine and the order the
        // files see is the order the writes were asked for.
        viewModelScope.launch(Dispatchers.IO) {
            for (write in settingsWrites) {
                handleSettingsWrite(write)
            }
        }
    }

    /**
     * Persists the current settings, asking first when that would put a
     * credential on disk in the clear on a device that cannot protect it.
     *
     * Enqueued rather than run inline because this is called straight from a
     * text field's `onValueChange`, and both the probe and the seal reach the
     * keystore — not something to do between two characters being typed.
     */
    private fun saveSettings() {
        settingsWrites.trySend(
            SettingsWrite(
                nodes = nodes.value,
                relayMode = relayMode.value,
                relayUrl = relayUrl.value,
                // The token is stored with the relay it belongs to, and only
                // with that one: a token that does not belong to the relay
                // being stored is not stored at all.
                relayToken = relayTokenToSend(relayToken.value, relayUrl.value),
                discoveryMode = discoveryMode.value
            )
        )
    }

    /**
     * Asks the keystore what it can do, then either writes or puts the write
     * in front of the user.
     */
    private suspend fun handleSettingsWrite(write: SettingsWrite) {
        if (write.allowPlaintextOverride) {
            commitSettings(write, allowPlaintext = true)
            return
        }
        if (needsConsentFor(write)) {
            pendingCredentialWrite = write
            plaintextConsentPending.value = true
            return
        }
        commitSettings(write, allowPlaintext = plaintextAccepted)
    }

    /**
     * Whether [write] has to wait for the user to answer.
     *
     * Only a write that actually carries a credential counts: adding an
     * endpoint, renaming one or switching relay mode stores nothing that needs
     * protecting, and asking about those would make the question meaningless
     * long before it was needed.
     */
    private suspend fun needsConsentFor(write: SettingsWrite): Boolean {
        if (plaintextAccepted) return false
        if (!carriesCredential(write.nodes, write.relayToken)) return false
        val manager = settingsManager ?: return false
        return !probeCredentialProtection(manager)
    }

    /**
     * Runs the write itself and reports what became of it.
     *
     * [allowPlaintext] is passed down rather than assumed: a device whose
     * keystore worked when it was asked and fails here is still refused, since
     * the question was answered for the other outcome. `SettingsManager` drops
     * a credential it cannot seal instead of storing it readable, so a write
     * that comes back unsealed left nothing on disk — and is asked about again
     * rather than reported as saved.
     */
    private suspend fun commitSettings(write: SettingsWrite, allowPlaintext: Boolean) {
        val manager = settingsManager ?: return
        val sealed = manager.saveNodes(write.nodes, allowPlaintext)
        val relaySealed = manager.saveRelayConfig(
            write.relayMode, write.relayUrl, write.relayToken, allowPlaintext
        )
        manager.saveDiscoveryMode(write.discoveryMode)
        credentialProtection.value = manager.credentialProtection()
        if (!(sealed && relaySealed) && !allowPlaintext) {
            pendingCredentialWrite = write
            plaintextConsentPending.value = true
        }
    }

    /**
     * Whether this device can protect a credential, read off the main thread
     * and then kept.
     *
     * Cached because the answer only changes when the keystore does, and asked
     * per write it is a keystore round trip on a text field's
     * `onValueChange`. A failure is not cached: it is exactly the answer most
     * likely to be stale, since it means the keystore was not ready.
     */
    private suspend fun probeCredentialProtection(manager: SettingsManager): Boolean {
        canProtectCached?.let { return it }
        val probed = withContext(Dispatchers.IO) { manager.canProtectCredentials() }
        if (probed) canProtectCached = true
        return probed
    }

    /**
     * Whether writing these settings would put a credential on disk.
     */
    private fun carriesCredential(nodes: List<NodeConfig>, relayToken: String): Boolean =
        nodes.any {
            !it.enrollment?.token.isNullOrBlank() || !it.twoFactor?.secret.isNullOrBlank()
        } || relayToken.isNotBlank()

    /**
     * Agrees that credentials may be stored unencrypted. The write that was
     * waiting goes through, and later ones no longer ask.
     */
    fun acceptPlaintextCredentials() {
        plaintextAccepted = true
        plaintextConsentPending.value = false
        // Recorded rather than kept in this object: an answer given once is
        // about the device, and the process that asked is not part of it.
        settingsManager?.savePlaintextCredentialConsent(true)
        // A connect that paused for this answer resumes first: it is holding
        // an enrollment token that the user has now agreed to store, and
        // leaving it paused would strand the endpoint on a dialog that is
        // already gone. A write that was waiting goes back on the queue
        // either way — it now passes the gate on its own, and dropping it
        // would lose whatever the user was asked about.
        val resume = pendingConnect
        pendingConnect = null
        val pending = pendingCredentialWrite
        pendingCredentialWrite = null
        if (pending != null) {
            // Re-queued rather than written here: the single writer owns every
            // write, and a second writer would be exactly the ordering hazard
            // that queue exists to prevent.
            settingsWrites.trySend(pending.copy(allowPlaintextOverride = true))
        }
        if (resume != null) {
            connect(resume.first, resume.second)
        } else if (pending == null) {
            saveSettings()
        }
    }

    /**
     * Declines. The waiting write is dropped rather than deferred: a
     * credential nobody agreed to store stays out of storage, and the endpoint
     * it belonged to is left as the user last saw it, still unsaved.
     */
    fun declinePlaintextCredentials() {
        pendingCredentialWrite = null
        // The connect that paused is not resumed. Its token was never spent,
        // so the endpoint still holds an invite the server has not given up —
        // which is recoverable, and not this decision to make for the user.
        pendingConnect = null
        plaintextConsentPending.value = false
        addLog("Credential not stored: this device cannot encrypt it")
    }

    /**
     * Switches n0's address lookup on or off for this device.
     *
     * Turning it off means a peer is only reachable by an address this device
     * was given — a ticket — and not by a Node ID alone, because finding the
     * address behind a Node ID is the lookup itself.
     */
    fun updateDiscoveryMode(mode: String) {
        discoveryMode.value = mode
        saveSettings()
        addLog("Discovery mode updated: $mode")
    }

    /**
     * Sets the relay configuration.
     *
     * [token] says what happens to the token, and every caller says it: a
     * token is issued by one relay and is good for that relay alone, so it
     * does not follow a change of relay. The parameter that used to default
     * to the stored token carried a bearer credential over to whatever relay
     * came next — which is how an invite could take it to a host of its
     * choosing.
     *
     * The URL is kept whatever the mode is: it names the custom relay this
     * phone is configured for, and the mode says whether that relay is in
     * use. A mode that does not use a relay URL at all leaves the token
     * alone — changing the mode is not changing the relay.
     */
    fun updateRelayConfig(mode: String, url: String, token: RelayTokenChange) {
        val before = relayToken.value
        relayMode.value = mode
        relayUrl.value = url
        val after = relayTokenAfter(url, before, token)
        relayToken.value = after
        saveSettings()
        addLog("Relay config updated: mode=$mode, url=$url")
        if (before.token.isNotBlank() && after.token.isBlank()) {
            addLog("Relay auth token cleared: a token belongs to the relay it was issued for")
            // Empty only before the application has put its context in place.
            val message = AppStrings.get(R.string.relay_token_cleared_notice)
            if (message.isNotEmpty()) notice.value = message
        }
    }

    /**
     * Sets or clears the enrollment token of one endpoint.
     *
     * A token replaces the credentials rather than sitting beside them: an
     * endpoint holding a token has not been issued any yet. Cleared as soon as
     * the issued secret lands in [twoFactor].
     */
    fun updateNodeEnrollment(nodeId: String, enrollment: NodeEnrollment?) {
        val index = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (index < 0) return
        // A pending enrollment is the one moment a device key can be offered:
        // the token in it is the human moment, and the key is what the device
        // proves itself with from then on. Prepared here rather than at the
        // connect, so the key is on file before the token is spent — a token
        // cannot be spent twice, and an endpoint whose key was lost after the
        // fact cannot enroll again from the same code.
        if (enrollment != null) {
            // Prepared off the main thread: the import that sets an enrollment
            // runs on the UI thread, and both the keystore and the JNI bridge
            // are slow enough to be felt as a dropped frame. `connect` joins
            // this before it registers the key, so the token is never spent
            // before the private half is on disk.
            val previous = deviceKeyPrep
            deviceKeyPrep = viewModelScope.launch(Dispatchers.IO) {
                previous?.join()
                prepareDeviceKeyForEnrollment(nodeId)
            }
        }
        val updated = nodes.value.toMutableList()
        updated[index] = updated[index].copy(enrollment = enrollment)
        publishNodes(updated)
        // No client id in the log: debug builds expose Log.d, and the id is half
        // of the 2FA credential pair. Whether there is one is what the line is
        // about.
        addLog(
            "Enrollment updated for " + nodeId.take(8) + ": " +
                if (enrollment?.token?.isNotBlank() == true) "pending" else "none"
        )
    }

    /**
     * Mints a device key for an endpoint that is about to enroll, and keeps it.
     *
     * A key is the credential an unattended device proves itself with: the
     * private half never leaves the phone and the server keeps only the public
     * one, so what it holds is no longer a way in as this device. It is offered
     * by the enrollment that spends the token, and signs every handshake after
     * it.
     *
     * A server that predates keys ignores the offer and issues a secret as it
     * always has, and the endpoint uses that instead. The user is asked about
     * neither.
     *
     * Runs on the IO dispatcher, started by [updateNodeEnrollment]: the seal and
     * the JNI call are both slow enough to drop a frame on the thread an invite
     * import runs on, and the connect that needs the key waits for it.
     *
     * A key that cannot be sealed is not kept: the endpoint then enrolls with
     * a TOTP secret, which the server can revoke and this app can show the
     * operator. A copy of the private half in the clear on a device that has
     * just said it cannot protect one is worse than no key at all.
     */
    private fun prepareDeviceKeyForEnrollment(nodeId: String) {
        val manager = settingsManager ?: return
        // A key belongs to the device, not to the credential it proves: the
        // server holds the public half under this device's name, so replacing
        // the key would leave the server holding one key and this phone
        // signing with another. It is kept, then, and a new one is minted
        // only for a node that has none.
        if (manager.deviceKeyFor(nodeId).isNotBlank()) {
            addLog("Kept the device key of ${nodeId.take(8)}")
            return
        }
        val privateKey = IrohProxy.nativeGenerateDeviceKey() ?: run {
            addLog("No device key for ${nodeId.take(8)}: this endpoint will enroll with a secret")
            return
        }
        if (!manager.saveDeviceKey(nodeId, privateKey)) {
            addLog("Device key not kept for ${nodeId.take(8)}: this device cannot store one")
            return
        }
        addLog("Prepared a device key for ${nodeId.take(8)}")
    }

    /**
     * Publishes [candidate] as the endpoint list and writes it.
     *
     * Publication is immediate and only the write waits: the list is this
     * process's own memory, and the thing that has to be asked about is the
     * copy that reaches disk. Holding the list back instead would leave the
     * screen disagreeing with what the user just did, and — since every write
     * is gated on its own — would not even keep the credential out of storage.
     */
    private fun publishNodes(candidate: List<NodeConfig>) {
        nodes.value = candidate
        saveSettings()
    }

    /**
     * Stores the credential the server issued for an enrollment token, if the
     * connect that just happened spent one.
     *
     * This is the only moment the secret exists on this device: the token is
     * gone, so without this the endpoint is left with an invite the server has
     * already forgotten and cannot enroll a second time.
     *
     * The one moment that cannot be taken back, which is why the consent
     * question is settled *before* the connect that spends the token rather
     * than here, after it: see [connect]. A secret that arrived and could not
     * be stored is still kept in memory and still written if the user agrees,
     * but the log below says which of those happened, because on a decline the
     * endpoint can never enroll again and only the user can fix that.
     */
    private fun collectIssuedCredential() {
        val encoded = IrohProxy.nativeTakeIssuedCredential() ?: return
        val parts = encoded.split("\n")
        if (parts.size < 3) {
            addLog("Enrollment answered with a credential this app cannot read")
            return
        }
        val clientId = parts[0]
        val secret = parts[1]
        val algorithm = parts[2]
        // A fourth line names the device the server enrolled; it answers with
        // three when it does not name devices at all. Left null rather than
        // blank, because what it records is "no name was given" — the state
        // that leaves this pair indistinguishable from the client's shared
        // secret, and the one the page offers to re-enroll out of.
        val device = parts.getOrNull(3)?.takeIf { it.isNotBlank() }
        // A fifth line carries the public half of a device key. It is what
        // tells a key credential from a secret one: a key answers with an
        // empty secret and an empty algorithm, and the half the server holds
        // is the only thing that says which key it is.
        val publicKey = parts.getOrNull(4)?.takeIf { it.isNotBlank() }
        val node = nodes.value.firstOrNull { it.enrollment?.clientId == clientId }
            ?: nodes.value.firstOrNull { it.enrollment != null }
        if (node == null) {
            // Dropping a secret is the safe outcome, but doing it silently is
            // not: the endpoint will never connect and nothing will say why.
            addLog("A credential was issued but no endpoint is enrolling")
            return
        }
        val twoFactor = NodeTwoFactor(
            enabled = true,
            clientId = clientId,
            secret = secret,
            // A key credential has no TOTP at all, so the server names no
            // algorithm; the default keeps the record well-formed, and the
            // public key is what says which kind of credential this is.
            algorithm = algorithm.ifBlank { "sha1" },
            device = device,
            publicKey = publicKey
        )
        updateNodeTwoFactor(node.nodeId, twoFactor)
        updateNodeEnrollment(node.nodeId, null)
        // A server that predates keys ignores the offer and issues a secret.
        // The key was never recorded there, so this endpoint does not answer
        // with it, and keeping it would leave a credential the server does not
        // hold — and one that a later enrollment would offer as if it had never
        // been used. Dropped here, which is the one moment that knows the offer
        // was ignored; enrolling again mints a key of its own.
        if (publicKey == null) {
            val leftover = settingsManager?.deviceKeyFor(node.nodeId).orEmpty()
            if (leftover.isNotBlank()) {
                settingsManager?.clearDeviceKey(node.nodeId)
                addLog(
                    "Dropped the device key of ${node.nodeId.take(8)}: this server issued a secret"
                )
            }
        }
        // Says what happened, not what will happen: the write behind this is
        // still queued, and on a device that cannot protect the credential it
        // will stop and ask rather than store anything. Reporting it as saved
        // here would be a claim about a write that has not run yet — and on the
        // decline path the token is gone and this secret with it.
        addLog(
            if (publicKey != null) {
                "Enrolled: the token is spent and this device's key is being stored"
            } else {
                "Enrolled: the token is spent and the issued secret is being stored"
            }
        )
    }

    /**
     * Replaces the 2FA credentials of one endpoint.
     *
     * A null [twoFactor] means this endpoint has none, which also drops the
     * saved secret rather than leaving it behind for whatever endpoint next
     * reuses the ID.
     *
     * A credential that is no longer a key takes the key with it: the private
     * half belongs to the credential that proved itself with it, and leaving it
     * on disk would keep a credential this endpoint no longer answers with —
     * and hand it to whatever endpoint reuses this ID next.
     *
     * No client id in the log: debug builds expose Log.d, and the ID is half
     * of the 2FA credential pair.
     */
    fun updateNodeTwoFactor(nodeId: String, twoFactor: NodeTwoFactor?) {
        val index = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (index == -1) return
        val previous = nodes.value[index].twoFactor
        // The key goes with the credential that proved itself with it — unless
        // this endpoint is about to enroll again, in which case the key is
        // what the enrollment will offer and dropping it now would leave the
        // device with nothing to prove itself with.
        val enrolling = nodes.value[index].enrollment != null
        if (previous?.publicKey != null && twoFactor?.publicKey == null && !enrolling) {
            settingsManager?.clearDeviceKey(nodeId)
            addLog("Dropped the device key of ${nodeId.take(8)}")
        }
        val updated = nodes.value.toMutableList().apply {
            set(index, this[index].copy(twoFactor = twoFactor))
        }
        publishNodes(updated)
        addLog(
            "2FA updated for ${nodeId.take(8)}: enabled=${twoFactor?.enabled ?: false}, " +
                "algorithm=${twoFactor?.algorithm ?: "-"}"
        )
    }

    fun addLog(message: String) {
        Log.d(TAG, message)
        viewModelScope.launch {
            // Publish a brand-new list instead of mutating the current one in
            // place: MutableStateFlow compares the new value with the old one
            // using equals(), and a List compares structurally, so an in-place
            // mutation followed by assigning a copy of it is a no-op and the
            // collectors (the Compose UI) never see a change.
            val updated = logMessages.value.toMutableList().apply { add(message) }
            if (updated.size > MAX_LOG_LINES) {
                // removeAt(0), not removeFirst(): the latter resolves to
                // java.util.List#removeFirst, which only exists from API 35
                // (this app still runs on API 26).
                updated.removeAt(0)
            }
            logMessages.value = updated
        }
    }

    fun startIroh() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (connector.ensureIrohStarted(isIrohStarted.value)) {
                    isIrohStarted.value = true
                }
            } catch (e: Exception) {
                addLog("Error starting iroh: ${e.message}")
                errorMessage.value = e.message ?: AppStrings.get(R.string.error_unknown)
            }
        }
    }

    /**
     * The connection sequence, without the screen around it.
     *
     * The same sequence the boot receiver runs, so that a tunnel brought up at
     * seven in the morning is built exactly like one the user asked for.
     */
    private val connector = ProxyConnector(object : ProxyConnector.ConnectionLog {
        override fun log(message: String) {
            addLog(message)
        }
    })

    /**
     * Null when [id] is a valid endpoint ID, otherwise a message for the user.
     *
     * The check runs through the native parser, so it can never disagree with
     * the connection path — and it is the same check the connection makes, so
     * an ID that passes here passes there.
     */
    private fun nodeIdFormatError(id: String): String? = connector.nodeIdFormatError(id)

    /**
     * Validates every configured node before a connect attempt starts.
     *
     * Without this a malformed ID only surfaced from deep inside the native
     * proxy start: the native layer returns a bare -1 for every failure, the
     * caller read that as "port in use", and the user got "Failed to start proxy
     * on ports 8080..8089" after 10 ports x 3 attempts — a message that named
     * neither the node nor the real cause.
     *
     * @return null when every ID parses, otherwise the reason for the first invalid one.
     */
    private fun validateConfiguredNodeIds(): String? =
        connector.validateConfiguredNodeIds(nodes.value)

    /**
     * The private half of each endpoint's device key, by endpoint ID.
     *
     * Read from the sealed store rather than from the native tables, because
     * the key has to be on disk before it is handed to the native side: a key
     * that is only in memory is a key the next connect will not have.
     *
     * The nodes are the ones the caller asks about, not the current list: a
     * connect carries a snapshot of the endpoints, and a key that is missing
     * from the map is a key that is not registered — which is what a
     * half-finished enrolment costs.
     */
    private fun deviceKeysByNodeId(nodes: List<NodeConfig>): Map<String, String> {
        val manager = settingsManager ?: return emptyMap()
        val keys = mutableMapOf<String, String>()
        for (node in nodes) {
            val key = manager.deviceKeyFor(node.nodeId)
            if (key.isNotBlank()) {
                keys[node.nodeId] = key
            }
        }
        return keys
    }

    /**
     * Releases every tunnel resource: nativeDestroy (stops the local proxy and
     * drops the iroh endpoint) + resets the state + stops the VPN service.
     * Key point: isIrohStarted is reset to false and nativeDestroy clears the
     * endpoint, so the next connect runs nativeStartIroh again and builds a
     * brand new tunnel instead of reusing the old endpoint.
     * Note: nativeDestroy is used here rather than nativeStopProxy - the latter
     * only stops the proxy and keeps the endpoint, which is what
     * startProxyWithRetries needs when it rebinds the port.
     */
    private suspend fun releaseAllResources(context: Context) {
        stopLinkPolling()
        try {
            IrohProxy.nativeDestroy()
        } catch (e: Exception) {
            addLog("releaseAllResources: nativeDestroy failed: ${e.message}")
        }
        isIrohStarted.value = false
        try {
            val intent = Intent(context, NexaVpnService::class.java).apply {
                action = NexaVpnService.ACTION_STOP
            }
            context.startService(intent)
        } catch (_: Exception) {}
        isVpnRunning.value = false
    }

    /**
     * Who owns the platform VPN slot, as seen from the UI.
     *
     * Runs off the main thread: both reads go through a binder. Our own session
     * is [VpnSlot.OwnSession] — the set of VPN networks does not say which one
     * is ours, and the service is the only side that can tell, so a connect
     * that starts while our tunnel is up is never treated as a takeover.
     */
    private suspend fun vpnSlot(context: Context): VpnSlot = withContext(Dispatchers.IO) {
        if (NexaVpnService.isServiceActive) return@withContext VpnSlot.OwnSession
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@withContext VpnSlot.Free
        if (UnderlyingNetworkSelector.vpnNetworks(cm).isEmpty()) {
            return@withContext VpnSlot.Free
        }
        val alwaysOn = UnderlyingNetworkSelector.alwaysOnVpnPackage(context)
            ?: return@withContext VpnSlot.ForeignVpn
        if (VpnTakeoverPolicy.isForeignAlwaysOn(alwaysOn, context.packageName)) {
            VpnSlot.AlwaysOnVpn(alwaysOn)
        } else {
            VpnSlot.ForeignVpn
        }
    }

    /**
     * What a connect may do about the VPN slot, before anything is started.
     *
     * The refusal cases are reported here as well as returned: the caller only
     * needs to act on [VpnTakeoverDecision.Proceed] and
     * [VpnTakeoverDecision.Ask], the latter being the one that needs a UI.
     */
    suspend fun takeoverCheck(context: Context): VpnTakeoverDecision {
        val decision = VpnTakeoverPolicy.decide(vpnSlot(context), vpnTakeoverChoice.value)
        when (decision) {
            is VpnTakeoverDecision.RefuseAlwaysOn -> {
                errorMessage.value = AppStrings.get(R.string.error_vpn_always_on, decision.packageName)
                addLog("connect aborted: ${decision.packageName} is the always-on VPN")
            }
            is VpnTakeoverDecision.Refuse -> {
                errorMessage.value = AppStrings.get(R.string.error_vpn_taken_over)
                addLog("connect aborted: another VPN app owns the slot")
            }
            is VpnTakeoverDecision.Ask, is VpnTakeoverDecision.Proceed -> Unit
        }
        return decision
    }

    /**
     * Remembers what the user wants done when another VPN app owns the slot.
     *
     * [VpnTakeoverChoice.Ask] is how the setting is taken back: the UI offers
     * it once a choice has been stored, so a remembered Cancel is not a dead
     * end.
     */
    fun rememberVpnTakeoverChoice(choice: VpnTakeoverChoice) {
        vpnTakeoverChoice.value = choice
        settingsManager?.saveVpnTakeoverChoice(choice)
        addLog("VPN takeover choice remembered: $choice")
    }

    /**
     * Connects.
     *
     * [allowTakeover] carries the user's answer to "another VPN app owns the
     * slot; may Nexa disconnect it?". Without it the connect is refused rather
     * than revoking the other app — see [takeoverCheck], which is what puts the
     * question to the user in the first place.
     */
    fun connect(context: Context, allowTakeover: Boolean = false) {
        if (isConnecting.value) return
        connectJob = viewModelScope.launch(Dispatchers.IO) {
            // Mutually exclusive with disconnect; abandon this connect if a
            // disconnect is already in progress.
            if (!connectionMutex.tryLock()) {
                addLog("connect: disconnect in progress, aborting")
                return@launch
            }

            // Enter the connecting state before the old tunnel is touched. The UI keys the status
            // card and the FAB on isConnecting, so flipping it first keeps them in place for the
            // whole reconnect; setting it after the teardown made the UI fall back to
            // "Disconnected", collapse those cards and jump back once connecting actually
            // started.
            isConnecting.value = true
            errorMessage.value = null
            connectionStatusText.value = null

            try {
                // If the VPN is already believed to be running (stale state after
                // activity recreation, or a repeated tap), tear the old tunnel down
                // cleanly first. Otherwise nativeStopProxy stops the TUN proxy while
                // the service skips ACTION_START ("VPN already running, skipping"),
                // leaving a dead tunnel that looks like a disconnect after connecting.
                if (isVpnRunning.value) {
                    addLog("connect: already running, stopping it before reconnecting")
                    releaseAllResources(context)
                }

                if (!IrohProxy.isNativeLoaded()) {
                    throw Exception(AppStrings.get(R.string.error_native_library))
                }
                val vpnPermissionGranted = VpnService.prepare(context) == null
                if (!vpnPermissionGranted) {
                    throw Exception(AppStrings.get(R.string.error_vpn_permission))
                }

                // Mutual-exclusion guard, the last one before the service is
                // told to establish: Android allows only one active VpnService
                // TUN per user, and establish() revokes whatever app holds the
                // slot without asking anybody. The UI asks first
                // (takeoverCheck) and passes the answer down; a connect that
                // arrives without one — a widget, a future entry point, a
                // stale UI — refuses rather than kicking the other VPN off.
                val decision = VpnTakeoverPolicy.decide(
                    vpnSlot(context),
                    if (allowTakeover) VpnTakeoverChoice.TakeOver else VpnTakeoverChoice.Cancel
                )
                if (decision != VpnTakeoverDecision.Proceed) {
                    errorMessage.value = when (decision) {
                        is VpnTakeoverDecision.RefuseAlwaysOn ->
                            AppStrings.get(R.string.error_vpn_always_on, decision.packageName)
                        else -> AppStrings.get(R.string.error_vpn_taken_over)
                    }
                    addLog("connect aborted: another VPN app owns the slot")
                    return@launch
                }

                // Pre-flight the configuration before anything is started: a malformed
                // endpoint ID has to be reported as such, immediately, instead of
                // surfacing after the endpoint group is built.
                validateConfiguredNodeIds()?.let { reason ->
                    addLog("connect aborted: $reason")
                    errorMessage.value = reason
                    return@launch
                }

                // Settle the credential question before anything is spent.
                //
                // An enrollment token is consumed by the pre-connect below and
                // cannot be enrolled twice: if the credential it buys then
                // cannot be stored, the endpoint is left with neither a token
                // nor a secret. So on a device that cannot protect a
                // credential, this stops *before* the token is spent and asks
                // instead — the one question here that is worth abandoning an
                // attempt over.
                val enrolling = nodes.value.any {
                    !it.enrollment?.token.isNullOrBlank() &&
                        it.twoFactor?.takeIf { otp -> otp.enabled }?.secret.isNullOrBlank()
                }
                if (enrolling) {
                    val manager = settingsManager
                    if (manager != null &&
                        !probeCredentialProtection(manager) &&
                        !plaintextAccepted
                    ) {
                        addLog("connect paused: waiting for permission to store the credential")
                        pendingConnect = context to allowTakeover
                        plaintextConsentPending.value = true
                        return@launch
                    }
                }

                var lastError: Exception? = null

                // Retry loop: the proxy preparation of an attempt is bounded
                // by ATTEMPT_TIMEOUT_MS and the wait for the tunnel by
                // TUNNEL_UP_TIMEOUT_MS; on timeout or failure all resources
                // are released before the next attempt.
                for (attempt in 1..MAX_CONNECT_ATTEMPTS) {
                    try {
                        withTimeout(ATTEMPT_TIMEOUT_MS) {
                            // The sequence itself lives in [ProxyConnector], so
                            // that a tunnel brought up at boot is built exactly
                            // like one the user asked for.
                            val outcome = connector.prepare(
                                context,
                                ProxyConnector.Plan(
                                    nodes = nodes.value,
                                    relayMode = relayMode.value,
                                    relayUrl = relayUrl.value,
                                    // The token goes to the relay it was issued
                                    // for, and to no other: this is the last
                                    // place where it can be held back.
                                    relayAuthToken = relayTokenToSend(
                                        relayToken.value,
                                        relayUrl.value
                                    ),
                                    // Whether this device may ask n0 where a peer
                                    // is. The plan carries it rather than the
                                    // connector reading the view model's state, so
                                    // the sequence cannot see a value that changed
                                    // underneath it.
                                    discoveryMode = discoveryMode.value,
                                    deviceId = deviceId.value,
                                    // Read after the wait below, not here: the
                                    // key is sealed by the import that armed the
                                    // enrollment, and a map built before that
                                    // write lands is a map without the key in
                                    // it — which is the same as having no key.
                                    // And for the endpoints this plan carries,
                                    // not for whatever the list says now.
                                    deviceKeys = { nodeList -> deviceKeysByNodeId(nodeList) },
                                    irohStarted = isIrohStarted.value,
                                    // The import that armed the enrollment sealed
                                    // the key off the main thread; joining here is
                                    // what makes the read below wait for that write
                                    // to land, rather than hand the native side a key
                                    // that is not on disk yet.
                                    awaitDeviceKeys = { deviceKeyPrep?.join() }
                                )
                            ) {
                                // The pre-connect is what spent the token: read the
                                // secret it bought now, because a second connect has
                                // nothing left to spend.
                                collectIssuedCredential()
                            }
                            if (outcome.startedIroh) {
                                isIrohStarted.value = true
                            }
                            delay(1000)
                        }

                        // Success: start the VPN foreground service.
                        val allDomains = nodes.value.flatMap { it.domains }
                        val intent = Intent(context, NexaVpnService::class.java).apply {
                            action = NexaVpnService.ACTION_START
                            putStringArrayListExtra(NexaVpnService.EXTRA_DOMAINS, ArrayList(allDomains))
                            // Carried through to the service: it is the only
                            // thing that lets establish() past its own guard.
                            putExtra(NexaVpnService.EXTRA_ALLOW_TAKEOVER, allowTakeover)
                        }
                        // The tunnel is up only when the service says so:
                        // startForegroundService() delivers the request and
                        // returns, so nothing is known about the tunnel until
                        // the establish has finished. The listener is
                        // registered before the request is sent, because the
                        // service may finish the establish before this
                        // coroutine gets to wait for the answer.
                        val outcome = CompletableDeferred<Boolean>()
                        val listener: (Boolean) -> Unit = { up -> outcome.complete(up) }
                        NexaVpnService.setStartOutcomeListener(listener)
                        try {
                            context.startForegroundService(intent)
                            val reportedUp = awaitTunnelUp(
                                outcome,
                                TUNNEL_UP_TIMEOUT_MS
                            ) { Log.w(TAG, it) }
                            if (!tunnelIsUp(reportedUp, NexaVpnService.isServiceActive)) {
                                // The attempt is over and there is no tunnel:
                                // the same thing a failed proxy preparation
                                // is, and retried the same way.
                                throw Exception(tunnelUpFailedMessage())
                            }
                        } finally {
                            NexaVpnService.clearStartOutcomeListener(listener)
                        }

                        isVpnRunning.value = true
                        addLog("Connected successfully (attempt $attempt/$MAX_CONNECT_ATTEMPTS)")
                        // The tunnel is up: start reporting how each backend is reached, and
                        // keep doing so — iroh may promote a relayed connection later.
                        startLinkPolling()
                        return@launch
                    } catch (e: TimeoutCancellationException) {
                        // withTimeout expired: retryable.
                        addLog("Attempt $attempt/$MAX_CONNECT_ATTEMPTS timed out after ${ATTEMPT_TIMEOUT_MS}ms")
                        lastError = e
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        // Deliberate cancellation from disconnect: do not
                        // retry, propagate to exit the loop.
                        throw e
                    } catch (e: Exception) {
                        addLog("Attempt $attempt/$MAX_CONNECT_ATTEMPTS failed: ${e.message}")
                        lastError = e
                    }

                    if (attempt < MAX_CONNECT_ATTEMPTS) {
                        addLog("Releasing all resources before retry...")
                        releaseAllResources(context)
                        delay(BACKOFF_MS[attempt])
                    }
                }
                errorMessage.value = lastError?.message
                    ?: AppStrings.get(R.string.error_all_attempts_failed)
                addLog("All $MAX_CONNECT_ATTEMPTS attempts failed")
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Deliberate cancellation from disconnect: propagate quietly;
                // the finally block still releases the mutex.
                throw e
            } catch (e: Exception) {
                // Pre-attempt failures (native library not loaded, VPN
                // permission not granted, ...). Without this catch the
                // exception escapes the coroutine and crashes the app.
                addLog("Connect failed: ${e.message}")
                errorMessage.value = e.message ?: AppStrings.get(R.string.error_connection_failed)
            } finally {
                isConnecting.value = false
                connectionStatusText.value = null
                connectionMutex.unlock()
            }
        }
    }

    /**
     * What to tell the user when a start did not bring the tunnel up.
     *
     * The reason the service refused with, when there is one: another VPN
     * app owning the slot is something the user can act on, and a generic
     * "connection failed" would hide it.
     */
    private fun tunnelUpFailedMessage(): String =
        NexaVpnService.lastRevokeReason
            ?: AppStrings.get(R.string.error_connection_failed)

    fun disconnect(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            // Cancel the in-flight connect: JNI cannot be interrupted, but the
            // next suspension point throws CancellationException and it exits.
            connectJob?.cancel()

            // Wait for connect to release the mutex (its finally block unlocks
            // it). The budget is slightly larger than a single connect timeout.
            val locked = withTimeoutOrNull(DISCONNECT_MUTEX_TIMEOUT_MS) {
                connectionMutex.withLock {
                    releaseAllResources(context)
                }
            }
            if (locked == null) {
                // Edge case: connect is still stuck in JNI past the budget.
                // There is no deadlock on the Rust side anymore, so force the
                // release.
                addLog("disconnect: could not acquire mutex within ${DISCONNECT_MUTEX_TIMEOUT_MS}ms, forcing release")
                releaseAllResources(context)
            }
            addLog("Disconnected")
        }
    }

    fun checkVpnPermission(context: Context): Boolean {
        val granted = VpnService.prepare(context) == null
        vpnPermissionGranted.value = granted
        // The manager is built on demand rather than skipped: the flag below is
        // what the settings page reads, and a flag that is only written when
        // the manager happens to be there is a flag that is sometimes missing.
        val manager = settingsManager ?: SettingsManager(context).also { settingsManager = it }
        if (granted) {
            // The permission is back, so the warning the boot path left behind
            // is no longer true. Nothing else clears it: the boot path only
            // runs at the next restart, and the screen tells the user to open
            // the app to grant it — so without this the warning outlives the
            // thing it is about, and the app tells the user to fix something
            // that is already fixed.
            //
            // The stored flag and the one on screen are written together or
            // not at all: a screen that says there is no warning while the
            // stored flag says there is one is a screen that contradicts
            // itself the next time the settings are read back.
            manager.saveVpnConsentMissing(false)
            vpnConsentMissing.value = false
        } else {
            // The consent is missing and the app knows it: the flag is what
            // tells the user the tunnel will not come back at the next
            // restart. The boot path writes it too, but the consent can be
            // withdrawn long after the last boot — and a warning that only
            // arrives with the next boot is a warning the user had no chance
            // to act on.
            manager.saveVpnConsentMissing(true)
            vpnConsentMissing.value = true
        }
        return granted
    }

    fun checkNotificationPermission(context: Context): Boolean {
        val granted = PermissionManager.checkNotificationPermission(context)
        notificationPermissionGranted.value = granted
        return granted
    }

    fun refreshPermissions(context: Context) {
        checkVpnPermission(context)
        checkNotificationPermission(context)
    }

    /**
     * Adds a node (identified by its endpoint ID). Returns null on success or
     * a human-readable reason when the node is rejected (empty, duplicate, or not a
     * parseable endpoint ID).
     *
     * The new list is always published as a brand-new object: MutableStateFlow
     * skips the emission when the new value equals the previous one, and an
     * in-place mutation would make the structural list comparison succeed, so
     * the UI would never recompose.
     */
    fun addNode(nodeId: String): String? {
        val id = nodeId.trim()
        if (id.isEmpty()) return AppStrings.get(R.string.error_endpoint_id_empty)
        if (nodes.value.any { it.nodeId == id }) {
            return AppStrings.get(R.string.error_endpoint_id_exists, id)
        }
        nodeIdFormatError(id)?.let { return it }

        nodes.value = nodes.value + NodeConfig(id)
        saveSettings()
        addLog("Added node: $id")
        return null
    }

    fun removeNode(nodeId: String) {
        if (nodes.value.none { it.nodeId == nodeId }) return

        nodes.value = nodes.value.filterNot { it.nodeId == nodeId }
        saveSettings()
        if (isIrohStarted.value) {
            IrohProxy.nativeRemoveNode(nodeId)
        }
        addLog("Removed node: $nodeId")
    }

    /**
     * Renames a node, i.e. edits its endpoint ID. The domain list attached to
     * the node is preserved.
     *
     * Returns null on success, or a human-readable reason when the rename is
     * rejected (empty, colliding with another node, or not a parseable endpoint ID).
     *
     * When iroh is already up, the native side is re-pointed immediately: the
     * old node is dropped and every domain of that node is mapped to the new
     * endpoint ID again, so the change takes effect without reconnecting. The
     * proxied domain set is unchanged, so the running TUN proxy still routes
     * the same traffic.
     */
    fun renameNode(oldNodeId: String, newNodeId: String): String? {
        val newId = newNodeId.trim()
        if (newId.isEmpty()) return AppStrings.get(R.string.error_endpoint_id_empty)
        if (newId == oldNodeId) return null

        val index = nodes.value.indexOfFirst { it.nodeId == oldNodeId }
        if (index == -1) return AppStrings.get(R.string.error_endpoint_not_found, oldNodeId)
        if (nodes.value.any { it.nodeId == newId }) {
            return AppStrings.get(R.string.error_endpoint_id_exists, newId)
        }
        nodeIdFormatError(newId)?.let { return it }

        val node = nodes.value[index]
        nodes.value = nodes.value.toMutableList().apply { set(index, node.copy(nodeId = newId)) }
        saveSettings()

        if (isIrohStarted.value) {
            IrohProxy.nativeRemoveNode(oldNodeId)
            for (domain in node.domains) {
                if (IrohProxy.nativeAddDomainMapping(domain, newId) != 0) {
                    addLog("Failed to re-map domain '$domain' to new node: $newId")
                }
            }
        }
        addLog("Renamed node: $oldNodeId -> $newId")
        return null
    }

    fun addDomainToNode(nodeId: String, domain: String) {
        if (domain.isNotEmpty()) {
            val nodeIndex = nodes.value.indexOfFirst { it.nodeId == nodeId }
            if (nodeIndex != -1) {
                val node = nodes.value[nodeIndex]
                if (!node.domains.contains(domain)) {
                    val newDomains = node.domains.toMutableList().apply { add(domain) }
                    val newNode = node.copy(domains = newDomains)
                    val newNodes = nodes.value.toMutableList().apply { set(nodeIndex, newNode) }
                    nodes.value = newNodes
                    saveSettings()
                }
            }
        }
    }

    fun removeDomainFromNode(nodeId: String, domain: String) {
        val nodeIndex = nodes.value.indexOfFirst { it.nodeId == nodeId }
        if (nodeIndex != -1) {
            val node = nodes.value[nodeIndex]
            if (node.domains.contains(domain)) {
                val newDomains = node.domains.toMutableList().apply { remove(domain) }
                val newNode = node.copy(domains = newDomains)
                val newNodes = nodes.value.toMutableList().apply { set(nodeIndex, newNode) }
                nodes.value = newNodes
                saveSettings()
            }
        }
    }

    fun clearLogs() {
        logMessages.value = mutableListOf()
    }

    /**
     * Syncs the ViewModel's isVpnRunning with the actual NexaVpnService state.
     *
     * Scenario: after the Activity/ViewModel is recreated (partial process
     * restore, developer options, ...), isVpnRunning defaults to false while
     * the VPN service may still be running in the foreground. Calling this
     * aligns the UI state with the real service state, so the UI cannot show
     * "Disconnected" while the tunnel is actually usable.
     */
    fun syncVpnServiceState() {
        if (!isVpnRunning.value && !isConnecting.value && NexaVpnService.isServiceActive) {
            isVpnRunning.value = true
            // The native endpoint is up too — the service only becomes active after
            // nativeStartIroh and nativeStartProxy succeeded. Recording it matters when this
            // ViewModel was created *after* the connect that started the session (a background
            // switch that recreated the activity): `removeNode`/`renameNode` re-point the
            // native side only when it is set.
            isIrohStarted.value = true
            addLog("Synced UI state: service is active")
            // ...and the connection types have to be reported again, since the poll that used
            // to run belongs to the ViewModel that is gone.
            startLinkPolling()
        }
        // The VPN slot was lost to another VPN app while this ViewModel had no
        // revoked-listener registered (app was backgrounded or the ViewModel
        // was recreated): align the UI now instead of showing a stale
        // "Connected".
        //
        // Not conditioned on a session this ViewModel knew about: a boot
        // connection refused because another app owns the slot never had one,
        // and the reason for it is exactly what the user is missing — the boot
        // path has no screen to report to, so this is where it is reported.
        if (!isConnecting.value && NexaVpnService.wasRevoked) {
            // Same reason as the revoked listener above: the session is over, so its counters
            // and the poll behind them go with it.
            stopLinkPolling()
            isVpnRunning.value = false
            errorMessage.value = NexaVpnService.lastRevokeReason
                ?: AppStrings.get(R.string.error_vpn_taken_over)
            addLog("Synced UI state: tunnel was revoked by another app")
        }
    }
}
