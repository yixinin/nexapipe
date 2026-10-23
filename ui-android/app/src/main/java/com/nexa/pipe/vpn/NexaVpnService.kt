package com.nexa.pipe.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.MainActivity
import com.nexa.pipe.R
import com.nexa.pipe.formatByteRate
import com.nexa.pipe.locale.AppLocale
import com.nexa.pipe.parseNodeTraffic
import com.nexa.pipe.ui.BootConnector
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/**
 * VPN service: creates the TUN interface and hands the fd over to the smoltcp
 * TUN proxy on the Rust side.
 *
 * The original ~1600-line hand-written TCP/IP stack has been removed and
 * replaced by the Rust netstack-smoltcp userspace stack. The Kotlin side is
 * only responsible for establishing the VPN, network callbacks, the foreground
 * service, and passing the TUN fd to Rust.
 *
 * Data flow: APP -> TUN fd -> Rust(smoltcp) -> handle_local_connection ->
 * iroh -> backend. DNS hijacking and TCP MSS / retransmit / FIN-ACK handling
 * are all done on the Rust side.
 */
class NexaVpnService : VpnService() {
    // The notification this service shows is written from its own context, so
    // it needs the selected language as much as the Activity does; switching
    // language and reconnecting is enough to rebuild it.
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocale.apply(newBase))
    }

    private val TAG = "NexaVpnService"
    // The TUN descriptor is not held in a field: it belongs to the establish
    // that opened it, from establish() until the native side takes it, and
    // that is also where it is closed when it never gets that far. See
    // establishVpnInternal.

    // @Volatile: written from the main thread (onStartCommand/onRevoke) and
    // read from IO coroutines (reconnect logic).
    @Volatile private var isRunning = false
    // Set for good by stopVPN(), cleared by startVPN(): the service is on its
    // way out, so an establish that is already running must not publish
    // anything. Cancelling the scope cannot stop it — the native call chain
    // blocks in Rust and has no suspension point a cancellation could hit — so
    // the cooperation has to be explicit.
    @Volatile private var isStopping = false
    private var allowedDomains = mutableSetOf<String>()

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var underlyingNetwork: Network? = null
    // The VPN networks Android created for our own TUN. Android does not label
    // a VPN network with the app that owns it, so ours is identified by which
    // network appeared when we called establish() — see trackOwnVpnNetwork.
    // Replaced wholesale rather than mutated in place: establish runs on the IO
    // dispatcher while stopVPN() and onRevoke() are entered on the main thread.
    // (stopVPN() only clears flags there — the native stop it used to run
    // inline is on teardownScope now.)
    @Volatile private var ownVpnNetworks: Set<Network> = emptySet()
    // Whether the last establish could not tell which VPN network was ours.
    // Only then does vpnSlot() fall back to "a single unknown VPN while our own
    // session is up is our own tunnel"; the rest of the time identity decides.
    @Volatile private var ownVpnUnidentified = false
    // Whether the user agreed, for this connect, that Nexa may take the slot
    // from another VPN app. Never set on the rebuild path: a network switch
    // must not revoke a VPN that took over while ours was being rebuilt.
    @Volatile private var allowTakeover = false
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // A second scope, deliberately not `serviceScope`: onDestroy() cancels that
    // one the moment stopVPN() returns, so the teardown stopVPN() schedules
    // there would be cancelled before it ever ran and the duplicated fd would
    // stay open. This one is never cancelled — the only thing it runs is a
    // native stop, which has to finish whether or not the service is still
    // alive to hear about it.
    private val teardownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // The boot connection, while it runs. Kept so it can be cancelled with
    // the service rather than left behind holding a native call.
    private var bootConnectJob: Job? = null
    @Volatile private var isUserStarted = false

    // Reconnect on network switch: keeps the reconnect job. The mutex serializes the rebuilds
    // themselves — one cannot be interrupted inside a native call, so two must never run at once.
    private var reconnectJob: Job? = null
    // The poll that keeps the notification's throughput current. It lives here and not in the
    // ViewModel on purpose: the ViewModel's polling only runs while its UI is in the
    // foreground, and a notification that freezes the moment the user leaves the app is the
    // one thing it must not do.
    private var trafficJob: Job? = null
    // The counters are cumulative, so a rate takes two samples: this is the previous one.
    private var lastTrafficSample: TrafficSample? = null
    // The last text handed to NotificationManager. Android throttles rapid updates, so a
    // tick that worked out the same text posts nothing rather than queueing behind one.
    //
    // Written from two threads and from two different ideas of what the notification is
    // showing: the poller sets it to whatever it just posted, and anything that re-posts
    // the plain notification — `startForeground` on a rebuild — has to clear it, because
    // the content on screen no longer matches what it remembers. Both happen under this
    // lock together with the post itself.
    private val notificationLock = Any()
    @Volatile private var lastNotificationText: String? = null
    /** One read of the cumulative counters, with the moment it was taken. */
    private data class TrafficSample(val sent: Long, val received: Long, val atMs: Long)
    // Whether the TUN proxy has started successfully. A network switch only
    // triggers a reconnect when this is true, so the initial VPN setup cannot
    // trigger one by accident.
    @Volatile private var tunProxyStarted = false
    private val reconnectMutex = Mutex()

    // TUN interface MTU. Must match TUN_MTU in crates/nexapipe-client/src/tun_proxy.rs and
    // ui-desktop/src-tauri/src/proxy/tun_proxy.rs. 1400 keeps one inner IP packet inside a
    // single QUIC datagram (~1435 usable bytes after the short header + AEAD tag); at 1500
    // every inner segment was split across two datagrams, roughly doubling the packet count
    // and AEAD cost.
    private val tunMtu = 1400

    // The addresses of the TUN are not written down here: the block the tunnel
    // claims is chosen per session (see VirtualBlockSurvey), and the addresses
    // inside it come from the native side — the same block the per-domain
    // addresses are handed out of. The legacy proxy address (`.3` in that
    // block) is not needed here: DNS responses are built by Rust, and TCP
    // traffic is split by Rust according to local_addr.ip().
    //
    // Note: do not hijack the system captive-portal check domains
    // (connectivitycheck.gstatic.com and friends) to a private IP. Android's
    // NetworkMonitor treats "the check domain resolves to a private IP" as "no
    // internet", which puts an exclamation mark on the Wi-Fi icon in the status
    // bar. Let them use real DNS over the physical network instead.

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        registerNetworkCallback()
        refreshUnderlyingNetwork("service created")
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        unregisterNetworkCallback()
        // Cancel the scope last: it is what would otherwise keep a slow
        // establish alive past the service. nativeStartTunProxy blocks for
        // tens of seconds, so this alone does not stop one that is already
        // inside it — that is what the isStopping checks are for — but it does
        // stop everything that was still waiting to run (a debounced
        // reconnect, a warm-up) from running against a dead service.
        serviceScope.cancel()
    }

    fun startVPN(domains: Set<String>, allowTakeover: Boolean = false) {
        this.allowedDomains = domains.toMutableSet()
        this.allowTakeover = allowTakeover
        isUserStarted = true
        // A new session begins: clear the stale "revoked" marker from a
        // previous session (consumed by VpnViewModel.syncVpnServiceState()),
        // and the reason that came with it.
        wasRevoked = false
        lastRevokeReason = null

        // The tunnel of this session is not up yet, whatever an earlier
        // session left behind: the flag says a tunnel is there, and it has
        // to mean *this* one — a UI that reads it while this session is
        // still being built would call a tunnel that is not there a
        // connected one.
        isServiceActive = false

        // A new session clears the teardown marker: the same service instance
        // is reused when the user stops and starts again without the process
        // being recreated, and an establish must be allowed to run then.
        isStopping = false

        val prepareIntent = prepare(this)
        if (prepareIntent != null) {
            Log.d(TAG, "VPN permission not granted")
            // The service goes away with it: a foreground service with no
            // tunnel behind it is a notification that says the tunnel is up
            // over a tunnel that is not there, and there is nothing else this
            // start was going to do. The boot path reaches this when the
            // consent was withdrawn between its own check and this one.
            //
            // The native side goes with it: this start was handed a proxy that
            // is already up — the boot path brings the native side up before
            // it asks the service to establish, and so does the screen — and
            // that side is process-global, so a service that goes away with it
            // still running leaves a live connection to the relay behind
            // nothing that the user can see or stop.
            releaseNativeResources()
            // The start is over and there is no tunnel: whoever asked for
            // it is waiting for exactly this answer.
            notifyStartOutcome(false)
            shutdownService()
            return
        }

        // ACTION_START means VpnViewModel wants the VPN re-established (with a
        // new TUN fd). nativeStopProxy (called by startProxyWithRetries during
        // connect) already stopped the Rust TUN proxy, but isRunning may still
        // be true because the service was never stopped through stopVPN.
        // isRunning must be reset, otherwise establishVPN bails out with
        // "VPN already running" and the TUN proxy is never rebuilt -> the data
        // plane is dead (it looks like the connection drops right after
        // connecting).
        synchronized(this@NexaVpnService) {
            if (isRunning) {
                Log.d(TAG, "startVPN: resetting isRunning (TUN proxy was stopped by nativeStopProxy)")
                isRunning = false
                tunProxyStarted = false
            }
        }
        // Cancel any pending reconnect so it cannot race with the new setup.
        reconnectJob?.cancel()
        reconnectJob = null

        refreshUnderlyingNetwork("VPN start requested")
        establishVPN()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            // A sticky restart: the system brought the service back without an
            // intent, and a service started with startForegroundService() has
            // five seconds to call startForeground() or the system takes the
            // app down with it.
            //
            // What the machine asks for when it wants the tunnel back is the
            // boot path, and that path ends the service when it cannot bring
            // a tunnel up — so nothing is left running over a tunnel that is
            // not there.
            startForegroundConnecting()
            bootConnectJob = serviceScope.launch {
                bootConnect()
            }
            return START_STICKY
        }

        when (intent.action) {
            ACTION_START -> {
                val domains = intent.getStringArrayListExtra(EXTRA_DOMAINS) ?: emptyList()
                // Whether the UI asked and was told to take the slot from
                // another VPN app. Absent means no: a start that carries no
                // such answer must not revoke anything.
                val takeover = intent.getBooleanExtra(EXTRA_ALLOW_TAKEOVER, false)
                // The same obligation the boot path meets, and for the same
                // reason: a service started with startForegroundService() has
                // five seconds to call startForeground(), and the system takes
                // the app down when it does not. Everything startVPN() does
                // before its own startForeground() — the consent check, the
                // establish, and the wait for Android to register the VPN
                // network — can take longer than that, so the obligation is
                // met here, before any of it.
                startForegroundConnecting()
                startVPN(domains.toSet(), takeover)
            }
            ACTION_STOP -> {
                stopVPN()
            }
            ACTION_BOOT_CONNECT -> {
                // The machine asked for the tunnel to come back.
                //
                // Android gives a service started with
                // startForegroundService() five seconds to call
                // startForeground(), and the wait for a network below can
                // take longer than that, so the obligation is met here —
                // with the text that says what is happening rather than
                // the one that says the tunnel is up, because it is not
                // yet.
                startForegroundConnecting()
                bootConnectJob = serviceScope.launch {
                    bootConnect()
                }
            }
        }
        return START_STICKY
    }

    /**
     * Meets the obligation a service started with `startForegroundService()`
     * has: it has five seconds to call `startForeground()`, and the system
     * takes the app down when it does not.
     *
     * Every path that starts the service meets it here, before anything that
     * can take longer than five seconds: the boot path waits for a network,
     * and the start path waits for the consent check, for `establish()` and
     * for Android to register the VPN network.
     *
     * The text says what is true: the tunnel is not up yet. A refusal is not
     * swallowed — the service never enters the foreground state that way, and
     * the log is what says why.
     */
    private fun startForegroundConnecting() {
        runCatching {
            createNotificationChannel()
            startForeground(
                NOTIFICATION_ID,
                createNotification(getString(R.string.notification_text_connecting))
            )
        }.onFailure { error ->
            Log.w(TAG, "the foreground was refused: ${error.message}")
        }
    }

    /**
     * Brings the tunnel back after a restart.
     *
     * The work is the same as a connection the user asked for — see
     * [com.nexa.pipe.ui.BootConnector] — and it runs here rather than in the
     * broadcast receiver because this service outlives the broadcast and can
     * wait for a network.
     */
    private suspend fun bootConnect() {
        if (!awaitNetwork(BOOT_NETWORK_TIMEOUT_MS)) {
            Log.w(TAG, "boot: no network came up in time, so the tunnel stays down")
            shutdownService()
            return
        }

        when (val outcome = BootConnector.connectIfWanted(this@NexaVpnService) { Log.i(TAG, it) }) {
            is BootConnector.BootOutcome.Established -> {
                // The tunnel itself is the service's to establish, and it does
                // that after this returns.
            }
            is BootConnector.BootOutcome.Failed -> {
                Log.w(TAG, "boot connect failed: ${outcome.cause.message}")
                // The attempt may have brought the native side up before it
                // failed, and that side is process-global: the iroh endpoint
                // and the endpoint group with their warm backend connections
                // outlive the service that started them, so a failed attempt
                // would leave a live QUIC connection to the relay behind
                // nothing that the user can see or stop. They are taken down
                // here as well; the user's path does the same through
                // releaseAllResources().
                releaseNativeResources()
                shutdownService()
            }
            is BootConnector.BootOutcome.Skipped -> {
                // Nothing was started, so nothing is left behind to take
                // down: the native side is process-global, and what is running
                // in it may belong to a session that is not this one's to end.
                shutdownService()
            }
        }
    }

    /**
     * Takes down the native side of a start that is not going to happen.
     *
     * The iroh endpoint and the endpoint group are process-global and outlive
     * the service: the service owns the TUN and the notification, and the
     * native side owns the connection to the relay and the warm backend
     * connections behind it. A start that is refused after the native side was
     * brought up — a boot attempt that failed, a tunnel that could not be
     * established because the consent was withdrawn — leaves all of it behind,
     * with no service and no notification and nothing the user can stop.
     *
     * The teardown is process-global, so it takes down whatever else is
     * running in the process as well. It is therefore only for a start that
     * brought the native side up: an attempt that started nothing must not
     * call it, or it ends a session that belongs to somebody else.
     *
     * It runs on the teardown scope and not on the caller's thread: the
     * native stop closes the endpoint and the warm connections behind it, and
     * that blocks for as long as they take — long enough to be the system's
     * "the app is not responding" on the main thread.
     */
    private fun releaseNativeResources() {
        teardownScope.launch {
            // The library may not be there at all, and the call would raise an
            // UnsatisfiedLinkError — an Error, not an Exception — which would
            // escape the catch below and take the process with it.
            if (!IrohProxy.isNativeLoaded()) return@launch
            try {
                IrohProxy.nativeDestroy()
            } catch (e: Exception) {
                Log.e(TAG, "nativeDestroy failed: ${e.message}")
            }
        }
    }

    /**
     * Waits for a network to come up.
     *
     * A boot broadcast arrives while the phone is still finding its way onto
     * a network, and a tunnel built on no network reaches no backend. Polling
     * is enough here: what is being waited for is a fact about the radio, and
     * the radio does not offer a better signal than "there is a network now".
     *
     * Bounded, because waiting forever is the same as not trying: the phone
     * may never get a network, and a foreground service waiting for one it
     * will never have is a notification nobody asked for.
     */
    private suspend fun awaitNetwork(timeoutMs: Long): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            if (connectivityManager?.activeNetwork != null) {
                return true
            }
            delay(BOOT_NETWORK_POLL_MS)
        }
        return false
    }

    /**
     * The system revoked our VPN: another VPN app (e.g. Clash) was established
     * and took over the single VPN slot Android allows per user.
     *
     * Without this override the service used to keep running with stale state
     * (isRunning / tunProxyStarted / isServiceActive all true), so the next
     * network switch triggered a reconnect that called establish() again and
     * stole the VPN slot back from the other app — a "VPN war" where both apps
     * kept killing each other. Instead: reset every session flag synchronously
     * (so an in-flight reconnect aborts), tear down off the main thread, stop
     * the service, and notify the UI.
     */
    override fun onRevoke() {
        Log.w(TAG, "onRevoke: another VPN app took over the VPN slot, tearing down")
        // Synchronous flag reset: reconnectTunnel()/rebuildTunnel() check these
        // before re-establishing, so this closes the steal-back race immediately.
        isUserStarted = false
        isRunning = false
        tunProxyStarted = false
        isServiceActive = false
        // The session is over, and no tunnel is coming up for it: whoever is
        // waiting for one is told now rather than at the end of its wait.
        notifyStartOutcome(false)
        ownVpnNetworks = emptySet()
        ownVpnUnidentified = false
        wasRevoked = true
        reconnectJob?.cancel()
        reconnectJob = null

        // stopVPN() defers the native stop itself, so this is not what keeps
        // the main thread free any more — but notifyVpnRevoked() and
        // stopSelf() must still follow it, and they cannot run on the main
        // thread that onRevoke() was called on either.
        serviceScope.launch {
            stopVPN()
            // Notified before stopping: stopSelf() runs onDestroy(), which
            // cancels this scope, and the UI would otherwise wait for a signal
            // that the shutdown it triggered cut off.
            notifyVpnRevoked(getString(R.string.error_vpn_taken_over))
            stopSelf()
        }
    }

    /**
     * Tear the session down.
     *
     * Every flag is cleared synchronously, because an establish or a reconnect
     * that is already running reads them and has to see this before it goes
     * any further — that is why this is safe to call from the main thread.
     * The native stop is not: it joins the smoltcp tasks, up to ~500 ms each,
     * and is handed to [teardownScope] instead.
     */
    fun stopVPN() {
        isRunning = false
        isUserStarted = false
        tunProxyStarted = false
        isServiceActive = false
        ownVpnNetworks = emptySet()
        ownVpnUnidentified = false
        // First, so an establish that is already running sees it however far
        // it gets.
        isStopping = true
        // Cancel an in-flight reconnect so it cannot race with this manual
        // disconnect.
        reconnectJob?.cancel()
        reconnectJob = null
        // ...and the notification's rate, whose job belongs to this service and
        // would otherwise keep reading counters of a proxy that is going away.
        stopTrafficPolling()

        teardownScope.launch { stopTunProxyAndLeaveForeground() }
    }

    /**
     * The half of the teardown that blocks: stopping the TUN proxy aborts the
     * smoltcp tasks and closes the duplicated fd, which brings the VPN down
     * with it.
     *
     * Running twice is harmless and expected — the Rust side takes the proxy
     * out of the state before stopping it, so the second call finds nothing
     * there — because every caller that stops the service calls [stopVPN] and
     * then reaches onDestroy(), which calls it again.
     */
    private fun stopTunProxyAndLeaveForeground() {
        // Stop the TUN proxy first (abort the smoltcp task + close the
        // duplicated fd -> the VPN is torn down automatically).
        // Must run before touching vpnInterface, because fd ownership has been
        // transferred to Rust.
        try {
            IrohProxy.nativeStopTunProxy()
        } catch (e: Exception) {
            Log.e(TAG, "nativeStopTunProxy failed: ${e.message}")
        }

        // Nothing to close here: by the time the TUN proxy runs, the
        // descriptor belongs to Rust — nativeStartTunProxy took it at the JNI
        // boundary and nativeStopTunProxy above closed it. A descriptor that
        // was never handed over was closed by the establish that still held
        // it, which is the path this function used to leave open.
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun establishVPN() {
        synchronized(this@NexaVpnService) {
            if (isRunning) {
                Log.d(TAG, "VPN already running, skipping")
                return
            }
            isRunning = true
        }

        serviceScope.launch {
            if (!establishVpnInternal(allowTakeover)) {
                Log.d(TAG, "VPN establishment failed")
                isRunning = false
                // The start is over and there is no tunnel: whoever asked for
                // it is waiting for exactly this answer, and the attempt has
                // to be retried rather than announced as a success.
                notifyStartOutcome(false)
                // Nothing left to shut down when the service is already going
                // away: startForeground() after stopSelf() is what throws
                // ForegroundServiceDidNotStartInTimeException, and the service
                // is being stopped anyway.
                if (!isStopping) shutdownService()
            }
        }
    }

    /**
     * Establishes the VPN and the TUN proxy. Shared by the initial setup and
     * by the reconnect after a network switch.
     *
     * [allowTakeover] says the user has agreed to take the slot from another
     * VPN app. It is the only way past the guard below, and the rebuild path
     * never passes it.
     *
     * @return true on success; false on failure (the caller then handles the
     *         isRunning state).
     */
    private suspend fun establishVpnInternal(allowTakeover: Boolean): Boolean {
        // A teardown that landed while this was still queued: none of what
        // follows would outlive the service, so do not even ask Android for a
        // TUN slot.
        if (isStopping) {
            Log.d(TAG, "Establish skipped: the service is stopping")
            return false
        }

        // The native library has to be there before a TUN is established.
        // Without it the calls below raise an UnsatisfiedLinkError — an
        // Error, not an Exception — which would escape the catch at the end
        // of this function and take the process with it. Establishing the TUN
        // first would be worse: the routes and the DNS server of the VPN
        // point into a TUN that nothing ever reads, so the device would be
        // left without DNS. Refuse before the TUN exists.
        if (!IrohProxy.isNativeLoaded()) {
            Log.e(TAG, "Establish failed: the native library is not loaded")
            return false
        }

        // Mutual-exclusion guard: Android allows only one active VpnService
        // TUN per user. If a foreign VPN app (e.g. Clash) currently owns the
        // slot, establish() would silently revoke it — refuse instead of
        // stealing it, unless the user agreed to take it. This single choke
        // point covers both the initial setup and the reconnect path
        // (rebuildTunnel), including the race where the other VPN started
        // while our session flags were still up.
        val slot = vpnSlot()
        val decision = VpnTakeoverPolicy.decide(
            slot,
            if (allowTakeover) VpnTakeoverChoice.TakeOver else VpnTakeoverChoice.Cancel
        )
        if (decision != VpnTakeoverDecision.Proceed) {
            val reason = when (decision) {
                is VpnTakeoverDecision.RefuseAlwaysOn ->
                    getString(R.string.error_vpn_always_on, decision.packageName)
                else -> getString(R.string.error_vpn_taken_over)
            }
            Log.e(TAG, "Another VPN owns the slot ($slot); refusing to establish")
            wasRevoked = true
            notifyVpnRevoked(reason)
            return false
        }

        val cm = connectivityManager
        // Snapshot before establish(): the VPN network that appears on top of
        // this is the one Android created for us.
        val vpnNetworksBefore = cm?.let { UnderlyingNetworkSelector.vpnNetworks(it) }.orEmpty()

        // The TUN descriptor's owner, tracked explicitly because it changes
        // hands three times below:
        //
        //   PFD   — Android opened it in establish(); the ParcelFileDescriptor
        //           owns it until detachFd() is called.
        //   LOCAL — after detachFd() this function owns the raw int.
        //   RUST  — once nativeStartTunProxy() has been entered the native
        //           side owns it and closes it on every path.
        //
        // Only one of the two variables below is ever set: the
        // ParcelFileDescriptor while it still owns the descriptor, the
        // detached int while this function owns it, and neither of them once
        // the native side has taken it. The descriptor has to be closed
        // exactly once — a second close of a number the process has already
        // handed on closes whatever holds that number now, and the failure is
        // silent — so the finally at the end of this function closes only
        // what is still ours.
        var tunPfd: ParcelFileDescriptor? = null
        var tunFd: Int? = null

        return try {
            // The block the tunnel claims, and the addresses inside it. The
            // native side holds them: the per-domain addresses it hands the
            // resolver live in the same block, so the two halves of the tunnel
            // cannot disagree about which addresses they are.
            val block = VirtualBlockSurvey.select(connectivityManager, ownVpnNetworks)
            if (block == null) {
                Log.e(TAG, "Could not determine the virtual block; refusing to establish")
                return false
            }
            Log.d(TAG, "Virtual block: ${block.network} and ${block.ipv6Network}/64")

            val builder = Builder()
                .setSession("Nexa")
                // Must match TUN_MTU in crates/nexapipe-client/src/tun_proxy.rs.
                .setMtu(tunMtu)
                .addAddress(block.interfaceIp, 24)
                // The IPv6 half of the block. Without an address Android gives
                // the TUN no IPv6 at all, and a route to a prefix the interface
                // does not hold is refused, so both are needed for the AAAA
                // answers Rust hands out to be reachable.
                .addAddress(block.ipv6InterfaceIp, 64)
                // Route only the virtual IP ranges: the DNS server and the
                // per-domain addresses go through the TUN, and so does the IPv6
                // half of the block. Nothing else is claimed: the device's own
                // IPv6 traffic is not our business.
                .addRoute(block.base, 24)
                .addRoute(block.ipv6Network, 64)
                .addDnsServer(block.dnsIp)
                // Exclude this app's own traffic so proxy connections use the
                // physical network.
                .addDisallowedApplication(packageName)

            val selectedNetwork = underlyingNetwork
            if (selectedNetwork != null) {
                builder.setUnderlyingNetworks(arrayOf(selectedNetwork))
                Log.d(
                    TAG,
                    "Set underlying network: $selectedNetwork " +
                        "(${UnderlyingNetworkSelector.transportName(connectivityManager!!, selectedNetwork)})"
                )
            } else {
                Log.d(TAG, "No underlying network from callback, skipping setUnderlyingNetworks")
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.d(TAG, "Failed to establish VPN")
                return false
            }
            // The ParcelFileDescriptor owns the descriptor from here until
            // detachFd() below.
            tunPfd = pfd

            // A suspension point, and the only one between the TUN coming up
            // and the descriptor changing hands: the coroutine can be
            // cancelled here — the user taps Disconnect while a network
            // switch is rebuilding, or the service is destroyed — and the
            // ParcelFileDescriptor is then the only thing holding the
            // descriptor. The finally below closes it. Without that the TUN
            // would stay established with nobody reading it while its routes
            // and its DNS server still point the device's DNS into it: a
            // device-wide DNS blackhole, with the foreground notification
            // taken away at the same time.
            trackOwnVpnNetwork(vpnNetworksBefore)

            // Transfer TUN fd ownership to Rust (the PFD is no longer usable
            // after detachFd).
            val fd = pfd.detachFd()
            tunPfd = null
            tunFd = fd

            val proxyDomainsStr = allowedDomains.joinToString(",")

            // TunProxy snapshots CUSTOM_DNS_SERVERS when it starts.  Refresh it
            // from the selected egress network so Wi-Fi and cellular DNS are
            // never mixed after a network switch.
            val dnsServers = UnderlyingNetworkSelector
                .dnsServers(connectivityManager!!, selectedNetwork)
            if (dnsServers.isNotEmpty()) {
                val dnsServersStr = dnsServers.joinToString(",")
                IrohProxy.nativeSetDnsServers(dnsServersStr)
                Log.d(TAG, "Set TUN DNS from ${UnderlyingNetworkSelector.transportName(connectivityManager!!, selectedNetwork)}: $dnsServersStr")
            } else {
                Log.w(TAG, "No DNS servers on selected underlying network: $selectedNetwork")
            }

            Log.d(TAG, "Starting TUN proxy: fd=$fd, " +
                    "proxyDomains=${allowedDomains.size} items")

            // The native side takes ownership of the descriptor: it closes it
            // on every path, including the ones that fail, because the
            // ownership transfer happens at the JNI boundary and it happens
            // once. So this side must not close it after the call — a second
            // close of a number the process may already have handed to
            // something else closes that instead, and the failure is silent.
            //
            // The one case where it is still ours is a native method that was
            // never entered at all, and that is what a `LinkageError` means:
            // the library or the method is not there. Anything else that
            // comes out of the call means the native method ran — it took the
            // descriptor and closed it on its way out — so closing it here
            // would be the second close this whole change is about.
            val result = try {
                IrohProxy.nativeStartTunProxy(
                    fd, proxyDomainsStr
                )
            } catch (e: Throwable) {
                if (e is LinkageError) {
                    Log.e(TAG, "nativeStartTunProxy could not be called at all", e)
                    // The native method was never entered, so it took the
                    // descriptor nowhere: it is still ours, and this is the
                    // only place that may close it.
                    closeTunFd(tunFd)
                } else {
                    Log.e(TAG, "nativeStartTunProxy threw after taking the fd", e)
                }
                throw e
            } finally {
                // The native side owns the descriptor from here on: it took it
                // at the JNI boundary and closes it on every path, including
                // the ones that fail. The LinkageError above is the one case
                // where it did not, and that branch closed it itself — so
                // there is nothing left here for the finally below.
                tunFd = null
            }

            if (result != 0) {
                Log.e(TAG, "Failed to start TUN proxy: $result")
                tunProxyStarted = false
                return false
            }

            // The service can be stopped while the call above blocks in Rust;
            // cancelling the scope never reached it, so ask again here. A
            // notification published now would belong to a service that is
            // gone, and the TUN proxy would outlive it.
            if (isStopping) {
                Log.d(TAG, "Service stopped during establish; discarding the TUN proxy")
                runCatching { IrohProxy.nativeStopTunProxy() }
                    .onFailure { Log.e(TAG, "nativeStopTunProxy after stop failed: ${it.message}") }
                tunProxyStarted = false
                return false
            }

            tunProxyStarted = true
            isServiceActive = true
            // The tunnel is up, and whoever asked for it is waiting for
            // exactly this answer. The flag above is already true, so a
            // reader that looks at it now and one that is woken by this
            // call see the same thing.
            notifyStartOutcome(true)
            Log.d(
                TAG,
                "VPN + TUN proxy established successfully (routing ${block.network} and " +
                    "${block.ipv6Network}/64)"
            )
            createNotificationChannel()
            // Posted with the cache together, and not in two steps: this replaces whatever
            // the poller last showed, so the cache has to hear about it in the same breath.
            // Cleared separately it would still hold the old rate text, and a tick whose new
            // text happened to equal that one would be skipped as "already showing" while
            // the banner sat there saying only "Connected" — which is what a network switch
            // looked like when the rates were quietly zero.
            synchronized(notificationLock) {
                startForeground(NOTIFICATION_ID, createNotification())
                lastNotificationText = null
            }
            // The tunnel is up, so the counters mean something: start showing them.
            startTrafficPolling()
            true
        } catch (e: TimeoutCancellationException) {
            // The budget of the reconnect that called this ran out. It has to
            // leave the coroutine the way it found it: the caller decides what
            // a timeout means (a retry), and turning it into a plain failure
            // here would swallow it.
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            // A deliberate cancellation — the user disconnected, or the
            // service is being destroyed. It is not a failure of the
            // establish and must not become one: the descriptor is cleaned up
            // on the way out, and the caller has to see the cancellation
            // rather than a `false` that leaves the session flags standing
            // over a tunnel that is not there.
            Log.d(TAG, "Establish cancelled")
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "VPN establishment failed: ${e.message}", e)
            tunProxyStarted = false
            false
        } finally {
            // Close the descriptor if it is still ours to close: the
            // ParcelFileDescriptor while it still owns it, the detached int
            // while this function owns it, and nothing at all once the native
            // side has taken it. Only one of the two is ever set, so this
            // closes the descriptor exactly once.
            tunPfd?.let { owned ->
                try {
                    owned.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Could not close the TUN descriptor: ${e.message}")
                }
            }
            closeTunFd(tunFd)
        }
    }

    /**
     * Closes a descriptor this side still owns.
     *
     * Only for a descriptor that was never handed to the native side: closing
     * a number the process has already handed on closes whatever holds that
     * number now, and the failure is silent.
     */
    private fun closeTunFd(fd: Int?) {
        if (fd == null) return
        try {
            ParcelFileDescriptor.adoptFd(fd).close()
        } catch (e: Exception) {
            Log.e(TAG, "Could not close the TUN descriptor $fd: ${e.message}")
        }
    }

    /**
     * Who owns the platform VPN slot right now.
     *
     * Our own tunnel is excluded by identity rather than by a flag: a flag
     * cannot tell "our session is up" apart from "our session is up and another
     * app has already taken the slot", which is exactly the rebuild race that
     * used to revoke the other app.
     */
    private fun vpnSlot(): VpnSlot {
        val cm = connectivityManager ?: return VpnSlot.Free
        val unknown = UnderlyingNetworkSelector.vpnNetworks(cm) - ownVpnNetworks
        val foreign = when {
            unknown.isEmpty() -> false
            // Our own tunnel could not be told apart from a foreign one when it
            // was established. Calling it foreign would tear the session down on
            // the next network switch, which is worse than leaving the old
            // exemption in place for a single network.
            ownVpnUnidentified && isServiceActive -> unknown.size > 1
            else -> true
        }
        if (!foreign) {
            return if (isServiceActive) VpnSlot.OwnSession else VpnSlot.Free
        }
        // Which network belongs to which package is not something Android tells
        // an app, so a configured always-on VPN is taken to be the VPN that is
        // up. Refusing is the safe answer: Android would restore it anyway.
        val alwaysOn = UnderlyingNetworkSelector.alwaysOnVpnPackage(this)
            ?: return VpnSlot.ForeignVpn
        return if (VpnTakeoverPolicy.isForeignAlwaysOn(alwaysOn, packageName)) {
            VpnSlot.AlwaysOnVpn(alwaysOn)
        } else {
            VpnSlot.ForeignVpn
        }
    }

    /**
     * Records the VPN network Android created for the TUN just established.
     *
     * [before] is the set of VPN networks that existed when establish() was
     * called; whatever appears on top of it is ours. Android registers that
     * network asynchronously, hence the short wait: without a recorded network
     * the next rebuild would see our own tunnel as a foreign VPN and refuse to
     * re-establish, which would break network switching altogether.
     */
    private suspend fun trackOwnVpnNetwork(before: Set<Network>) {
        val cm = connectivityManager ?: return
        var created: Set<Network> = emptySet()
        for (attempt in 0 until OWN_NETWORK_POLL_ATTEMPTS) {
            val appeared = UnderlyingNetworkSelector.vpnNetworks(cm) - before
            if (appeared.isNotEmpty()) {
                created = appeared
                break
            }
            if (attempt < OWN_NETWORK_POLL_ATTEMPTS - 1) delay(OWN_NETWORK_POLL_MS)
        }
        if (created.size != 1) {
            // Nothing appeared, or a foreign VPN appeared in the same window and
            // the two cannot be told apart. Guessing would let a rebuild revoke
            // that foreign VPN, so nothing is recorded and vpnSlot() keeps its
            // isServiceActive exemption for one network.
            ownVpnUnidentified = true
            Log.w(TAG, "Could not tell which VPN network is ours (${created.size} appeared)")
            return
        }
        val current = UnderlyingNetworkSelector.vpnNetworks(cm)
        // Drop the networks that are gone: the set would otherwise grow by one
        // on every network switch, none of them ever matching again.
        ownVpnNetworks = (ownVpnNetworks intersect current) + created
        ownVpnUnidentified = false
        Log.d(TAG, "Own VPN network: ${created.first()}")
    }

    /**
     * Stops the service cleanly after a failed establish.
     *
     * The service is started with startForegroundService(), which obligates it
     * to call startForeground() once; skipping that throws
     * ForegroundServiceDidNotStartInTimeException. If the VPN was never
     * established the brief startForeground here satisfies the obligation, and
     * the notification is removed immediately afterwards.
     */
    private fun shutdownService() {
        runCatching {
            createNotificationChannel()
            // The text says what is true: the tunnel is not up. The default
            // says "Connected", and this notification is posted rather than
            // skipped — so for as long as the removal takes, the shade would
            // claim a tunnel that was never there.
            startForeground(
                NOTIFICATION_ID,
                createNotification(getString(R.string.notification_text_connecting))
            )
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ============================================================
    // Network callbacks - track the underlyingNetwork (Wi-Fi / cellular)
    // ============================================================

    private fun registerNetworkCallback() {
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                refreshUnderlyingNetwork("network available: $network")
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                super.onCapabilitiesChanged(network, capabilities)
                refreshUnderlyingNetwork("network capabilities changed: $network")
            }

            override fun onLost(network: Network) {
                super.onLost(network)
                refreshUnderlyingNetwork("network lost: $network")
            }
        }

        // NET_CAPABILITY_VALIDATED is deliberately not required: carriers often
        // hijack the connectivity check, so Wi-Fi may never be validated ->
        // onAvailable is never called -> underlyingNetwork stays null. We do not
        // hijack the system connectivity-check domains either; they are still
        // validated over the real physical network.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager?.registerNetworkCallback(request, networkCallback as ConnectivityManager.NetworkCallback)
    }

    /**
     * Re-evaluate all physical networks on every callback instead of retaining
     * the first one delivered by ConnectivityManager.  This makes the policy
     * deterministic: usable Wi-Fi always wins over cellular.
     */
    private fun refreshUnderlyingNetwork(reason: String) {
        val cm = connectivityManager ?: return
        val selected = UnderlyingNetworkSelector.selectPreferredNetwork(cm)
        val previous = underlyingNetwork
        if (selected == previous) return

        underlyingNetwork = selected
        val selectedDescription = "${UnderlyingNetworkSelector.transportName(cm, selected)} $selected"
        Log.d(TAG, "Underlying network changed ($reason): $previous -> $selectedDescription")

        // The initial choice is consumed by establishVpnInternal.  Once TUN is
        // running, a different preferred network needs a new VPN interface so
        // Android updates both the underlying network and the TUN DNS snapshot.
        onUnderlyingNetworkChanged("$reason; selected $selectedDescription")
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            connectivityManager?.unregisterNetworkCallback(it)
        }
    }

    // ============================================================
    // Network-switch reconnect - rebuild the whole tunnel when the
    // underlying network (Wi-Fi / cellular) changes
    // ============================================================

    private fun onUnderlyingNetworkChanged(reason: String) {
        // Only trigger once the user has started the VPN and the TUN proxy is
        // up, so the initial setup cannot trigger it by accident.
        if (!isUserStarted || !isRunning || !tunProxyStarted) {
            Log.d(TAG, "Network change ignored ($reason): session not fully up")
            return
        }
        Log.d(TAG, "Network change detected ($reason), scheduling reconnect")
        scheduleReconnect()
    }

    private fun scheduleReconnect() {
        // Debounce: consecutive onLost/onAvailable collapse into the last one,
        // and the new network gets a moment to settle.
        reconnectJob?.cancel()
        reconnectJob = serviceScope.launch {
            delay(RECONNECT_DEBOUNCE_MS)
            reconnectTunnel()
        }
    }

    /**
     * Runs one reconnect, serialized against any other.
     *
     * The debounce cancels the previous job, but a cancelled coroutine only notices at a
     * suspension point and a rebuild has none inside its native calls — so the previous attempt
     * can still be mid-flight when this one starts. Waiting for it is the whole point: the
     * earlier code returned on "already in progress" instead, and the attempt that had been
     * cancelled had already stopped the TUN proxy. That combination is how a network switch
     * could end with the TUN down and nothing left to rebuild it.
     */
    private suspend fun reconnectTunnel() {
        if (!isUserStarted || !isRunning) return
        val completed = withTimeoutOrNull(RECONNECT_HANDOVER_TIMEOUT_MS) {
            reconnectMutex.withLock { reconnectTunnelOnce() }
            true
        }
        if (completed == null) {
            Log.w(
                TAG,
                "Reconnect: the previous attempt did not finish within " +
                    "${RECONNECT_HANDOVER_TIMEOUT_MS}ms, skipping this one"
            )
        }
    }

    private suspend fun reconnectTunnelOnce() {
        // The switch is not finished yet (e.g. airplane mode was turned
        // on): wait for the next network event.
        if (underlyingNetwork == null) {
            Log.d(TAG, "Reconnect: no underlying network yet, skipping")
            return
        }
        if (!IrohProxy.isNativeLoaded()) {
            Log.e(TAG, "Reconnect: native library not loaded")
            return
        }
        Log.d(TAG, "Reconnect: rebuilding tunnel on underlying network $underlyingNetwork")

        var lastError: Exception? = null
        for (attempt in 1..MAX_RECONNECT_ATTEMPTS) {
            if (!isUserStarted || !isRunning) return
            try {
                withTimeout(RECONNECT_ATTEMPT_TIMEOUT_MS) {
                    rebuildTunnel()
                }
                Log.d(TAG, "Reconnect complete (attempt $attempt/$MAX_RECONNECT_ATTEMPTS)")
                return
            } catch (e: TimeoutCancellationException) {
                lastError = e
                Log.e(TAG, "Reconnect attempt $attempt/$MAX_RECONNECT_ATTEMPTS timed out")
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Deliberate cancellation from a manual disconnect or
                // service destruction: do not retry.
                throw e
            } catch (e: Exception) {
                lastError = e
                Log.e(TAG, "Reconnect attempt $attempt/$MAX_RECONNECT_ATTEMPTS failed: ${e.message}")
            }
            if (attempt < MAX_RECONNECT_ATTEMPTS) {
                delay(RECONNECT_BACKOFF_MS)
            }
        }
        Log.e(TAG, "Reconnect: all attempts failed: ${lastError?.message}")
        // The TUN proxy is stopped at this point and the VPN went down with it, while
        // `isRunning` / `isServiceActive` are still true. That combination is what used to
        // leave the UI showing "Connected" over a dead data plane with no way back short of
        // killing the app: report it and tear the session down so the UI can say so and the
        // user can reconnect.
        //
        // Tear the session down *before* reporting it: the UI tells "the session is over" apart
        // from "the tunnel is up but the backend is not answering" by looking at
        // isServiceActive, which stopVPN() has just cleared.
        stopVPN()
        stopSelf()
        notifyBroken(getString(R.string.notify_tunnel_rebuild_failed))
    }

    /**
     * Rebuilds the tunnel: stop the old TUN proxy -> drop the connections that
     * were opened on the previous network -> re-establish the VPN and the TUN
     * proxy on the new underlying network -> warm the pool again.
     *
     * The iroh endpoint and the local proxy are left untouched on purpose:
     * recreating the endpoint opens an outage window of seconds to tens of
     * seconds (nativeStartIroh can block for 30s on a weak network) and may
     * leave the tunnel unusable if the rebuild fails.
     *
     * Step 2 is the one that used to be missing, and it is why a rebuilt tunnel
     * could still not reach the backend: QUIC does not notice a network switch.
     * A connection opened on the old network reports no close reason while its
     * path is dead, so the pool keeps handing it out and every proxied request
     * fails or hangs — the UI says "Connected" over a tunnel that carries
     * nothing. Dropping them makes the next request dial on the network that is
     * actually up.
     */
    private suspend fun rebuildTunnel() {
        // 1. Stop the old TUN proxy (closes the duplicated fd -> the old VPN is
        //    torn down automatically).
        runCatching { IrohProxy.nativeStopTunProxy() }
            .onFailure { Log.e(TAG, "Reconnect: nativeStopTunProxy failed: ${it.message}") }
        tunProxyStarted = false

        // 2. Forget the connections the old network left behind.
        runCatching { IrohProxy.nativeDropConnections() }
            .onFailure { Log.e(TAG, "Reconnect: nativeDropConnections failed: ${it.message}") }

        // 3. Re-establish the VPN (new TUN fd + new underlying network) and
        //    start the TUN proxy. Never with the user's takeover consent: a
        //    network switch is not an answer to "may we disconnect the other
        //    app", and a foreign VPN that arrived during the rebuild must not
        //    be revoked by it.
        if (!establishVpnInternal(allowTakeover = false)) {
            throw Exception("Reconnect: failed to re-establish VPN/TUN proxy")
        }

        // 4. Warm the pool again, and check that the backend is reachable from
        //    the new network. Without this a network the backend cannot be
        //    dialed on looks exactly like a working one until a request fails.
        val warmed = IrohProxy.nativePreconnect()
        if (warmed <= 0) {
            Log.w(TAG, "Reconnect: no backend answered the warm-up (nativePreconnect=$warmed)")
            notifyBroken(getString(R.string.notify_backend_unreachable))
        } else {
            Log.d(TAG, "Reconnect: $warmed backend(s) reachable on the new network")
        }
    }

    // ============================================================
    // Notifications
    // ============================================================

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    /**
     * The notification, with [text] as its second line — the plain "Connected" until the
     * first rate is known, then the current up and down rates.
     */
    private fun createNotification(text: String = getString(R.string.notification_text)): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            // The line under the title changes about once a second. Without this every tick
            // would replay the alert — sound, heads-up — that belongs to a notification that
            // has only just appeared.
            .setOnlyAlertOnce(true)
            .build()
    }

    /**
     * Starts refreshing the throughput in the notification; no-op when a poll is running.
     *
     * The baseline is dropped here as well as in [stopTrafficPolling]: the counters restart
     * from zero when the proxy does, and a rate carried across a restart would be fiction.
     */
    private fun startTrafficPolling() {
        if (trafficJob?.isActive == true) return
        lastTrafficSample = null
        trafficJob = serviceScope.launch {
            while (isActive) {
                publishThroughput()
                delay(TRAFFIC_POLL_INTERVAL_MS)
            }
        }
    }

    private fun stopTrafficPolling() {
        trafficJob?.cancel()
        trafficJob = null
        lastTrafficSample = null
        synchronized(notificationLock) { lastNotificationText = null }
    }

    /**
     * One tick: reads the counters, works out the rates and updates the notification when the
     * text has actually changed.
     *
     * The counters are cumulative, so the first sample only sets the baseline — a rate needs
     * two. A later sample that is *lower* is not negative throughput: the counters reset when
     * the proxy is stopped and started, which a network-switch rebuild does, so the baseline
     * is re-taken and this tick reports nothing rather than a rate that went backwards.
     */
    private suspend fun publishThroughput() {
        val raw = try {
            IrohProxy.nativeTraffic()
        } catch (e: Exception) {
            Log.w(TAG, "Could not read traffic counters: ${e.message}")
            return
        }
        if (raw == null) {
            // Nothing started yet, or the endpoint group is gone: no rate to show, and the
            // baseline is stale either way.
            lastTrafficSample = null
            return
        }

        var sent = 0L
        var received = 0L
        for (volume in parseNodeTraffic(raw).values) {
            sent += volume.sent
            received += volume.received
        }

        // Monotonic: a wall clock that jumps (NTP, user, sleep) would invent a rate.
        val now = SystemClock.elapsedRealtime()
        val previous = lastTrafficSample
        lastTrafficSample = TrafficSample(sent, received, now)
        if (previous == null) return

        val elapsedMs = now - previous.atMs
        if (elapsedMs <= 0L) return
        if (sent < previous.sent || received < previous.received) return

        // Per second, so the number is quoted the way a transfer is: KiB/s, not bytes/tick.
        val up = (sent - previous.sent) * 1000L / elapsedMs
        val down = (received - previous.received) * 1000L / elapsedMs
        publishNotificationText(
            getString(
                R.string.notification_text_rate,
                formatByteRate(up),
                formatByteRate(down)
            )
        )
    }

    /**
     * Re-posts the notification with [text], unless it is the text already showing.
     *
     * Same id as the one `startForeground` used, so this updates that notification instead of
     * adding a second one. Android throttles posts that come faster than it can render, and a
     * rate that has not changed is not worth spending one on.
     *
     * The two checks are what make it safe to call from anywhere: cancelling the poller does
     * not wait for the tick already running, and that tick reaches this line after the tunnel
     * is down and its notification has been taken away. Posting then would put a rate back on
     * screen for a service the user has stopped, which is why the teardown marker is read —
     * and written — inside the same lock the post itself takes.
     */
    private fun publishNotificationText(text: String) {
        synchronized(notificationLock) {
            if (isStopping) return
            if (text == lastNotificationText) return
            lastNotificationText = text
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(NOTIFICATION_ID, createNotification(text))
        }
    }

    companion object {
        private const val CHANNEL_ID = "NexaVPN"
        // The one notification this service owns: startForeground posts it, and every rate
        // update replaces it rather than adding another.
        private const val NOTIFICATION_ID = 1
        // How often the counters are read for the notification. One second is what makes the
        // figure read as a rate; more often and the text rarely changes, less often and it
        // lags what the tunnel is doing.
        private const val TRAFFIC_POLL_INTERVAL_MS = 1_000L
        const val ACTION_START = "com.nexa.pipe.vpn.ACTION_START"
        const val ACTION_STOP = "com.nexa.pipe.vpn.ACTION_STOP"
        /**
         * Bring the tunnel back after a restart.
         *
         * Sent by [BootReceiver] rather than by the screen: the user asked
         * for the tunnel to come back when the machine starts, and there is no
         * screen to ask at that point.
         */
        const val ACTION_BOOT_CONNECT = "com.nexa.pipe.vpn.ACTION_BOOT_CONNECT"
        const val EXTRA_DOMAINS = "com.nexa.pipe.vpn.EXTRA_DOMAINS"
        // Whether the user agreed that Nexa may take the slot from another VPN
        // app. Carried by ACTION_START; absent (or false) means the service
        // refuses to establish rather than revoking the other app.
        const val EXTRA_ALLOW_TAKEOVER = "com.nexa.pipe.vpn.EXTRA_ALLOW_TAKEOVER"

        // How long to wait for Android to register the VPN network of the TUN
        // we just established, and how often to look. Short on purpose: this
        // runs inside establish(), between the TUN coming up and the proxy
        // starting.
        private const val OWN_NETWORK_POLL_ATTEMPTS = 5
        private const val OWN_NETWORK_POLL_MS = 100L

        // How long the boot path waits for a network, and how often it looks.
        //
        // Generous, because a phone that has just been switched on has to find
        // a network first, and a tunnel built on no network reaches no
        // backend — but bounded, because a phone that never finds one must not
        // leave a foreground service waiting for it.
        private const val BOOT_NETWORK_TIMEOUT_MS = 60_000L
        private const val BOOT_NETWORK_POLL_MS = 1_000L

        // Network-switch reconnect parameters
        private const val RECONNECT_DEBOUNCE_MS = 1_500L
        private const val MAX_RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_ATTEMPT_TIMEOUT_MS = 60_000L
        private const val RECONNECT_BACKOFF_MS = 2_000L
        // How long a new reconnect waits for the one before it. Generous on purpose: a rebuild
        // blocked in a native call cannot be interrupted, so the wait is what keeps two of them
        // from ever touching the TUN at the same time.
        private const val RECONNECT_HANDOVER_TIMEOUT_MS = 120_000L

        /**
         * Process-level flag: whether the VPN service is active (the TUN proxy
         * has been established). Used by the ViewModel to sync the UI state
         * after the activity is recreated, so the UI cannot show
         * "Disconnected" while the VPN service is actually still running.
         */
        @Volatile
        @JvmStatic
        var isServiceActive: Boolean = false
            private set

        /**
         * Set when the VPN slot was lost to another VPN app: either onRevoke()
         * fired (the other app displaced our established VPN) or the
         * establish-time mutual-exclusion guard refused to steal the slot
         * back. Consumed by VpnViewModel.syncVpnServiceState() so the UI
         * aligns even when the event happened while no revoked-listener was
         * registered (app backgrounded / ViewModel recreated). Cleared when a
         * new session starts (startVPN()).
         */
        @Volatile
        @JvmStatic
        var wasRevoked: Boolean = false
            private set

        /**
         * Why the slot was lost, kept because the event that carries the reason
         * may reach no listener at all: a boot connection is refused with no
         * screen to report to, and the reason is what the user needs then.
         * Cleared with [wasRevoked] when a new session starts.
         */
        @Volatile
        @JvmStatic
        var lastRevokeReason: String? = null
            private set

        // Push channel for the "VPN slot lost" event so a foreground UI
        // updates immediately instead of waiting for the next resume-time
        // syncVpnServiceState() call. The reason is the message to show: the
        // slot can be lost to an ordinary VPN app or to the device's always-on
        // one, and those need different words.
        @Volatile
        @JvmStatic
        private var revokedListener: ((String) -> Unit)? = null

        fun setRevokedListener(listener: ((String) -> Unit)?) {
            revokedListener = listener
        }

        private fun notifyVpnRevoked(reason: String) {
            // Kept whether or not anyone is listening: a boot connection is
            // refused with no screen to report to, and the reason is what the
            // user is told when the app is opened afterwards.
            lastRevokeReason = reason
            revokedListener?.invoke(reason)
        }

        /**
         * Push channel for "the session is up but not actually working": a network switch the
         * tunnel did not survive, or one it survived while the backend stayed unreachable.
         *
         * Both used to be invisible — `isServiceActive` stayed true, so the UI kept showing a
         * healthy "Connected" over a dead data plane. The listener lets a foreground UI drop
         * back to the error state instead of lying.
         */
        @Volatile
        @JvmStatic
        private var brokenListener: ((String) -> Unit)? = null

        fun setBrokenListener(listener: ((String) -> Unit)?) {
            brokenListener = listener
        }

        /**
         * Reports a session that can no longer carry traffic. [reason] is the
         * message to show; the service decides whether the session is merely
         * degraded (the tunnel is up, the backend is not) or over.
         */
        private fun notifyBroken(reason: String) {
            brokenListener?.invoke(reason)
        }

        /**
         * Push channel for the outcome of a start.
         *
         * The service is the only side that knows it: the request to start
         * says nothing about the tunnel — `startForegroundService()` returns
         * as soon as the request is delivered — and only the establish says
         * whether the tunnel is up. The listener is told so once per start:
         * true when the tunnel is up, false when the start failed.
         *
         * Registered for the duration of one start, so a start nobody is
         * waiting for is reported to nobody.
         */
        @Volatile
        @JvmStatic
        private var startOutcomeListener: ((Boolean) -> Unit)? = null

        fun setStartOutcomeListener(listener: ((Boolean) -> Unit)?) {
            startOutcomeListener = listener
        }

        /**
         * Removes the listener, unless it is already another one.
         *
         * The check is what keeps a caller that has given up from removing
         * the listener of a start that came after it.
         */
        fun clearStartOutcomeListener(listener: (Boolean) -> Unit) {
            if (startOutcomeListener === listener) startOutcomeListener = null
        }

        /**
         * Reports the outcome of the start that is running.
         */
        private fun notifyStartOutcome(up: Boolean) {
            startOutcomeListener?.invoke(up)
        }
    }
}
