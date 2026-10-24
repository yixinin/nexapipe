package com.nexa.pipe.ui

import android.content.Context
import android.net.ConnectivityManager
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.R
import com.nexa.pipe.locale.AppStrings
import com.nexa.pipe.vpn.UnderlyingNetworkSelector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.net.InetAddress

/**
 * The connection sequence, without the screen around it.
 *
 * The view model owns the screen and the retry loop; this owns the part that has
 * to happen the same way whoever is connecting: the native side has to be told
 * about the relay, the credentials and the domain mappings, the iroh endpoint
 * has to be up, the endpoint group has to be built, and the backends have to
 * answer before a tunnel is worth showing.
 *
 * It is a class of its own because there is more than one caller. The screen
 * connects when the user asks, and the boot receiver connects when the machine
 * comes up. Two copies of this sequence would be two copies to keep in step,
 * and the step that drifts is the one that only runs at seven in the morning.
 *
 * Every step throws on failure rather than returning a verdict: the caller's
 * retry loop already knows what to do with an exception, and a second way of
 * saying "that failed" is a second way of saying it slightly differently.
 */
class ProxyConnector(private val log: ConnectionLog) {

    /**
     * Where the running commentary goes.
     *
     * The screen puts it in front of the user; the boot receiver writes it to
     * the log, because there is no screen to put it in.
     */
    interface ConnectionLog {
        fun log(message: String)
    }

    /**
     * Everything one attempt needs to know.
     *
     * A value rather than a reference to the view model's state, so the
     * sequence cannot read a list that is being edited underneath it.
     */
    class Plan(
        /** The endpoints, with their domains and their credentials. */
        val nodes: List<NodeConfig>,
        /** "pinned", "default", "disabled" or "custom". */
        val relayMode: String,
        val relayUrl: String,
        val relayAuthToken: String,
        /**
         * Whether this device may ask n0 where a peer is: "n0" (the default)
         * or "none".
         *
         * With the lookup off, a peer is only reachable by an address this
         * device was given — a ticket — and not by a Node ID alone, because
         * finding the address behind a Node ID is the lookup itself.
         */
        val discoveryMode: String,
        /** The name this install answers as. */
        val deviceId: String,
        /**
         * The private half of each endpoint's device key, by endpoint ID.
         *
         * Read by the caller rather than here, because this class does not
         * know where a sealed half lives. A function rather than a value: it
         * is read after [awaitDeviceKeys] has run, because a key that is
         * still being sealed at that point is a key that is not on disk yet,
         * and a snapshot taken earlier would hand the native side nothing.
         *
         * The nodes are passed in rather than read from the caller: the plan
         * carries a snapshot of them, and a key that is missing from the map
         * is a key that is not registered — which is what a half-finished
         * enrolment costs.
         */
        val deviceKeys: (List<NodeConfig>) -> Map<String, String> = { emptyMap() },
        /**
         * Whether the iroh endpoint is already up.
         *
         * False on every attempt after a failed one, because the resources are
         * released between attempts and the endpoint goes down with them.
         */
        val irohStarted: Boolean = false,
        /**
         * Waits for whatever writes a device key to finish writing it.
         *
         * The key is registered with the native side, and it has to be on disk
         * before that: a key that is only in memory is a key the next connect
         * will not have.
         */
        val awaitDeviceKeys: suspend () -> Unit = {}
    )

    /**
     * What an attempt did, for the caller to keep its own state in step with.
     */
    class Outcome(
        /** Whether this call was the one that brought the endpoint up. */
        val startedIroh: Boolean
    )

    /**
     * Brings the native side up for one connection attempt.
     *
     * Throws when the attempt cannot be made: no library, no usable endpoint
     * ID, no domain to route, no backend that answers.
     */
    suspend fun prepare(
        context: Context,
        plan: Plan,
        /**
         * Called once the backends have answered.
         *
         * That is when a server may have issued a credential — the one a
         * registration invite buys — and the credential has to be picked up
         * and stored before the next attempt spends nothing to get it.
         */
        onCredentialIssued: suspend () -> Unit = {}
    ): Outcome {
        // The native library is not loaded: every call below raises an
        // UnsatisfiedLinkError, and that is an Error and not an Exception, so
        // it would escape the caller's `catch (e: Exception)` and take the
        // process down with it. The screen checks this before it gets here;
        // the boot path does not, so the check is here as well.
        if (!IrohProxy.isNativeLoaded()) {
            throw Exception(AppStrings.get(R.string.error_native_library))
        }

        // Inject the system DNS into iroh so it does not fall back to Google
        // DNS after the JNI system-DNS read fails on Android (unreliable
        // behind restrictive networks, backends unreachable).
        // Re-read on every attempt because the network may have changed after
        // the resources were released.
        val dnsServers = systemDnsServers(context)
        if (dnsServers.isNotEmpty()) {
            log.log("Injecting system DNS servers: $dnsServers")
            IrohProxy.nativeSetDnsServers(dnsServers)
        }

        // Pre-resolve the iroh infrastructure domains to work around the GFW
        // dropping iroh.link UDP DNS responses. Re-resolved on every attempt.
        //
        // Always handed over, empty included: the table on the native side is
        // replaced by the call, so a configuration that resolves nothing has
        // to say so rather than keep what the last attempt left behind.
        val dnsOverrides = resolveIrohDnsOverrides(plan)
        IrohProxy.nativeSetDnsOverride(dnsOverrides)

        // Configure the relay mode.
        IrohProxy.nativeSetRelayConfig(plan.relayMode, plan.relayUrl, plan.relayAuthToken)

        // Configure whether this device may ask n0 where a peer is.
        IrohProxy.nativeSetDiscoveryMode(plan.discoveryMode)

        // Configure the 2FA credentials (must be injected before
        // nativeStartProxy). Every endpoint carries its own pair, so the
        // native table is cleared first: without that, an endpoint whose 2FA
        // was switched off would still hold the credentials of an earlier
        // connect for as long as the process lives.
        IrohProxy.nativeClearNodeTwoFactor()

        // One name for this install, however many endpoints it authenticates
        // to, read when the enrollment below is armed. Before any credential
        // is registered rather than after: what is in the native tables at
        // nativeStartProxy is what goes on the wire.
        IrohProxy.nativeSetDeviceId(plan.deviceId)

        for (node in plan.nodes) {
            val otp = node.twoFactor?.takeIf { it.enabled } ?: continue
            IrohProxy.nativeSetTwoFactorForNode(
                node.nodeId,
                otp.clientId,
                otp.secret,
                otp.algorithm,
                // The device this secret was issued to, or empty for one
                // issued to the client — which is every pair this app could
                // hold before devices existed, and every pair a plain invite
                // will ever hand over. Those must keep answering unnamed: a
                // server asked for a device it does not know refuses rather
                // than falling back.
                otp.device.orEmpty()
            )
        }

        // A token instead of credentials, for an endpoint that was invited with
        // one. Only where no secret exists: enrolling rotates the secret, so
        // an endpoint that already has one must not spend a token again.
        for (node in plan.nodes) {
            val enrollment = node.enrollment ?: continue
            val hasSecret = node.twoFactor?.takeIf { it.enabled }
                ?.secret?.isNotBlank() == true
            if (hasSecret) continue
            IrohProxy.nativeSetEnrollmentForNode(
                node.nodeId,
                enrollment.clientId,
                enrollment.token
            )
        }

        // The device key of an endpoint that has one, for the two things it is
        // used for: the enrollment above offers it, and every handshake after
        // it signs with it. Registered before the group starts, like every
        // other credential — what is in the native tables at nativeStartProxy
        // is what goes on the wire.
        //
        // The import that armed the enrollment sealed the key off the main
        // thread; joining here is what makes the read below wait for that
        // write to land, rather than hand the native side a key that is not on
        // disk yet.
        plan.awaitDeviceKeys()
        val deviceKeys = plan.deviceKeys(plan.nodes)
        for (node in plan.nodes) {
            val key = deviceKeys[node.nodeId].orEmpty()
            if (key.isBlank()) continue
            IrohProxy.nativeSetDeviceKeyForNode(node.nodeId, key)
        }

        val startedIroh = ensureIrohStarted(plan.irohStarted)

        // The domains to route, and the endpoints that carry them.
        addDomainMappings(plan.nodes)

        // The endpoint group the tunnel runs on.
        startEndpointGroup()

        // Pre-connect: warm up iroh connections directly on the Rust side and
        // cache them in the shared connection pool. Unlike HTTP-based warm-up
        // through the local proxy, this does not depend on backends answering
        // plain HTTP requests, and it does not consume pooled connections, so
        // warm-up is reliable.
        //
        // This is also the only step that validates the configured endpoint
        // IDs against the network: nativeStartProxy merely parses them, so a
        // well-formed but nonexistent node ID (or a server that is down)
        // would sail through and the VPN would come up reporting "connected"
        // while every proxied request fails.
        log.log("Pre-connecting to backends (native warm-up)...")
        val preConnectedCount = IrohProxy.nativePreconnect()
        if (preConnectedCount <= 0) {
            // Fail the attempt: the retry loop gets another go, and if every
            // attempt fails the reason reaches the caller instead of a green
            // "connected" over a tunnel that reaches nothing.
            throw Exception(preconnectFailureReason(preConnectedCount, plan.nodes))
        }
        log.log("Pre-connect completed: $preConnectedCount backend(s) warmed")

        // The pre-connect is what spent the token: read the secret it bought
        // now, because a second connect has nothing left to spend.
        onCredentialIssued()

        return Outcome(startedIroh)
    }

    /**
     * Starts the iroh endpoint if it is not up yet.
     *
     * nativeStartIroh already has a 30s timeout on the Rust side. Throwing
     * means failure; the caller decides whether to retry.
     *
     * Public because the screen can start the endpoint on its own, without a
     * connection: the settings page has a button that does exactly that.
     */
    suspend fun ensureIrohStarted(alreadyStarted: Boolean): Boolean {
        // The native library may not be there at all: the call below raises an
        // UnsatisfiedLinkError, which is an Error and not an Exception, so it
        // would escape the caller's `catch (e: Exception)` and take the
        // process down with it. prepare() checks this too, but this is public
        // and the screen can reach it on its own — without a connection
        // behind it — so the check has to be here as well.
        if (!IrohProxy.isNativeLoaded()) {
            throw Exception(AppStrings.get(R.string.error_native_library))
        }
        if (alreadyStarted) return false
        log.log("Starting iroh first...")
        val id = IrohProxy.nativeStartIroh()
        if (id == null) {
            throw Exception(AppStrings.get(R.string.error_start_iroh))
        }
        // The node id is the endpoint's public identity, but the log panel
        // keeps the last hundred lines and a screenshot of it is a screenshot
        // of the machine's inventory. The first eight characters are enough to
        // tell two endpoints apart, and every other node id in this app is
        // logged the same way.
        log.log("Iroh started: ${id.take(8)}")
        return true
    }

    /**
     * Reads the system DNS server list from ConnectivityManager and returns it
     * as a comma-separated string of IPs.
     *
     * By default iroh fails to read the system DNS on Android through JNI
     * ("Null pointer in call_method obj argument") and falls back to Google DNS
     * (8.8.8.8/8.8.4.4), which is unreliable behind restrictive networks and
     * leaves the backend unreachable. Instead, Kotlin reads the system DNS
     * straight from ConnectivityManager.getLinkProperties().dnsServers and
     * hands it to nativeSetDnsServers on the Rust side, so iroh uses a custom
     * DnsResolver instead of the broken JNI path.
     *
     * A connected Wi-Fi network is always preferred; cellular is only picked
     * when no usable Wi-Fi exists. Only that network's DNS is read, so Wi-Fi
     * and cellular DNS are never mixed. If the system DNS list is empty (an
     * edge case), fall back to public DNS servers that are widely reachable
     * from mainland China (AliDNS 223.5.5.5, 114DNS 114.114.114.114).
     */
    private fun systemDnsServers(context: Context): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return ""
        val selectedNetwork = UnderlyingNetworkSelector.selectPreferredNetwork(cm)
        val servers = UnderlyingNetworkSelector
            .dnsServers(cm, selectedNetwork)
            .toCollection(linkedSetOf())
        if (servers.isNotEmpty()) {
            log.log(
                "Using ${UnderlyingNetworkSelector.transportName(cm, selectedNetwork)} DNS: $servers"
            )
        }

        // Last-resort fallback: public DNS servers commonly reachable from
        // mainland China. AliDNS + 114DNS cover the common cases.
        if (servers.isEmpty()) {
            log.log("No system DNS found, falling back to public DNS (223.5.5.5, 114.114.114.114)")
            servers.add("223.5.5.5")
            servers.add("114.114.114.114")
        }

        return servers.joinToString(",")
    }

    /**
     * Pre-resolves the IPs of the iroh infrastructure domains and injects them
     * into the OverrideResolver on the Rust side.
     *
     * The Great Firewall (GFW) drops UDP DNS responses for iroh.link domains,
     * so iroh's internal hickory resolver times out on dns.iroh.link and
     * *.relay.n0.iroh.link. Those domains are pre-resolved here with the system
     * DNS (InetAddress, which may go through DoT / Private DNS and bypass the
     * GFW) and returned as "domain=ip1,ip2;domain2=ip3" for connect() to pass
     * to nativeSetDnsOverride. The OverrideResolver then returns the
     * pre-resolved IPs directly for these domains, so pkarr resolve (HTTPS to
     * dns.iroh.link/pkarr/<z32>) and the relay connection succeed.
     */
    private suspend fun resolveIrohDnsOverrides(plan: Plan): String {
        // DNS origin and default relay servers used by iroh presets::N0.
        //
        // Only the ones this configuration actually uses. The lookup's own
        // host is asked about nothing when the lookup is off, and the n0
        // relays are dialled by nobody when the relay is the operator's own
        // or when there is none. Resolving a host the endpoint will never
        // talk to is a question asked for nothing — and with the lookup off
        // it is a question about n0 that the operator said not to ask.
        val domains = mutableListOf<String>()
        if (plan.discoveryMode != "none") {
            domains.add("dns.iroh.link")
        }
        if (plan.relayMode != "custom" && plan.relayMode != "disabled") {
            domains.add("use1-1.relay.n0.iroh.link")
            domains.add("usw1-1.relay.n0.iroh.link")
            domains.add("euc1-1.relay.n0.iroh.link")
            domains.add("aps1-1.relay.n0.iroh.link")
        }
        if (domains.isEmpty()) {
            log.log("No iroh domain to pre-resolve: neither the lookup nor the n0 relays are in use")
            return ""
        }

        val overrides = kotlinx.coroutines.coroutineScope {
            domains.map { domain ->
                async(Dispatchers.IO) {
                    try {
                        val addrs = InetAddress.getAllByName(domain)
                        val ips = addrs.mapNotNull { it.hostAddress }
                        if (ips.isNotEmpty()) {
                            log.log("Resolved iroh domain $domain -> $ips")
                            "$domain=${ips.joinToString(",")}"
                        } else {
                            log.log("Failed to resolve iroh domain $domain (no IPs)")
                            null
                        }
                    } catch (e: Exception) {
                        log.log("Failed to resolve iroh domain $domain: ${e.message}")
                        null
                    }
                }
            }.awaitAll()
        }

        val result = overrides.filterNotNull().joinToString(";")
        log.log("iroh DNS overrides: $result")
        return result
    }

    /**
     * Clears and re-adds the domain -> node mappings.
     *
     * Throws when there is no mapping at all: a tunnel that routes nothing is
     * a tunnel that looks connected and carries nothing.
     */
    private fun addDomainMappings(nodes: List<NodeConfig>) {
        IrohProxy.nativeClearNodes()
        var hasDomainMappings = false
        for (node in nodes) {
            if (node.domains.isNotEmpty()) {
                for (domain in node.domains) {
                    log.log("Adding domain mapping: '$domain' -> nodeId: ${node.nodeId.take(8)}")
                    val result = IrohProxy.nativeAddDomainMapping(domain, node.nodeId)
                    if (result != 0) {
                        log.log("Failed to add domain mapping: $domain")
                    } else {
                        hasDomainMappings = true
                    }
                }
            }
        }
        if (!hasDomainMappings) {
            throw Exception(AppStrings.get(R.string.error_no_domain_mappings))
        }
    }

    /**
     * Builds the endpoint group the tunnel runs on. nativeStopProxy runs first
     * so a previous attempt cannot leave half of one behind.
     *
     * Nothing is bound on loopback: on Android every app shares 127.0.0.1, so a
     * local proxy port hands any of them an already-authenticated tunnel
     * without the user being asked. The tunnel is entered through the TUN fd
     * alone (nativeStartTunProxy), which is what the VPN permission covers.
     *
     * There is nothing to retry here: a failure is either a configuration error
     * (malformed endpoint ID, no domains) or a group that could not be built,
     * and both fail identically on every attempt. Either way, the real reason is
     * on the native side, so it leads the message instead of a generic string.
     */
    private fun startEndpointGroup() {
        log.log("Starting endpoint group...")
        IrohProxy.nativeStopProxy()
        val result = IrohProxy.nativeStartProxy()
        if (result != 0) {
            val reason = nativeFailureReason()
            throw Exception(
                AppStrings.get(R.string.error_invalid_proxy_config) +
                    if (reason != null) ": $reason" else ""
            )
        }
        log.log("Endpoint group started")
    }

    /**
     * Human-readable reason for a failed native pre-connect.
     *
     * `nativePreconnect` returns the number of backends that answered. Zero means
     * every configured endpoint ID was unreachable (wrong ID, server offline, or
     * the relay/network blocks it). A negative value means the check itself could
     * not run, e.g. no endpoint group or it exceeded its timeout.
     */
    private fun preconnectFailureReason(result: Int, nodes: List<NodeConfig>): String {
        val targets = nodes
            .map { it.nodeId }
            .ifEmpty { listOf(AppStrings.get(R.string.error_configured_backends)) }
            .joinToString(", ")
        val base = if (result == 0) {
            AppStrings.get(R.string.error_no_backend_reachable, targets)
        } else {
            AppStrings.get(R.string.error_preconnect_failed, result)
        }
        // A server that answered and then refused the connection (2FA, most
        // often) leaves its reason on the native side. Without it a refusal
        // looks exactly like an offline server.
        val detail = nativeFailureReason()
        return if (detail != null) {
            "$base ${AppStrings.get(R.string.error_cause, detail)}"
        } else {
            base
        }
    }

    /** Reason behind the last failed native call, or null when there is none. */
    private fun nativeFailureReason(): String? = try {
        IrohProxy.nativeTakeLastError()
    } catch (e: Exception) {
        log.log("Could not read the native error: ${e.message}")
        null
    }

    /**
     * Null when [id] is a valid endpoint ID, otherwise a message for the user.
     *
     * The check runs through the native parser, so it can never disagree with
     * the connection path. Best-effort by design: when the native library is not
     * loaded the ID is accepted here and the connect-time pre-flight reports
     * the problem instead.
     *
     * Public because the settings page checks an endpoint ID as it is typed,
     * before there is any connection to check it against.
     */
    fun nodeIdFormatError(id: String): String? {
        if (!IrohProxy.isNativeLoaded()) return null
        val reason = try {
            IrohProxy.nativeValidateNodeId(id)
        } catch (e: Exception) {
            log.log("Node ID validation unavailable: ${e.message}")
            return null
        } ?: return null
        return AppStrings.get(R.string.error_invalid_endpoint_id, id, reason)
    }

    /**
     * Validates every configured node before a connect attempt starts.
     *
     * Without this a malformed ID only surfaced from deep inside the native
     * proxy start: the native layer returns a bare -1 for every failure, the
     * caller read that as "port in use", and the user got "Failed to start proxy
     * on ports 8080..8089" after 10 ports x 3 attempts — a message that named
     * neither the node nor the real cause.
     *
     * @return null when every ID parses, otherwise the reason for the first
     *   invalid one.
     */
    fun validateConfiguredNodeIds(nodes: List<NodeConfig>): String? {
        for (node in nodes) {
            val error = nodeIdFormatError(node.nodeId)
            if (error != null) return error
        }
        return null
    }
}
