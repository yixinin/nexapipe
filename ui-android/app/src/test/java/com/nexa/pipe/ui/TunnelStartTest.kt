package com.nexa.pipe.ui

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the UI is allowed to believe about a start of the tunnel.
 *
 * The rule this pins down: the request to start says nothing about the
 * tunnel — `startForegroundService()` returns as soon as the request is
 * delivered — so only the service's own report of the establish may be
 * called a connected tunnel. A UI that believes the request instead says
 * "connected" over a tunnel that was never established, and keeps saying it
 * when the establish fails.
 */
class TunnelStartTest {

    @Test
    fun a_start_the_service_reported_as_up_is_a_tunnel() {
        assertTrue(tunnelIsUp(reportedUp = true, serviceActive = true))
    }

    @Test
    fun a_request_that_was_only_delivered_is_not_a_tunnel() {
        assertFalse(tunnelIsUp(reportedUp = false, serviceActive = false))
    }

    @Test
    fun a_start_nobody_answered_is_not_a_tunnel() {
        // The flag can still be true from an earlier session: the request
        // was delivered and the establish never finished, and neither of
        // them is a tunnel.
        assertFalse(tunnelIsUp(reportedUp = false, serviceActive = true))
    }

    @Test
    fun a_tunnel_the_service_no_longer_has_is_not_a_tunnel() {
        // The service reported the establish as done and the tunnel was
        // taken down in between: the session is over, not connected.
        assertFalse(tunnelIsUp(reportedUp = true, serviceActive = false))
    }

    @Test
    fun the_wait_ends_with_what_the_service_reported() {
        runBlocking {
            val up = CompletableDeferred<Boolean>()
            up.complete(true)
            assertTrue(awaitTunnelUp(up, timeoutMs = 1_000) { })

            val failed = CompletableDeferred<Boolean>()
            failed.complete(false)
            assertFalse(awaitTunnelUp(failed, timeoutMs = 1_000) { })
        }
    }

    @Test
    fun a_service_that_says_nothing_is_not_a_tunnel() {
        runBlocking {
            val outcome = CompletableDeferred<Boolean>()
            var logged = false

            val up = awaitTunnelUp(outcome, timeoutMs = 50) { logged = true }

            // Silence is not success: the attempt is over and is retried,
            // and the wait that ran out is said out loud.
            assertFalse(up)
            assertTrue(logged)
        }
    }
}
