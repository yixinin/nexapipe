package com.nexa.pipe.provisioning

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Kotlin half of the invite parser.
 *
 * These mirror the Rust tests in `nexapipe_client::provisioning`: the two
 * implementations have to accept and reject exactly the same codes, because one
 * writes what the other reads.
 */
class EndpointInviteTest {

    // A Node ID nobody is listening on. Fixed, so a parsed invite can be
    // compared against the one it was built from.
    private val nodeId = "1f2e3d4c5b6a798807162534435261708f9ea0b1c2d3e4f5061728394a5b6c7d"

    private fun invite(): EndpointInvite = EndpointInvite(
        target = InviteTarget.NodeId(nodeId),
        name = "Home",
        domains = listOf("a.example", "b.example"),
        relay = null,
        totp = InviteTotp(
            issuer = "NexaPipe",
            clientId = "client-001",
            secret = "JBSWY3DPEHPK3PXP",
            algorithm = "sha1",
            digits = 6,
            period = 30
        )
    )

    private fun success(uri: String): EndpointInvite {
        val result = EndpointInviteCodec.parse(uri)
        assertTrue("expected success but got $result", result is InviteParseResult.Success)
        return (result as InviteParseResult.Success).invite
    }

    private fun failure(uri: String): String {
        val result = EndpointInviteCodec.parse(uri)
        assertTrue("expected failure but got $result", result is InviteParseResult.Failure)
        return (result as InviteParseResult.Failure).message
    }

    @Test
    fun round_trips_every_field() {
        val parsed = success(invite().toUri())
        assertEquals(invite(), parsed)
    }

    @Test
    fun builds_a_canonical_uri() {
        val bare = EndpointInvite(
            target = InviteTarget.NodeId(nodeId),
            name = null,
            domains = listOf("a.example"),
            relay = null,
            totp = null
        )
        assertEquals("nexapipe://endpoint/$nodeId?v=1&domains=a.example", bare.toUri())
    }

    @Test
    fun round_trips_a_ticket_target() {
        val invite = EndpointInvite(
            target = InviteTarget.Ticket("endpointabc123"),
            name = null,
            domains = emptyList(),
            relay = null,
            totp = null
        )
        val uri = invite.toUri()
        assertTrue(uri, uri.startsWith("nexapipe://ticket/"))
        assertEquals(invite, success(uri))
    }

    @Test
    fun percent_decodes_values() {
        val invite = invite().copy(
            name = "My VPN @ home",
            relay = "https://relay.example"
        )
        val uri = invite.toUri()
        assertTrue(uri, uri.contains("My%20VPN%20%40%20home"))
        assertTrue(uri, uri.contains("https%3A%2F%2Frelay.example"))
        assertEquals(invite, success(uri))
    }

    @Test
    fun accepts_an_uppercase_scheme_and_a_trailing_slash() {
        val uri = invite().toUri().replace("nexapipe://", "NEXAPIPE://").replace("?v=1", "/?v=1")
        assertEquals(invite(), success(uri))
    }

    @Test
    fun ignores_unknown_parameters() {
        val invite = success("${invite().toUri()}&strike=magnet")
        assertEquals(listOf("a.example", "b.example"), invite.domains)
    }

    @Test
    fun keeps_the_first_occurrence_of_a_repeated_parameter() {
        val base = invite().copy(domains = emptyList())
        val invite = success("${base.toUri()}&domains=a.example&domains=b.example")
        assertEquals(listOf("a.example"), invite.domains)
    }

    @Test
    fun normalizes_domains() {
        val invite = success("nexapipe://endpoint/$nodeId?v=1&domains=%20A.example.%20,a.example,B.EXAMPLE")
        assertEquals(listOf("a.example", "b.example"), invite.domains)
    }

    /**
     * The domain list is a list of patterns, and the server's route patterns
     * are what ends up in an invite.
     *
     * `*.` is the catch-all in another spelling: folded into `*`, it would hand
     * the client the catch-all — every host — for a spelling that asked for
     * something narrower. It keeps its own shape instead, and a pattern in
     * that shape matches nothing.
     */
    @Test
    fun a_pattern_that_folds_into_the_catch_all_keeps_its_shape() {
        val invite = success("nexapipe://endpoint/$nodeId?v=1&domains=%2A.example.com,%2A.")
        assertEquals(listOf("*.example.com", "*."), invite.domains)
    }

    @Test
    fun rejects_broken_domain_lists() {
        assertTrue(failure("nexapipe://endpoint/$nodeId?v=1&domains=a,,b").contains("invalid"))
        assertTrue(failure("nexapipe://endpoint/$nodeId?v=1&domains=a%2Fb").contains("invalid"))
    }

    @Test
    fun rejects_other_schemes_and_kinds() {
        assertTrue(failure("https://example.com/?v=1").contains("Not a nexapipe://"))
        assertTrue(failure("nexapipe://server/$nodeId?v=1").contains("Unknown invite kind"))
        assertTrue(failure("nexapipe://endpoint/nope?v=1").contains("is not a Node ID"))
    }

    @Test
    fun rejects_a_future_version() {
        // v=2 became real — enrollment — so the version nobody can read is the
        // next one along.
        assertTrue(failure("nexapipe://endpoint/$nodeId?v=3").contains("Unsupported invite version 3"))
    }

    @Test
    fun round_trips_an_enrollment_invite_as_version_two() {
        val invite = EndpointInvite(
            target = InviteTarget.NodeId(nodeId),
            name = "Home",
            domains = listOf("a.example"),
            relay = null,
            totp = null,
            enrollment = InviteEnrollment(clientId = "client-001", token = "tok")
        )

        val uri = invite.toUri()
        assertTrue(uri, uri.contains("v=2"))
        assertTrue(uri, uri.contains("enroll=tok"))
        assertTrue(uri, !uri.contains("secret="))
        assertTrue(invite.isEnrollment())

        assertEquals(invite, success(uri))
        assertEquals("client-001", success(uri).enrollment?.clientId)
        assertNull(success(uri).totp)
    }

    /**
     * A v=1 app ignores parameters it does not know, so a token in a v=1 code
     * would be dropped and the scan would import an endpoint with no
     * credentials — which looks like it worked until it tries to connect.
     */
    @Test
    fun refuses_an_enrollment_token_in_a_version_one_code() {
        val uri = "nexapipe://endpoint/$nodeId?v=1&client=client-001&enroll=tok"
        assertTrue(failure(uri).contains("enrollment"))
    }

    @Test
    fun refuses_a_code_that_hands_out_both_a_token_and_a_secret() {
        val uri = "nexapipe://endpoint/$nodeId?v=2&client=client-001&enroll=tok" +
            "&secret=JBSWY3DPEHPK3PXP"
        assertTrue(failure(uri).contains("both"))
    }

    @Test
    fun needs_a_client_id_next_to_the_token() {
        assertTrue(failure("nexapipe://endpoint/$nodeId?v=2&enroll=tok").contains("no client id"))
    }

    @Test
    fun needs_a_non_empty_token() {
        assertTrue(failure("nexapipe://endpoint/$nodeId?v=2&client=client-001&enroll=%20").contains("empty"))
    }

    @Test
    fun rejects_a_relay_that_is_not_a_url() {
        assertTrue(failure("nexapipe://endpoint/$nodeId?relay=not-a-url").contains("invalid"))
    }

    @Test
    fun rejects_a_relay_that_is_not_http() {
        // iroh's RelayUrl is http/https only, so a relay the endpoint could
        // never dial is refused here rather than at connect time.
        assertTrue(failure("nexapipe://endpoint/$nodeId?relay=ftp%3A%2F%2Frelay.example").contains("invalid"))
        // A scheme without a host parses as a URI but names no server.
        assertTrue(failure("nexapipe://endpoint/$nodeId?relay=https%3A%2F%2F").contains("invalid"))
    }

    @Test
    fun accepts_an_http_relay_with_a_host() {
        assertEquals(
            "https://relay.example",
            success("nexapipe://endpoint/$nodeId?relay=https%3A%2F%2Frelay.example").relay
        )
    }

    @Test
    fun rejects_a_code_length_outside_the_supported_range() {
        val uri = "nexapipe://endpoint/$nodeId?client=c&secret=JBSWY3DPEHPK3PXP&digits=9"
        assertTrue(failure(uri).contains("digits"))
    }

    @Test
    fun needs_a_client_id_next_to_the_secret() {
        assertTrue(failure("nexapipe://endpoint/$nodeId?secret=JBSWY3DPEHPK3PXP").contains("no client id"))
    }

    @Test
    fun needs_a_secret_next_to_the_other_two_factor_parameters() {
        assertTrue(failure("nexapipe://endpoint/$nodeId?client=client-001").contains("no secret"))
    }

    @Test
    fun reads_a_nested_otpauth_uri() {
        val embedded = "otpauth%3A%2F%2Ftotp%2FNexaPipe%3Aclient-001%3Fsecret%3DJBSWY3DPEHPK3PXP" +
            "%26issuer%3DNexaPipe%26algorithm%3DSHA256"
        val invite = success("nexapipe://endpoint/$nodeId?otpauth=$embedded")
        assertEquals("client-001", invite.totp?.clientId)
        assertEquals("NexaPipe", invite.totp?.issuer)
        assertEquals("JBSWY3DPEHPK3PXP", invite.totp?.secret)
        assertEquals("sha256", invite.totp?.algorithm)
    }

    @Test
    fun rejects_an_unsupported_algorithm() {
        assertTrue(
            failure("nexapipe://endpoint/$nodeId?client=c&secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
                .contains("Unsupported algorithm")
        )
    }

    /**
     * A code printed by `nexapipe --generate-invite`, byte for byte.
     *
     * The server writes these with the Rust codec and the app reads them with
     * this one, so this is the closest thing to an interop test: change either
     * side's grammar and it fails here.
     */
    @Test
    fun reads_a_code_printed_by_the_server() {
        val uri = "nexapipe://endpoint/" +
            "a612286b30098f67db06783c45004e43cf182e06806540e7e6260a0f009a7063" +
            "?v=1&name=Home&domains=example.com,api.example.com" +
            "&relay=https%3A%2F%2Frelay.example.com" +
            "&client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXP" +
            "&algorithm=SHA256&digits=6&period=30"

        val invite = success(uri)
        assertEquals(
            "a612286b30098f67db06783c45004e43cf182e06806540e7e6260a0f009a7063",
            (invite.target as InviteTarget.NodeId).id
        )
        assertEquals("Home", invite.name)
        assertEquals(listOf("example.com", "api.example.com"), invite.domains)
        assertEquals("https://relay.example.com", invite.relay)
        assertEquals("client-001", invite.totp?.clientId)
        assertEquals("NexaPipe", invite.totp?.issuer)
        assertEquals("sha256", invite.totp?.algorithm)
        assertEquals(30, invite.totp?.period)
    }

    @Test
    fun warns_about_parameters_the_client_drops() {
        assertNull(invite().warnings().takeIf { it.isNotEmpty() })

        val odd = invite().copy(
            totp = invite().totp!!.copy(digits = 8, period = 60)
        )
        assertEquals(2, odd.warnings().size)
        assertTrue(odd.warnings().first().contains("8 digits"))
    }

    /**
     * A parameter's *name* is matched without its case.
     *
     * The name decides whether a parameter is read at all, and a parameter
     * that is not read is an unknown one — and unknown parameters are
     * dropped. So `Secret=…` used to be dropped whole: the code imported as
     * an endpoint with no second factor, while the desktop app reading the
     * same code kept the credential and authenticated with it. The Rust
     * parser folds the name too, and the two have to agree.
     */
    @Test
    fun a_parameter_name_is_matched_without_its_case() {
        val uri = "${bare()}&Secret=JBSWY3DPEHPK3PXP&client=client-001"
        val invite = success(uri)
        assertEquals("client-001", invite.totp?.clientId)
        assertEquals("JBSWY3DPEHPK3PXP", invite.totp?.secret)
    }

    /**
     * A malformed escape sequence is refused rather than kept as a literal
     * `%`.
     *
     * It used to be kept, so a code the desktop app refused imported here as
     * an endpoint with a name of `%ZZ` in it.
     */
    @Test
    fun refuses_a_malformed_escape_sequence() {
        val message = failure("${bare()}&name=%ZZ")
        assertTrue(message, message.contains("escape sequence"))
    }

    /**
     * Bytes that are not UTF-8 are refused rather than turned into
     * replacement characters.
     *
     * They used to be substituted, so the same code named an endpoint on the
     * desktop and named something else here.
     */
    @Test
    fun refuses_a_code_that_is_not_utf8() {
        val message = failure("${bare()}&name=%C3%28")
        assertTrue(message, message.contains("UTF-8"))
    }

    /** A parameter with no name is a malformed one, and the code is refused. */
    @Test
    fun refuses_a_parameter_with_no_name() {
        val message = failure("${bare()}&=x")
        assertTrue(message, message.contains("malformed parameter"))
    }

    /**
     * A code past the hard limit is refused rather than parsed.
     *
     * The Rust parser refuses one too, and parsing it is work an attacker
     * gets for free.
     */
    @Test
    fun refuses_a_code_past_the_hard_limit() {
        val uri = "${bare()}&name=${"a".repeat(5000)}"
        val message = failure(uri)
        assertTrue(message, message.contains("past the"))
    }

    /** A bare invite, with no optional fields set. */
    private fun bare(): String = "nexapipe://endpoint/$nodeId?v=1"
}
