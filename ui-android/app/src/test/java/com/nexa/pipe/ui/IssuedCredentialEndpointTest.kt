package com.nexa.pipe.ui

import com.nexa.pipe.ui.NodeConfig
import com.nexa.pipe.ui.NodeEnrollment
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Which endpoint an issued credential belongs to.
 *
 * The credential names the client it was issued for, and the client refuses
 * an answer that names a different one, so the client id is the whole of the
 * match.
 *
 * The case this pins is two endpoints enrolling at once and a credential
 * that belongs to neither of them by name. Filing it under the first
 * endpoint that happened to be enrolling hands that endpoint a credential
 * the server never issued to it, and leaves the endpoint the credential was
 * issued for holding a token the server has already spent. Both then fail
 * closed and both have to enrol again — a far worse outcome than dropping
 * the credential.
 */
class IssuedCredentialEndpointTest {

    private fun node(nodeId: String, clientId: String?): NodeConfig = NodeConfig(
        nodeId = nodeId,
        enrollment = clientId?.let { NodeEnrollment(clientId = it, token = "token") }
    )

    @Test
    fun a_credential_goes_to_the_endpoint_that_enrolled_with_its_client_id() {
        val nodes = listOf(
            node("node-a", "client-a"),
            node("node-b", "client-b")
        )

        assertEquals("node-a", endpointForIssuedCredential(nodes, "client-a")?.nodeId)
        assertEquals("node-b", endpointForIssuedCredential(nodes, "client-b")?.nodeId)
    }

    @Test
    fun a_credential_that_names_no_endpoint_is_not_filed_under_one() {
        val nodes = listOf(
            node("node-a", "client-a"),
            node("node-b", "client-b")
        )

        assertNull(
            "a credential for an unknown client id belongs to no endpoint",
            endpointForIssuedCredential(nodes, "client-c")
        )
    }

    @Test
    fun an_endpoint_that_is_not_enrolling_is_never_the_one() {
        val nodes = listOf(
            node("node-a", null),
            node("node-b", "client-b")
        )

        assertNull(endpointForIssuedCredential(nodes, "client-a"))
        assertEquals("node-b", endpointForIssuedCredential(nodes, "client-b")?.nodeId)
    }
}
