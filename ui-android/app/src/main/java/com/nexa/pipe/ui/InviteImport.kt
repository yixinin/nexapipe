package com.nexa.pipe.ui

import android.content.Context
import android.widget.Toast
import com.nexa.pipe.R
import com.nexa.pipe.provisioning.EndpointInvite

/**
 * Applies a scanned endpoint invite: the node, its domains, the relay it
 * asks for and the 2FA credentials of that endpoint.
 *
 * Returns the message to show when the invite cannot be applied at all.
 *
 * [context] is the real context — the Toast is shown with it — and
 * [localizedContext] is the locale-wrapped one, which is where the strings
 * are read from.
 */
internal fun applyInviteImport(
    viewModel: VpnViewModel,
    setup: InviteSetup,
    context: Context,
    localizedContext: Context,
    invite: EndpointInvite
): String? {
    val nodeId = inviteNodeId(invite)
        // A ticket bundles addresses the node list has no room for. The
        // server can hand out a Node ID invite instead.
        ?: return localizedContext.getString(R.string.invite_ticket_unsupported)

    if (setup.nodes.none { it.nodeId == nodeId }) {
        viewModel.addNode(nodeId)?.let { return it }
    }
    if (invite.domains.isEmpty()) {
        viewModel.addLog("Invite for ${nodeId.take(8)} carried no domains")
    }
    invite.domains.forEach { viewModel.addDomainToNode(nodeId, it) }
    // The relay is global, so an invite only proposes one: it says how
    // *that* endpoint is reachable, not what this phone should use. The
    // change is listed by `inviteConflicts`, which is what puts the
    // confirmation dialog in front of it — a relay that would actually be
    // overwritten is never applied silently.
    //
    // The invite carries no token for the relay it names, so the token
    // this phone holds goes with the import rather than travelling to a
    // relay of the invite's choosing.
    invite.relay?.let { relay ->
        viewModel.updateRelayConfig("custom", relay, RelayTokenChange.Drop)
    }
    invite.totp?.let { otp ->
        viewModel.updateNodeTwoFactor(
            nodeId,
            NodeTwoFactor(
                enabled = true,
                clientId = otp.clientId,
                secret = otp.secret,
                algorithm = otp.algorithm
            )
        )
        // A token is not a credential, so an invite that hands one over
        // leaves this endpoint with none until it has been spent.
        viewModel.updateNodeEnrollment(nodeId, null)
        invite.warnings().forEach { viewModel.addLog("Invite import: $it") }
        invite.warnings().firstOrNull()?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
        }
    }
    // An enrollment invite spends its token on the next connect, which is
    // also when the credentials arrive — so the token itself is the only
    // thing written here.
    //
    // The credential this endpoint holds now goes with it, because what
    // comes back replaces it: the server issues a fresh one and the old
    // secret stops being a credential. That is a replacement of something
    // that works, so `inviteConflicts` names it and the confirmation stands
    // in front of it.
    invite.enrollment?.let { enrollment ->
        viewModel.updateNodeEnrollment(
            nodeId,
            NodeEnrollment(clientId = enrollment.clientId, token = enrollment.token)
        )
        viewModel.updateNodeTwoFactor(nodeId, null)
    }
    // No client id in the log: debug builds expose Log.d, and the id is
    // half of the 2FA credential pair. What kind of credential arrived is
    // what the line is about.
    val credential = when {
        invite.totp != null -> "totp"
        invite.enrollment != null -> "enrollment"
        else -> "none"
    }
    viewModel.addLog(
        "Imported invite: node=${nodeId.take(8)} domains=${invite.domains.size} 2FA=$credential"
    )
    Toast.makeText(
        context,
        localizedContext.getString(R.string.invite_imported, invite.name ?: nodeId.take(8)),
        Toast.LENGTH_SHORT
    ).show()
    return null
}
