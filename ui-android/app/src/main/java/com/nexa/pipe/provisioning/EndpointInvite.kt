package com.nexa.pipe.provisioning

import java.io.ByteArrayOutputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Locale

/**
 * Where an invite points: either a stable Node ID, which needs discovery to
 * become an address, or a ticket that already carries addresses.
 */
sealed class InviteTarget {
    data class NodeId(val id: String) : InviteTarget()
    data class Ticket(val ticket: String) : InviteTarget()

    val value: String
        get() = when (this) {
            is NodeId -> id
            is Ticket -> ticket
        }

    val kind: String
        get() = when (this) {
            is NodeId -> "Node ID"
            is Ticket -> "ticket"
        }
}

/**
 * The 2FA half of an invite.
 *
 * The native client always derives 6-digit codes over a 30-second step, so
 * [digits] and [period] are reported (and warned about) rather than honored.
 */
data class InviteTotp(
    val issuer: String,
    val clientId: String,
    val secret: String,
    val algorithm: String,
    val digits: Int,
    val period: Int
)

/**
 * A one-time enrollment token, in place of [InviteTotp].
 *
 * The token is not a credential: it is spent on the first connection, which
 * answers with the TOTP secret this device is to keep and rotates the one the
 * server held. So a code carrying a token is a code that stops working the
 * moment it has been used — and what it buys has to be written down, because a
 * token cannot be spent twice and an app that forgets the secret cannot enroll
 * again from the same code.
 */
data class InviteEnrollment(
    val clientId: String,
    val token: String
)

/** A complete endpoint invitation. */
data class EndpointInvite(
    val target: InviteTarget,
    val name: String?,
    val domains: List<String>,
    val relay: String?,
    val totp: InviteTotp?,
    /**
     * A one-time token to spend instead of presenting credentials. Never set
     * together with [totp]: an invite hands out one or the other.
     */
    val enrollment: InviteEnrollment? = null
) {

    /** Whether this invite enrolls rather than handing out a secret. */
    fun isEnrollment(): Boolean = enrollment != null
    /** Non-fatal issues to surface right after an import. */
    fun warnings(): List<String> {
        val otp = totp ?: return emptyList()
        val digits = EndpointInviteCodec.DEFAULT_DIGITS
        val period = EndpointInviteCodec.DEFAULT_PERIOD
        return buildList {
            if (otp.digits != digits) {
                add("This invite asks for ${otp.digits} digits, but NexaPipe generates $digits.")
            }
            if (otp.period != period) {
                add("This invite uses a ${otp.period}-second step, but NexaPipe uses $period seconds.")
            }
        }
    }

    /** Renders the canonical `nexapipe://` link; [EndpointInviteCodec.parse] reads it back. */
    fun toUri(): String = EndpointInviteCodec.build(this)
}

/** Outcome of [EndpointInviteCodec.parse]. */
sealed interface InviteParseResult {
    data class Success(val invite: EndpointInvite) : InviteParseResult
    data class Failure(val message: String) : InviteParseResult
}

/**
 * Reads and writes `nexapipe://` endpoint invitations.
 *
 * ```text
 * nexapipe://endpoint/<node-id>?v=1&name=Home&domains=a.example,b.example
 *     &relay=https%3A%2F%2Frelay.example
 *     &client=client-001&issuer=NexaPipe&secret=JBSWY3DPEHPK3PXP
 *     &algorithm=SHA1&digits=6&period=30
 * ```
 *
 * `endpoint` carries a bare Node ID and `ticket` a full endpoint ticket; the
 * rest is shared. Values are percent encoded (everything outside the RFC 3986
 * unreserved set plus the list separator `,`), `+` stays literal, unknown
 * parameters are ignored so newer servers can extend the format, and a repeated
 * parameter keeps its first occurrence.
 *
 * A parameter's *name* is matched without its case, so a code that carries a
 * credential under a differently-cased name keeps it: an unmatched name is an
 * unknown parameter, and unknown parameters are dropped.
 *
 * A malformed escape sequence, bytes that are not UTF-8, a parameter with no
 * name and a code past the hard limit are all refused. The Rust parser
 * refuses them too, and the two halves have to accept and reject the same
 * codes — one of them writes what the other reads.
 *
 * `v=2` is the enrollment form: it carries `enroll=<token>` instead of the
 * `secret=` block, and is a version of its own so that a v=1 reader refuses it
 * rather than importing it as an endpoint with no credentials.
 *
 * This mirrors `nexapipe_client::provisioning` in the Rust client library; both
 * must accept and reject the same codes.
 */
object EndpointInviteCodec {
    const val SCHEME = "nexapipe"
    const val VERSION = 1
    /**
     * The version an invite carrying an enrollment token is written as.
     *
     * Its own version rather than a new parameter in `v=1`, because an app that
     * only knows v=1 ignores parameters it does not recognise: it would read a
     * registration code as an ordinary endpoint share whose credentials simply
     * went missing, which looks like a successful import that cannot connect.
     */
    const val ENROLLMENT_VERSION = 2
    const val NODE_ID_HOST = "endpoint"
    const val TICKET_HOST = "ticket"
    const val DEFAULT_ISSUER = "NexaPipe"
    const val DEFAULT_ALGORITHM = "sha1"
    const val DEFAULT_DIGITS = 6
    const val DEFAULT_PERIOD = 30

    /** Code length range the Rust client's `InviteTotp::with_params` enforces. */
    const val MIN_DIGITS = 6
    const val MAX_DIGITS = 8

    /**
     * The hard limit on an invite code, in bytes.
     *
     * The same limit the Rust client's `MAX_URI_LEN` applies: past roughly
     * this length a code is not one anybody will read, and parsing it is work
     * an attacker gets for free.
     */
    const val MAX_URI_LEN = 4 * 1024

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val SUPPORTED_ALGORITHMS = listOf("sha1", "sha256", "sha512")
    private val NODE_ID_PATTERN = Regex("[0-9a-fA-F]{64}")

    /** All iroh `RelayUrl` accepts is absolute http(s); ws/wss are the same servers. */
    private val RELAY_SCHEMES = setOf("http", "https", "ws", "wss")

    /** Parses a scanned or pasted invite. Never throws. */
    fun parse(raw: String): InviteParseResult {
        val trimmed = raw.trim()
        // A code past the hard limit is not a code anybody will read, and
        // parsing it is work an attacker gets for free. The Rust parser
        // refuses one too, and the two have to agree — so this counts bytes,
        // not characters.
        val bytes = trimmed.toByteArray(Charsets.UTF_8).size
        if (bytes > MAX_URI_LEN) {
            return failure("The invite code is $bytes bytes, past the $MAX_URI_LEN byte limit")
        }
        val prefix = "$SCHEME://"
        if (!trimmed.startsWith(prefix, ignoreCase = true)) {
            return failure("Not a $SCHEME:// invite code")
        }

        val body = trimmed.substring(prefix.length).substringBefore('#')
        val queryStart = body.indexOf('?')
        val path = if (queryStart >= 0) body.substring(0, queryStart) else body
        val query = if (queryStart >= 0) body.substring(queryStart + 1) else ""

        val slash = path.indexOf('/')
        val host = (if (slash >= 0) path.substring(0, slash) else path).trim()
        val rawValue = if (slash >= 0) path.substring(slash + 1) else ""
        // One empty segment is tolerated: links typed into a browser-like field
        // often come back as `.../<node-id>/?v=1`.
        val value = percentDecode(rawValue.trimEnd('/')).getOrElse { return failure(it.message.orEmpty()) }

        val target = when {
            host.equals(NODE_ID_HOST, ignoreCase = true) -> {
                if (!NODE_ID_PATTERN.matches(value)) {
                    return failure("\"$value\" is not a Node ID (64 hex characters)")
                }
                InviteTarget.NodeId(value.lowercase(Locale.ROOT))
            }
            host.equals(TICKET_HOST, ignoreCase = true) -> {
                if (value.isEmpty()) return failure("The invite carries no endpoint ticket")
                InviteTarget.Ticket(value)
            }
            else -> return failure("Unknown invite kind \"$host\"; expected endpoint or ticket")
        }

        val params = parseQuery(query).getOrElse { return failure(it.message.orEmpty()) }
        val version = params["v"]?.trim()?.toIntOrNull()
        if (params["v"] != null && version == null) {
            return failure("Invite version \"${params["v"]}\" is not a number")
        }
        val isEnrollmentVersion = version == ENROLLMENT_VERSION
        if (version != null && version != VERSION && !isEnrollmentVersion) {
            return failure("Unsupported invite version $version (this app understands $VERSION and $ENROLLMENT_VERSION)")
        }

        val domains = splitDomains(params["domains"] ?: "")?.let(::normalizeDomains)
            ?: return failure("The domain list contains an invalid entry")

        val relay = params["relay"]?.trim()?.takeIf { it.isNotEmpty() }?.also {
            if (!isValidRelayUrl(it)) {
                // "invalid" is part of the message on purpose: this is the same
                // wording the Rust half uses, and both test suites assert on it.
                return failure("The relay URL \"$it\" is invalid: it is not an http(s) URL")
            }
        }
        val name = params["name"]?.trim()?.takeIf { it.isNotEmpty() }

        val otp = parseTotp(params).getOrElse { return failure(it.message.orEmpty()) }
        val enrollment = parseEnrollment(params, version)
            .getOrElse { return failure(it.message.orEmpty()) }
        return InviteParseResult.Success(
            EndpointInvite(
                target = target,
                name = name,
                domains = domains,
                relay = relay,
                totp = otp,
                enrollment = enrollment
            )
        )
    }

    /** Builds an invite link; [parse] reads it back unchanged. */
    fun build(invite: EndpointInvite): String {
        val version = if (invite.enrollment != null) ENROLLMENT_VERSION else VERSION
        val params = mutableListOf("v" to version.toString())
        invite.name?.takeIf { it.isNotBlank() }?.let { params += "name" to it }
        if (invite.domains.isNotEmpty()) params += "domains" to invite.domains.joinToString(",")
        invite.relay?.let { params += "relay" to it }
        invite.enrollment?.let { enrollment ->
            params += "client" to enrollment.clientId
            params += "enroll" to enrollment.token
        }
        invite.totp?.let { otp ->
            params += "client" to otp.clientId
            params += "issuer" to otp.issuer
            params += "secret" to otp.secret
            params += "algorithm" to otp.algorithm.uppercase(Locale.ROOT)
            params += "digits" to otp.digits.toString()
            params += "period" to otp.period.toString()
        }

        val query = params.joinToString("&") { (key, value) -> "$key=${percentEncode(value)}" }
        val host = when (invite.target) {
            is InviteTarget.NodeId -> NODE_ID_HOST
            is InviteTarget.Ticket -> TICKET_HOST
        }
        return "$SCHEME://$host/${percentEncode(invite.target.value)}?$query"
    }

    /**
     * Reads the 2FA block, if the invite has one.
     *
     * The failure variant carries the message to show, which is why the result
     * is a [Result] rather than a nullable value.
     */
    private fun parseTotp(params: Map<String, String>): Result<InviteTotp?> {
        val secret = params["secret"]
        if (secret == null) {
            // A nested otpauth:// URI is the interop form: it carries the same
            // fields under their standard names.
            val embedded = params["otpauth"]
                ?: return if (params["enroll"] == null &&
                    listOf("client", "issuer", "algorithm", "digits", "period").any { it in params }
                ) {
                    // An enrollment is the one shape that legitimately carries a
                    // client id without a secret.
                    Result.failure(invalid("The invite carries 2FA parameters but no secret"))
                } else {
                    Result.success(null)
                }
            return parseEmbeddedOtpauth(embedded)
        }
        if (params["client"].isNullOrBlank()) {
            return Result.failure(invalid("The invite carries a 2FA secret but no client id"))
        }

        val algorithm = params["algorithm"]?.trim().orEmpty().ifEmpty { DEFAULT_ALGORITHM }
        if (algorithm.lowercase(Locale.ROOT) !in SUPPORTED_ALGORITHMS) {
            return Result.failure(
                invalid("Unsupported algorithm \"${params["algorithm"]}\"; expected SHA1, SHA256 or SHA512")
            )
        }
        val normalized = normalizeSecret(secret)
            ?: return Result.failure(invalid("The 2FA secret is not a valid Base32 string"))
        val digits = readInt(params["digits"], DEFAULT_DIGITS)
            ?: return Result.failure(invalid("Invalid digits value \"${params["digits"]}\""))
        if (digits !in MIN_DIGITS..MAX_DIGITS) {
            return Result.failure(
                invalid("This invite asks for $digits digits per code, but only $MIN_DIGITS to $MAX_DIGITS are supported")
            )
        }
        val period = readInt(params["period"], DEFAULT_PERIOD)
            ?: return Result.failure(invalid("Invalid period value \"${params["period"]}\""))

        return Result.success(
            InviteTotp(
                issuer = params["issuer"]?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_ISSUER,
                clientId = params["client"]!!.trim(),
                secret = normalized,
                algorithm = algorithm.lowercase(Locale.ROOT),
                digits = digits,
                period = period
            )
        )
    }

    /**
     * Reads the enrollment block, if the invite has one.
     *
     * `enroll` in a v=1 code is refused rather than ignored: the rule that
     * unknown parameters are dropped would otherwise turn a registration code
     * into an endpoint share with no credentials, which imports successfully and
     * then never connects.
     */
    private fun parseEnrollment(
        params: Map<String, String>,
        version: Int?
    ): Result<InviteEnrollment?> {
        val token = params["enroll"] ?: return Result.success(null)
        if (version != null && version < ENROLLMENT_VERSION) {
            return Result.failure(
                invalid("The invite carries an enrollment token but is version $version")
            )
        }
        // Both spellings: `otpauth` carries a secret of its own and is only
        // consulted when `secret` is absent, so checking `secret` alone lets
        // `?enroll=…&otpauth=otpauth://…` through as an invite that both has a
        // credential and is about to be issued one. Keep this in step with
        // `enrollment_from_params` in the client crate.
        if (params["secret"] != null || params["otpauth"] != null) {
            return Result.failure(
                invalid("The invite carries both an enrollment token and a 2FA secret")
            )
        }
        val clientId = params["client"]?.trim().orEmpty()
        if (clientId.isEmpty()) {
            return Result.failure(
                invalid("The invite carries an enrollment token but no client id")
            )
        }
        if (token.trim().isEmpty()) {
            return Result.failure(invalid("The enrollment token is empty"))
        }
        return Result.success(InviteEnrollment(clientId, token.trim()))
    }

    private fun invalid(message: String) = IllegalArgumentException(message)

    /**
     * A relay must be an absolute `http(s)` URL with a host — anything else is
     * rejected by iroh's `RelayUrl` at connect time, so it is rejected here
     * with a message instead of a silent failure. `URI` (not `URL`) because
     * the `URL` constructor has no handlers for `ws`/`wss`.
     */
    private fun isValidRelayUrl(raw: String): Boolean {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return false
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return false
        if (scheme !in RELAY_SCHEMES) return false
        return !uri.host.isNullOrBlank()
    }

    private fun parseEmbeddedOtpauth(uri: String): Result<InviteTotp?> {
        val trimmed = uri.trim()
        val prefix = "otpauth://"
        if (!trimmed.startsWith(prefix, ignoreCase = true)) {
            return Result.failure(invalid("The embedded otpauth parameter is not an otpauth:// URI"))
        }
        val rest = trimmed.substring(prefix.length)
        val queryStart = rest.indexOf('?')
        val path = if (queryStart >= 0) rest.substring(0, queryStart) else rest
        val query = if (queryStart >= 0) rest.substring(queryStart + 1) else ""

        // `otpauth://totp/Issuer:client?...` — the type segment sits in front
        // of the label.
        val label = percentDecode(path.substringAfterLast('/')).getOrElse { return Result.failure(it) }
        val (labelIssuer, clientId) = label.indexOf(':').let { colon ->
            if (colon >= 0) {
                label.substring(0, colon).trim() to label.substring(colon + 1).trim()
            } else {
                null to label.trim()
            }
        }
        if (clientId.isEmpty()) {
            return Result.failure(invalid("The embedded otpauth:// URI does not contain a client id"))
        }

        val params = parseQuery(query).getOrElse { return Result.failure(it) }
        val secret = params["secret"]
            ?: return Result.failure(invalid("The embedded otpauth:// URI carries no secret"))
        return parseTotp(
            mapOf(
                "client" to clientId,
                "issuer" to (labelIssuer?.takeIf { it.isNotEmpty() }
                    ?: params["issuer"]?.takeIf { it.isNotBlank() }
                    ?: DEFAULT_ISSUER),
                "secret" to secret,
                "algorithm" to params["algorithm"].orEmpty(),
                "digits" to params["digits"].orEmpty(),
                "period" to params["period"].orEmpty()
            )
        )
    }

    /** Returns null when the list is malformed: an empty entry means a mistyped code. */
    private fun splitDomains(raw: String): List<String>? {
        if (raw.isBlank()) return emptyList()
        val parts = raw.split(',')
        if (parts.any { it.trim().isEmpty() }) return null
        return parts.map { it.trim() }
    }

    /** Returns null when any entry is not a pattern this client can match with. */
    private fun normalizeDomains(domains: List<String>): List<String>? {
        val out = LinkedHashSet<String>()
        for (raw in domains) {
            val domain = normalizePattern(raw.trim())
            if (domain.isEmpty()) return null
            if (domain.any { it.isWhitespace() || it == '/' || it == '?' || it == '#' }) return null
            out += domain
        }
        return out.toList()
    }

    /**
     * The folded form of a pattern, mirroring `nexapipe_proto::normalize_pattern`.
     *
     * The case is folded and the trailing dots and the brackets are taken off —
     * but not when taking them off would leave the catch-all. `*.`, `*..` and
     * `[*]` all fold to `*`, and a pattern that means "every host" where the
     * invite said something narrower is the one mistake this must not make:
     * folded into `*`, it would hand the client the catch-all and the client
     * would proxy every host. Kept in its own shape, it matches nothing.
     */
    private fun normalizePattern(pattern: String): String {
        val folded = pattern.trimEnd('.').trim { it == '[' || it == ']' }.lowercase(Locale.ROOT)
        if (folded == "*" && pattern != "*") {
            // The fold would have widened it into the catch-all.
            return pattern.lowercase(Locale.ROOT)
        }
        return folded
    }

    /** Uppercase Base32 without padding, or null when the input is not Base32. */
    private fun normalizeSecret(raw: String): String? {
        val cleaned = raw.filterNot { it.isWhitespace() || it == '=' }.uppercase(Locale.ROOT)
        if (cleaned.isEmpty() || cleaned.length < 8) return null
        if (cleaned.any { it !in BASE32_ALPHABET }) return null
        return cleaned
    }

    private fun readInt(value: String?, fallback: Int): Int? {
        val trimmed = value?.trim().orEmpty()
        if (trimmed.isEmpty()) return fallback
        val parsed = trimmed.toIntOrNull() ?: return null
        return if (parsed > 0) parsed else null
    }

    private fun parseQuery(query: String): Result<Map<String, String>> {
        if (query.isEmpty()) return Result.success(emptyMap())
        val params = mutableMapOf<String, String>()
        for (part in query.split('&')) {
            if (part.isEmpty()) continue
            val equals = part.indexOf('=')
            val key = percentDecode(if (equals >= 0) part.substring(0, equals) else part)
                .getOrElse { return Result.failure(it) }
                .lowercase(Locale.ROOT)
            // A parameter with no name is a malformed one, and the Rust parser
            // refuses the whole code over it. Silently dropping it here is how
            // the two parsers came to disagree about the same code.
            if (key.isEmpty()) {
                return Result.failure(invalid("The invite code has a malformed parameter"))
            }
            val value = if (equals >= 0) {
                percentDecode(part.substring(equals + 1)).getOrElse { return Result.failure(it) }
            } else {
                ""
            }
            // First occurrence wins, as in the Rust parser.
            if (!params.containsKey(key)) params[key] = value
        }
        return Result.success(params)
    }

    /** Keeps the unreserved characters plus the list separator readable. */
    private fun percentEncode(value: String): String {
        val out = StringBuilder(value.length)
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            val char = byte.toInt().toChar()
            val keep = char.isLetterOrDigit() || char == '-' || char == '.' || char == '_' ||
                char == '~' || char == ','
            if (keep) out.append(char) else out.append('%').append(String.format("%02X", byte.toInt() and 0xFF))
        }
        return out.toString()
    }

    /**
     * The inverse of [percentEncode]; `+` stays literal.
     *
     * A malformed escape and a byte sequence that is not UTF-8 are both
     * refused, because the Rust parser refuses them and the two halves have to
     * agree about which codes are codes. Keeping a broken escape as a literal
     * `%` used to be what this did, and it made a code the desktop app
     * rejected import here as an endpoint with a name of `%ZZ` in it.
     */
    private fun percentDecode(value: String): Result<String> {
        val bytes = ByteArrayOutputStream(value.length)
        var index = 0
        while (index < value.length) {
            val char = value[index]
            if (char == '%') {
                val hex = if (index + 3 <= value.length) {
                    value.substring(index + 1, index + 3)
                } else {
                    return Result.failure(invalid("The invite code has a truncated escape sequence"))
                }
                val code = hex.toIntOrNull(16)
                    ?: return Result.failure(invalid("The invite code has a malformed escape sequence"))
                bytes.write(code)
                index += 3
                continue
            }
            val encoded = char.toString().toByteArray(Charsets.UTF_8)
            bytes.write(encoded, 0, encoded.size)
            index++
        }
        // Decoded strictly: a byte sequence that is not UTF-8 is refused
        // rather than turned into replacement characters, which is what
        // `String(bytes, UTF_8)` does and what the Rust parser does not do.
        return try {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            Result.success(decoder.decode(ByteBuffer.wrap(bytes.toByteArray())).toString())
        } catch (e: CharacterCodingException) {
            Result.failure(invalid("The invite code is not valid UTF-8"))
        }
    }

    private fun failure(message: String) = InviteParseResult.Failure(message)
}
