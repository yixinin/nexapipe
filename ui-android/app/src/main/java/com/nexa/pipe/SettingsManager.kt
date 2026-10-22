package com.nexa.pipe

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import androidx.core.content.edit
import com.nexa.pipe.ui.NodeConfig
import com.nexa.pipe.ui.NodeTwoFactor
import com.nexa.pipe.vpn.VpnTakeoverChoice
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString

// The tag the app's own log lines carry. At the file level rather than in the
// companion, because the migration below is a function of its own and logs
// under the same tag.
private const val TAG = "SettingsManager"

class SettingsManager internal constructor(
    private val prefs: SharedPreferences,
    // 2FA secrets live in their own prefs file so backup rules can exclude
    // them as a whole; a TOTP seed must never leave the device. The endpoint
    // list itself *is* backed up, so every secret is pulled out of it on save
    // and kept here under its own endpoint ID instead.
    private val secretPrefs: SharedPreferences,
    // Every credential written to `secretPrefs` goes through this, so the file
    // holds ciphertext even though it is a plain preferences file.
    private val secrets: SecretStore
) {
    constructor(context: Context) : this(
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
        context.getSharedPreferences("NexaPipeSecrets", Context.MODE_PRIVATE),
        SecretStore()
    )

    private val json = Json { ignoreUnknownKeys = true }

    init {
        migrateLegacyTwoFactor()
        migrateRelayAuthToken()
        migrateSecretsAtRest()
    }

    companion object {
        const val PREFS_NAME = "NexaPipeSettings"
        const val KEY_NODES = "nodes"
        const val KEY_RELAY_MODE = "relay_mode"
        const val KEY_RELAY_URL = "relay_url"
        // Whether this endpoint may use n0's address lookup — the DNS and pkarr
        // queries that turn a Node ID into an address. "n0" (the default) keeps
        // it; "none" switches it off, and a peer then has to bring an address of
        // its own (a ticket) to be reachable.
        const val KEY_DISCOVERY_MODE = "discovery_mode"
        // The relay bearer token. Kept in `secretPrefs`, not `prefs`: the relay
        // is handed it verbatim, so it is a credential like the TOTP seeds, and
        // only the secrets file is excluded from cloud backup and device
        // transfer. Left in `prefs` it rode the very backup that is careful not
        // to take the seeds.
        const val KEY_RELAY_AUTH_TOKEN = "relay_auth_token"
        // Prefix of the per-endpoint secret entries in `secretPrefs`.
        const val SECRET_PREFIX = "two_factor_secret_"
        // Prefix of the per-endpoint enrollment tokens. A token is a credential
        // too — it is what a registration invite hands out — so it is kept out
        // of the backed-up list alongside the secrets.
        const val ENROLLMENT_PREFIX = "enrollment_token_"
        // Prefix of the per-endpoint device keys: the private half of the
        // Ed25519 key an endpoint proves itself with.
        //
        // A credential like the seeds beside it, and kept in the same file
        // because that file is the one backup excludes — but a stronger one: a
        // seed is a copy of something the server holds, while this half is
        // the only one there is. It never appears in the backed-up endpoint
        // list, and it never leaves the device.
        const val DEVICE_KEY_PREFIX = "device_key_"
        // Read once by `migrateLegacyTwoFactor` and then deleted: 2FA used to
        // be one app-wide setting, it now belongs to an endpoint.
        const val KEY_2FA_ENABLED = "two_factor_enabled"
        const val KEY_2FA_CLIENT_ID = "two_factor_client_id"
        const val KEY_2FA_SECRET = "two_factor_secret"
        const val KEY_2FA_ALGORITHM = "two_factor_algorithm"
        const val KEY_2FA_MIGRATED = "two_factor_migrated"

        /**
         * The name this install answers as when it authenticates.
         *
         * It lives in [secretPrefs] rather than the backed-up file: it names
         * *this* device, and a configuration restored onto another phone must
         * not turn up claiming to be the one it was copied from. Sealed like
         * the credentials beside it, because that file being ciphertext
         * throughout is the property its exclusion from backups rests on —
         * the name itself is not a secret.
         */
        const val KEY_DEVICE_ID = "device_id"

        // Language tag of the app UI, e.g. "zh-CN". Empty means "follow the
        // system", which is the default.
        private const val KEY_LANGUAGE = "app_language"

        // What the user chose the last time another VPN app owned the slot:
        // "take_over" or "cancel". Absent means "ask every time", which is the
        // default — a remembered choice is only written when one was made.
        private const val KEY_VPN_TAKEOVER_CHOICE = "vpn_takeover_choice"

        /**
         * Whether this device was ever allowed to store a credential in the
         * clear.
         *
         * In `prefs` and not `secretPrefs`: it is a decision, not a secret,
         * and a file that must never hold anything readable is no place to
         * keep the answer to "may this file hold something readable".
         */
        private const val KEY_PLAINTEXT_CONSENT = "plaintext_credential_consent"

        /**
         * Whether the tunnel should come back on its own after a restart.
         *
         * Off by default: an app that reconnects without being asked is an app
         * that forwards traffic without being asked, and the user who wants
         * that has to say so.
         */
        const val KEY_AUTO_CONNECT_ON_BOOT = "auto_connect_on_boot"

        /**
         * Whether the VPN permission was found to be missing at boot.
         *
         * Android does not promise that the permission a VPN app was given
         * survives a restart, so the boot path asks rather than assumes. When
         * it finds the permission gone it records that here, and the app says
         * so — a tunnel that did not come back needs a reason the user can act
         * on, and "the machine forgot" is not one.
         */
        const val KEY_VPN_CONSENT_MISSING = "vpn_consent_missing"

        /**
         * The saved language tag, or "" for "follow the system".
         *
         * A static read on purpose: `attachBaseContext` needs it before a
         * [SettingsManager] — and its 2FA migration — would be worth building.
         */
        @JvmStatic
        fun loadLanguage(context: Context): String =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_LANGUAGE, "") ?: ""

        @JvmStatic
        fun saveLanguage(context: Context, languageTag: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_LANGUAGE, languageTag)
                .apply()
        }
    }

    /**
     * Moves the old app-wide 2FA setting onto the endpoints.
     *
     * Such a pair authenticated *every* connection, so the faithful migration
     * is the same credentials on every configured endpoint — from there each
     * one is edited on its own page. Runs at most once. With no endpoint yet
     * there is nothing to attach the credentials to, and they are dropped
     * rather than quietly kept as a setting that still applies to everything.
     */
    private fun migrateLegacyTwoFactor() {
        if (secretPrefs.getBoolean(KEY_2FA_MIGRATED, false)) {
            return
        }
        val legacy = takeLegacyTwoFactor()
        secretPrefs.edit().putBoolean(KEY_2FA_MIGRATED, true).apply()
        if (legacy == null || !legacy.enabled || legacy.clientId.isBlank() || legacy.secret.isBlank()) {
            return
        }
        val nodes = decodeNodes()
        if (nodes.isEmpty()) {
            Log.w(TAG, "Dropped the app-wide 2FA setting: there is no endpoint to attach it to")
            return
        }
        val otp = NodeTwoFactor(
            enabled = true,
            clientId = legacy.clientId,
            secret = legacy.secret,
            algorithm = legacy.algorithm
        )
        saveNodes(nodes.map { node -> node.copy(twoFactor = otp) })
        Log.i(TAG, "Moved the app-wide 2FA setting onto ${nodes.size} endpoint(s)")
    }

    /**
     * Reads the pre-endpoint 2FA setting and deletes it.
     *
     * The oldest versions wrote it to [prefs]; a later migration moved it to
     * [secretPrefs]. Both are checked so an app that skipped a version still
     * gets its credentials migrated.
     */
    private fun takeLegacyTwoFactor(): LegacyTwoFactor? {
        val source = when {
            secretPrefs.contains(KEY_2FA_ENABLED) -> secretPrefs
            prefs.contains(KEY_2FA_ENABLED) -> prefs
            else -> return null
        }
        val legacy = LegacyTwoFactor(
            enabled = source.getBoolean(KEY_2FA_ENABLED, false),
            clientId = source.getString(KEY_2FA_CLIENT_ID, "") ?: "",
            secret = source.getString(KEY_2FA_SECRET, "") ?: "",
            algorithm = source.getString(KEY_2FA_ALGORITHM, "sha1") ?: "sha1"
        )
        source.edit()
            .remove(KEY_2FA_ENABLED)
            .remove(KEY_2FA_CLIENT_ID)
            .remove(KEY_2FA_SECRET)
            .remove(KEY_2FA_ALGORITHM)
            .apply()
        return legacy
    }

    private data class LegacyTwoFactor(
        val enabled: Boolean,
        val clientId: String,
        val secret: String,
        val algorithm: String
    )

    /**
     * Persists the endpoints. The 2FA secret — and any enrollment token — of
     * each endpoint is written to [secretPrefs] and stripped from the list
     * saved in [prefs], so the backed up copy carries the configuration but
     * never a credential.
     *
     * Reports whether every credential it was given is now sealed at rest.
     * A caller that has not established consent for a plaintext write gets
     * `false` and no new secret: the credential stays out of storage rather than
     * going down readable because the keystore failed on the call that
     * happened to be the one writing it. The endpoint list itself is still
     * written — it carries no secret — and a credential that was already stored
     * for that endpoint is left untouched, so a refused write loses the new
     * value and nothing else.
     */
    fun saveNodes(nodes: List<NodeConfig>, allowPlaintext: Boolean = true): Boolean {
        val editor = secretPrefs.edit()
        // A secret outlives its endpoint otherwise: deleting the endpoint
        // would leave the seed behind, and the next endpoint to reuse that ID
        // would inherit it.
        for (key in secretPrefs.all.keys) {
            if (key.startsWith(SECRET_PREFIX)) {
                val nodeId = key.removePrefix(SECRET_PREFIX)
                val otp = nodes.firstOrNull { it.nodeId == nodeId }?.twoFactor
                if (otp == null || otp.secret.isBlank()) {
                    editor.remove(key)
                }
            }
            if (key.startsWith(ENROLLMENT_PREFIX)) {
                val nodeId = key.removePrefix(ENROLLMENT_PREFIX)
                val enrollment = nodes.firstOrNull { it.nodeId == nodeId }?.enrollment
                if (enrollment == null || enrollment.token.isBlank()) {
                    editor.remove(key)
                }
            }
            if (key.startsWith(DEVICE_KEY_PREFIX)) {
                val nodeId = key.removePrefix(DEVICE_KEY_PREFIX)
                val node = nodes.firstOrNull { it.nodeId == nodeId }
                // A key lives with the credential it proves: either the
                // enrollment that is about to spend a token, or the public
                // half the server answered with. Neither means it is stale —
                // the node was cleared, or the invite it was made for is
                // gone.
                val keepsKey = node?.twoFactor?.publicKey != null ||
                    !node?.enrollment?.token.isNullOrBlank()
                if (!keepsKey) {
                    editor.remove(key)
                }
            }
        }

        var allSealed = true
        val persisted = nodes.map { node ->
            val stripped = node.enrollment?.let { enrollment ->
                if (enrollment.token.isBlank()) {
                    null
                } else {
                    // Sealed before anything is written, and a refusal drops the
                    // token instead of writing it: `SecretStore` is asked
                    // whether it can protect this value instead of being asked
                    // to store it and being allowed to answer for itself.
                    val sealed = secrets.sealOrNull(enrollment.token)
                    when {
                        sealed != null -> {
                            editor.putString(ENROLLMENT_PREFIX + node.nodeId, sealed)
                            node.copy(enrollment = enrollment.copy(token = ""))
                        }
                        allowPlaintext -> {
                            allSealed = false
                            editor.putString(
                                ENROLLMENT_PREFIX + node.nodeId,
                                secrets.seal(enrollment.token)
                            )
                            node.copy(enrollment = enrollment.copy(token = ""))
                        }
                        else -> {
                            // Refused: the token is dropped rather than stored
                            // in the clear, so the endpoint keeps whatever it
                            // had and the caller can ask before trying again.
                            allSealed = false
                            node.copy(enrollment = null)
                        }
                    }
                }
            } ?: node
            val otp = stripped.twoFactor
            if (otp == null || otp.secret.isBlank()) {
                stripped
            } else {
                val sealed = secrets.sealOrNull(otp.secret)
                when {
                    sealed != null -> {
                        editor.putString(SECRET_PREFIX + node.nodeId, sealed)
                        stripped.copy(twoFactor = otp.copy(secret = ""))
                    }
                    allowPlaintext -> {
                        allSealed = false
                        editor.putString(SECRET_PREFIX + node.nodeId, secrets.seal(otp.secret))
                        stripped.copy(twoFactor = otp.copy(secret = ""))
                    }
                    else -> {
                        // Refused. Written as switched off rather than left
                        // enabled with no secret: the previous secret for this
                        // endpoint is still in the file, so an enabled-but-
                        // blank record would come back on the next launch
                        // looking like it had kept the credential it never
                        // received. Off says what happened.
                        allSealed = false
                        stripped.copy(twoFactor = otp.copy(secret = "", enabled = false))
                    }
                }
            }
        }
        editor.apply()
        prefs.edit().putString(KEY_NODES, json.encodeToString(persisted)).apply()
        return allSealed
    }

    /**
     * What became of the last credential written to [secretPrefs].
     *
     * [SecretStore.Protection.Sealed] is the only answer that means the file
     * holds ciphertext. The others mean a credential went down as plaintext,
     * which the file being excluded from backups does not make harmless — it
     * only stops it leaving the device. The UI asks, so the user can be told
     * instead of finding out from a backup they assumed was encrypted.
     */
    fun credentialProtection(): SecretStore.Protection = secrets.protection()

    /**
     * Whether credentials written from here on would be sealed at rest.
     *
     * [credentialProtection] says what became of the last one; this says what
     * would become of the next, which is what a caller holding a credential it
     * has not written yet needs in order to ask first rather than report
     * afterwards.
     *
     * A probe and not a promise: it repeats the steps [SecretStore.seal]
     * would take and throws the result away, so the keystore can answer
     * "yes" here and fail there. [saveNodes] and [saveRelayConfig] therefore
     * report what they actually wrote, and a caller that asked first still
     * has to be able to notice a credential going down in the clear.
     */
    fun canProtectCredentials(): Boolean = secrets.canSeal()

    /**
     * Whether storing credentials unencrypted has been agreed to on this
     * device.
     *
     * Remembered rather than asked per credential, so it outlives the process
     * that asked: a device that cannot seal one credential cannot seal the
     * next either, and an answer given once should not be demanded again on
     * every launch.
     */
    fun plaintextCredentialConsent(): Boolean =
        prefs.getBoolean(KEY_PLAINTEXT_CONSENT, false)

    /** Records the answer to [plaintextCredentialConsent] for good. */
    fun savePlaintextCredentialConsent(accepted: Boolean) {
        prefs.edit { putBoolean(KEY_PLAINTEXT_CONSENT, accepted) }
    }

    /**
     * The private half of an endpoint's device key, or empty when it has none.
     *
     * The credential that proves this device to the server, and the only copy
     * there is: the server holds the public half and nobody else holds this
     * one. It is read from the file backup excludes, and it is never written
     * into the endpoint list that is backed up.
     */
    fun deviceKeyFor(nodeId: String): String =
        secrets.unseal(secretPrefs.getString(DEVICE_KEY_PREFIX + nodeId, "") ?: "")

    /**
     * Stores the private half of an endpoint's device key, sealed.
     *
     * Returns whether it was sealed. A key that could not be sealed is not
     * written at all: this half is the credential, and a copy of it in the
     * clear on a device that has just said it cannot protect one is worse than
     * no key — the endpoint then enrolls with a TOTP secret instead, which the
     * server can revoke.
     */
    fun saveDeviceKey(nodeId: String, privateKeyHex: String): Boolean {
        val sealed = secrets.sealOrNull(privateKeyHex) ?: return false
        secretPrefs.edit { putString(DEVICE_KEY_PREFIX + nodeId, sealed) }
        return true
    }

    /** Forgets an endpoint's device key, which is what a cleared credential does. */
    fun clearDeviceKey(nodeId: String) {
        secretPrefs.edit { remove(DEVICE_KEY_PREFIX + nodeId) }
    }

    /**
     * The name this install answers as, generated on first call and then kept.
     *
     * A server can revoke one device of a client — or rate-limit it — only if
     * that device answers with a name of its own, so every install gets one
     * whether or not anything was asked of it.
     *
     * Kept rather than regenerated, because a name that changed between runs
     * would leave the server holding a row for every device this phone has
     * ever claimed to be.
     */
    fun deviceId(): String {
        val saved = secrets.unseal(secretPrefs.getString(KEY_DEVICE_ID, "") ?: "")
        if (saved.isNotBlank()) return saved
        val generated = DeviceName.generate(Build.MODEL)
        secretPrefs.edit { putString(KEY_DEVICE_ID, secrets.seal(generated)) }
        return generated
    }

    /** Loads the endpoints, re-attaching each secret and token from [secretPrefs]. */
    fun loadNodes(): List<NodeConfig> {
        val stored = decodeNodes()
        if (stored.isEmpty()) return stored
        return stored.map { node ->
            val withToken = node.enrollment?.let { enrollment ->
                val token = secrets.unseal(secretPrefs.getString(ENROLLMENT_PREFIX + node.nodeId, ""))
                node.copy(enrollment = enrollment.copy(token = token))
            } ?: node
            val otp = withToken.twoFactor ?: return@map withToken
            val secret = secrets.unseal(secretPrefs.getString(SECRET_PREFIX + node.nodeId, ""))
            withToken.copy(twoFactor = otp.copy(secret = secret))
        }
    }

    /**
     * Moves a relay token that an older version wrote to [prefs] into
     * [secretPrefs].
     *
     * The rule and the file operations are [relayTokenMigration]'s; this is
     * the call of it with this app's files and this device's keystore.
     */
    private fun migrateRelayAuthToken() {
        relayTokenMigration(
            prefs,
            secretPrefs,
            seal = { secrets.sealOrNull(it) },
            unseal = { secrets.unseal(it) }
        )
    }

    /**
     * Encrypts the credentials older versions left in [secretPrefs] as
     * plaintext.
     *
     * Not required for correctness — [loadNodes] reads plaintext values too —
     * but it is what takes the plaintext off the disk, and without it a
     * credential nobody has edited since would stay readable forever.
     *
     * Each value is sealed and read back before it is written, so one that
     * cannot be opened keeps its plaintext instead of becoming an
     * undecryptable blob. A value that could not be sealed at all is left
     * alone, and this runs again on the next start.
     */
    private fun migrateSecretsAtRest() {
        val keys = secretPrefs.all.keys.toList()
        if (keys.isEmpty()) return
        val editor = secretPrefs.edit()
        var sealed = 0
        for (key in keys) {
            if (!isCredentialKey(key)) continue
            val plain = secretPrefs.getString(key, "") ?: ""
            if (plain.isEmpty() || plain.startsWith(SecretStore.MARKER)) continue
            val written = secrets.seal(plain)
            // `seal` hands the value back untouched when it has no key, so
            // this is both the "nothing was encrypted" and the "no key" case.
            if (written == plain) continue
            if (secrets.unseal(written) != plain) {
                Log.e(TAG, "Left $key in plaintext: the sealed value did not read back")
                continue
            }
            editor.putString(key, written)
            sealed++
        }
        if (sealed > 0) {
            editor.apply()
            Log.i(TAG, "Encrypted $sealed stored credential(s)")
        }
    }

    /**
     * Whether [key] names a credential in [secretPrefs].
     *
     * The file also holds non-credentials — the migration flag, for one — and
     * those must stay readable as they are.
     */
    private fun isCredentialKey(key: String): Boolean =
        key == KEY_RELAY_AUTH_TOKEN ||
            key.startsWith(SECRET_PREFIX) ||
            key.startsWith(ENROLLMENT_PREFIX)

    private fun decodeNodes(): List<NodeConfig> {
        val jsonStr = prefs.getString(KEY_NODES, "")
        if (jsonStr.isNullOrEmpty()) {
            return emptyList()
        }
        return try {
            json.decodeFromString<List<NodeConfig>>(jsonStr)
        } catch (e: Exception) {
            Log.w(TAG, "Could not read the saved endpoints: ${e.message}")
            emptyList()
        }
    }

    /**
     * Saves the relay configuration.
     *
     * Reports whether the bearer token is sealed at rest, on the same terms
     * as [saveNodes]: without consent for a plaintext write the token is
     * dropped rather than stored readable, and the mode and URL — which are
     * not secrets — are kept either way.
     */
    fun saveRelayConfig(
        relayMode: String,
        relayUrl: String,
        authToken: String,
        allowPlaintext: Boolean = true
    ): Boolean {
        prefs.edit {
            putString(KEY_RELAY_MODE, relayMode)
            putString(KEY_RELAY_URL, relayUrl)
        }
        // The token is written to the secrets file, and dropped rather than
        // stored blank, for the reasons given at [KEY_RELAY_AUTH_TOKEN].
        if (authToken.isBlank()) {
            secretPrefs.edit { remove(KEY_RELAY_AUTH_TOKEN) }
            // The legacy copy goes with it. The read path falls back to the
            // backed-up preferences, so a token the user has cleared would
            // otherwise come back from there.
            prefs.edit { remove(KEY_RELAY_AUTH_TOKEN) }
            return true
        }
        val sealed = secrets.sealOrNull(authToken)
        if (sealed != null) {
            secretPrefs.edit { putString(KEY_RELAY_AUTH_TOKEN, sealed) }
            return true
        }
        if (!allowPlaintext) {
            // Refused. Whatever token was already stored is left exactly as it
            // was: a write nobody agreed to must not also destroy a credential
            // this device is holding in the clear already or, more likely, as
            // ciphertext. The new one is simply not written.
            return false
        }
        secretPrefs.edit { putString(KEY_RELAY_AUTH_TOKEN, secrets.seal(authToken)) }
        return false
    }

    /** Loads the relay mode; defaults to "pinned" (pinned to aps1-1). */
    fun loadRelayMode(): String {
        return prefs.getString(KEY_RELAY_MODE, "pinned") ?: "pinned"
    }

    /**
     * Saves the discovery mode.
     *
     * Not a credential, so it needs none of the sealing the relay token gets:
     * it says whether this device asks n0 where a peer is, and that is a
     * preference like any other.
     */
    fun saveDiscoveryMode(mode: String) {
        prefs.edit { putString(KEY_DISCOVERY_MODE, mode) }
    }

    /** Loads the discovery mode; defaults to "n0". */
    fun loadDiscoveryMode(): String {
        return prefs.getString(KEY_DISCOVERY_MODE, "n0") ?: "n0"
    }

    /** Loads the custom relay URL. */
    fun loadRelayUrl(): String {
        return prefs.getString(KEY_RELAY_URL, "") ?: ""
    }

    /**
     * Loads the bearer token for the custom relay, if it needs one.
     *
     * The secrets file is where the token lives once it has been sealed; the
     * backed-up preferences are where it lives when this device cannot seal
     * it. Both are read, and the secrets file wins — it is written whenever
     * the token is saved, so it holds the newer of the two.
     */
    fun loadRelayAuthToken(): String {
        return relayTokenRead(
            secretPrefs.getString(KEY_RELAY_AUTH_TOKEN, null),
            prefs.getString(KEY_RELAY_AUTH_TOKEN, null)
        ) { secrets.unseal(it) }
    }

    /**
     * Stores what the user wants done when another VPN app owns the slot.
     *
     * [VpnTakeoverChoice.Ask] removes the key rather than writing "ask": the
     * default is a preference file that does not mention the choice at all, so
     * an app that cannot read a value back is back to asking rather than to a
     * remembered answer nobody remembers making.
     */
    fun saveVpnTakeoverChoice(choice: VpnTakeoverChoice) {
        if (choice == VpnTakeoverChoice.Ask) {
            prefs.edit { remove(KEY_VPN_TAKEOVER_CHOICE) }
        } else {
            prefs.edit { putString(KEY_VPN_TAKEOVER_CHOICE, choice.name) }
        }
    }

    /** Loads the remembered takeover choice; [VpnTakeoverChoice.Ask] by default. */
    fun loadVpnTakeoverChoice(): VpnTakeoverChoice {
        val stored = prefs.getString(KEY_VPN_TAKEOVER_CHOICE, null) ?: return VpnTakeoverChoice.Ask
        return runCatching { VpnTakeoverChoice.valueOf(stored) }
            .getOrDefault(VpnTakeoverChoice.Ask)
    }

    /**
     * Whether the tunnel should come back on its own after a restart.
     *
     * Off until the user says otherwise: a proxy that reconnects on its own
     * forwards traffic on its own.
     */
    fun autoConnectOnBoot(): Boolean = prefs.getBoolean(KEY_AUTO_CONNECT_ON_BOOT, false)

    /** Records whether the tunnel should come back after a restart. */
    fun saveAutoConnectOnBoot(enabled: Boolean) {
        prefs.edit { putBoolean(KEY_AUTO_CONNECT_ON_BOOT, enabled) }
    }

    /**
     * Whether the VPN permission was missing when the boot path last looked.
     *
     * Read by the settings page, which has to tell the user that the tunnel
     * will not come back until the permission is granted again — otherwise the
     * switch says "on" and nothing happens, which is the same silence the
     * setting had before it was wired to anything.
     */
    fun vpnConsentMissing(): Boolean = prefs.getBoolean(KEY_VPN_CONSENT_MISSING, false)

    /** Records that the VPN permission was missing at boot, or that it was not. */
    fun saveVpnConsentMissing(missing: Boolean) {
        prefs.edit { putBoolean(KEY_VPN_CONSENT_MISSING, missing) }
    }
}

/**
 * Moves a relay token out of the backed-up preferences, if one is there.
 *
 * The rule is [relayTokenMove]'s; this is the part that acts on it. It is a
 * function of its own so it can be driven without a device:
 *
 * - A token that can be sealed is written to the secrets file, sealed, and
 *   only then removed from the file it came out of — and only if that write
 *   reached the disk. A write that failed leaves the token where it was,
 *   where the read path still finds it.
 * - A token that cannot be sealed stays where it is. It is not written in the
 *   clear into the file whose whole point is that it holds ciphertext, and
 *   the read path reads that location too, so the tunnel keeps its
 *   credential.
 * - A blank value is not a credential: the key goes, and nothing is written.
 *
 * Both writes are committed rather than queued, so the order they reach the
 * disk is the order they are made in: the sealed copy is on the disk before
 * the cleartext one is taken off it, and a process that dies between the two
 * leaves the token where it was instead of nowhere.
 */
internal fun relayTokenMigration(
    prefs: SharedPreferences,
    secretPrefs: SharedPreferences,
    seal: (String) -> String?,
    unseal: (String?) -> String
) {
    val key = SettingsManager.KEY_RELAY_AUTH_TOKEN
    if (!prefs.contains(key)) {
        return
    }
    val token = prefs.getString(key, "") ?: ""
    when (val move = relayTokenMove(token) { seal(it) }) {
        RelayTokenMove.None -> {
            // Not a credential: the value saved whenever a relay needs no
            // token. The key goes anyway, so the file does not carry a key
            // that looks like a credential.
            prefs.edit(commit = true) { remove(key) }
        }
        is RelayTokenMove.Move -> {
            // A token the secrets file already holds is the newer one — it is
            // written there whenever the token is saved — so the copy in the
            // backed-up file is dropped rather than moved over it.
            val stored = secretPrefs.getString(key, null)
            if (!stored.isNullOrBlank() && unseal(stored).isNotBlank()) {
                prefs.edit(commit = true) { remove(key) }
                Log.i(TAG, "Dropped the superseded relay auth token from the backed-up preferences")
                return
            }
            // The sealed copy is written — and committed, not queued —
            // before the token is removed from the file it came out of: the
            // two are different files, so the order they reach the disk is
            // this order rather than SharedPreferences' to choose, and a
            // process that dies between them leaves the token where it was
            // instead of nowhere. Once, at startup, on one small value: the
            // block is the price of not losing a credential.
            //
            // The commit is not the KTX `edit(commit = true)`: that one
            // throws the result away, and the result is the answer to
            // "did the write reach the disk". The token is only taken off
            // the file it came out of once it is on the disk here.
            @Suppress("ApplySharedPref", "UseKtx")
            val written = secretPrefs.edit().putString(key, move.sealed).commit()
            if (!written) {
                // The write did not reach the disk, so the token stays where
                // it is: removing it now is the step that could lose it, and
                // the read path finds it there.
                Log.w(TAG, "Left the relay auth token where it was: the secrets file could not be written")
                return
            }
            prefs.edit(commit = true) { remove(key) }
            Log.i(TAG, "Moved the relay auth token out of the backed-up preferences")
        }
        RelayTokenMove.Keep -> {
            Log.w(
                TAG,
                "Left the relay auth token where it was: this device cannot seal it yet"
            )
        }
    }
}
