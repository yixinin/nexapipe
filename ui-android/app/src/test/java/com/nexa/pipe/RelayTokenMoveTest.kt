package com.nexa.pipe

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What happens to a relay token an older version left in the backed-up
 * preferences.
 *
 * The token is a credential — it is handed to the relay verbatim — and the
 * file it is moving out of is the one that rides the backup. The file it is
 * moving into is the one whose whole point is that it holds ciphertext, so a
 * token that cannot be sealed has nowhere to go.
 */
class RelayTokenMoveTest {

    /**
     * A token this device can seal moves, and what is written is the sealed
     * value rather than the token itself.
     */
    @Test
    fun a_sealable_token_moves_sealed() {
        val move = relayTokenMove("the-relay-token") { "sealed:$it" }

        assertTrue("the token moves: $move", move is RelayTokenMove.Move)
        assertEquals("sealed:the-relay-token", (move as RelayTokenMove.Move).sealed)
    }

    /**
     * A device with no keystore cannot seal anything, and the token stays
     * where it is.
     *
     * It is not written in the clear into the secrets file: that file is
     * excluded from the backup precisely because it holds ciphertext, and a
     * plain value in it is a credential in a file that says it holds none.
     */
    @Test
    fun a_token_that_cannot_be_sealed_stays_where_it_is() {
        val move = relayTokenMove("the-relay-token") { null }

        assertEquals(RelayTokenMove.Keep, move)
    }

    /**
     * A blank value is the one saved whenever a relay needs no token. It is
     * not a credential, so nothing is written anywhere — but the key is still
     * removed, so the file does not carry one that looks like a credential.
     */
    @Test
    fun a_blank_token_is_not_a_credential() {
        assertEquals(RelayTokenMove.None, relayTokenMove("") { "sealed:$it" })
        assertEquals(RelayTokenMove.None, relayTokenMove("   ") { "sealed:$it" })
    }

    /**
     * A blank value is answered before the keystore is asked at all, so a
     * relay that needs no token cannot make the device look unprotected.
     */
    @Test
    fun a_blank_token_never_asks_the_keystore() {
        var asked = false
        relayTokenMove("") { asked = true; "sealed" }

        assertTrue("the keystore was asked for nothing", !asked)
    }

    /**
     * A token that stays in the backed-up preferences is still read from
     * there.
     *
     * This is the read path, not the decision: a token the app cannot seal
     * has nowhere else to go, so the read has to look where it stayed —
     * otherwise the app hands the relay an empty token and the tunnel loses
     * its credential.
     */
    @Test
    fun a_token_kept_where_it_is_is_still_read() {
        val legacy = "the-relay-token"

        assertEquals(RelayTokenMove.Keep, relayTokenMove(legacy) { null })
        assertEquals(legacy, relayTokenRead(null, legacy) { it ?: "" })
    }

    /**
     * The token the app itself reads is the one left in the backed-up
     * preferences.
     *
     * The whole path, on a device with no keystore: the migration runs when
     * the settings are built, cannot seal the token, leaves it where it was —
     * and the app still reads it.
     */
    @Test
    fun the_app_reads_a_token_it_could_not_seal() {
        val prefs = FakePrefs("prefs")
        prefs.put(SettingsManager.KEY_RELAY_AUTH_TOKEN, "the-relay-token")
        val secrets = FakePrefs("secrets")

        // A host has no Android keystore, so this device cannot seal
        // anything: the case the token has to survive.
        val manager = SettingsManager(prefs, secrets, SecretStore())
        assertFalse("this device cannot seal anything", manager.canProtectCredentials())

        assertEquals("the-relay-token", manager.loadRelayAuthToken())
    }

    /**
     * The secrets file wins over the copy left in the backed-up preferences.
     *
     * It is written whenever the token is saved, so it holds the newer of the
     * two; what is left in the backed-up file is the copy from before the
     * token moved.
     */
    @Test
    fun the_secrets_file_wins_over_the_legacy_copy() {
        val read = relayTokenRead("sealed:the-token", "the-old-token") {
            it?.removePrefix("sealed:") ?: ""
        }

        assertEquals("the-token", read)
    }

    /**
     * A token that moved is read back as the token, not as its sealed form.
     */
    @Test
    fun a_moved_token_reads_back_as_the_token() {
        val move = relayTokenMove("the-relay-token") { "sealed:$it" }
        val sealed = (move as RelayTokenMove.Move).sealed

        assertEquals(
            "the-relay-token",
            relayTokenRead(sealed, null) { it?.removePrefix("sealed:") ?: "" }
        )
    }

    /**
     * A relay that needs no token reads as no token, whichever file says so.
     */
    @Test
    fun no_token_reads_as_empty() {
        assertEquals("", relayTokenRead(null, null) { it ?: "" })
        assertEquals("", relayTokenRead("", "") { it ?: "" })
    }

    /**
     * A token that cannot be sealed stays in the backed-up preferences, and
     * the read finds it there.
     *
     * Nothing is written to the secrets file: a cleartext value there is a
     * credential in the file that says it holds none.
     */
    @Test
    fun a_token_that_cannot_be_sealed_is_not_written_to_the_secrets_file() {
        val prefs = FakePrefs("prefs")
        prefs.put(SettingsManager.KEY_RELAY_AUTH_TOKEN, "the-relay-token")
        val secrets = FakePrefs("secrets")

        relayTokenMigration(prefs, secrets, seal = { null }, unseal = { it ?: "" })

        assertEquals(
            "the token stayed where it was",
            "the-relay-token",
            prefs.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
        assertNull(
            "nothing was written to the secrets file",
            secrets.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
    }

    /**
     * A token that can be sealed is written to the secrets file, sealed, and
     * only then removed from the file it came out of.
     *
     * Both writes are committed, so the order they reach the disk is the
     * order they are made in: the sealed copy is on the disk before the
     * cleartext one is taken off it.
     */
    @Test
    fun a_sealed_copy_is_committed_before_the_cleartext_one_is_removed() {
        val log = mutableListOf<String>()
        val prefs = FakePrefs("prefs", log = log)
        prefs.put(SettingsManager.KEY_RELAY_AUTH_TOKEN, "the-relay-token")
        val secrets = FakePrefs("secrets", log = log)

        relayTokenMigration(prefs, secrets, seal = { "sealed:$it" }, unseal = { it ?: "" })

        assertEquals(
            "sealed:the-relay-token",
            secrets.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
        assertNull(
            "the cleartext copy is gone",
            prefs.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
        assertEquals(
            "the sealed copy reached the disk before the cleartext one was taken off it",
            listOf("commit:secrets", "commit:prefs"),
            log
        )
    }

    /**
     * A write that fails leaves the token where it was.
     *
     * The sealed copy is not on the disk, so removing the cleartext one would
     * leave the credential in neither file: the removal waits for a write
     * that worked.
     */
    @Test
    fun a_failed_write_leaves_the_token_where_it_was() {
        val prefs = FakePrefs("prefs")
        prefs.put(SettingsManager.KEY_RELAY_AUTH_TOKEN, "the-relay-token")
        val secrets = FakePrefs("secrets", failCommit = true)

        relayTokenMigration(prefs, secrets, seal = { "sealed:$it" }, unseal = { it ?: "" })

        assertEquals(
            "the token stayed in the backed-up preferences",
            "the-relay-token",
            prefs.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
        assertNull(
            "the sealed copy never reached the disk",
            secrets.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
        assertEquals(
            "the token is still readable",
            "the-relay-token",
            relayTokenRead(
                secrets.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null),
                prefs.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
            ) { it ?: "" }
        )
    }

    /**
     * A token the secrets file already holds is not moved over.
     *
     * It is written there whenever the token is saved, so it is the newer of
     * the two; the copy in the backed-up file is the one from before the
     * token moved, and it goes rather than replacing what the app uses.
     */
    @Test
    fun a_token_the_secrets_file_already_holds_is_not_moved_over() {
        val prefs = FakePrefs("prefs")
        prefs.put(SettingsManager.KEY_RELAY_AUTH_TOKEN, "the-old-token")
        val secrets = FakePrefs("secrets")
        secrets.put(SettingsManager.KEY_RELAY_AUTH_TOKEN, "the-new-token")

        relayTokenMigration(prefs, secrets, seal = { "sealed:$it" }, unseal = { it ?: "" })

        assertEquals(
            "the newer token was left alone",
            "the-new-token",
            secrets.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
        assertNull(
            "the superseded copy is gone",
            prefs.getString(SettingsManager.KEY_RELAY_AUTH_TOKEN, null)
        )
    }
}

/**
 * A preferences file that lives in a map.
 *
 * What matters about the migration is the order its writes are made in and
 * whether they reach the disk, so the fake records both — and can be told
 * to fail a commit, which is the failure the migration has to survive.
 */
private class FakePrefs(
    private val name: String,
    private val values: MutableMap<String, Any?> = mutableMapOf(),
    private val log: MutableList<String> = mutableListOf(),
    private val failCommit: Boolean = false
) : SharedPreferences {

    /** Seeds a value the way an older version would have left it. */
    fun put(key: String, value: String) {
        values[key] = value
    }

    override fun getAll(): MutableMap<String, *> = values.toMutableMap()

    override fun getString(key: String, defValue: String?): String? =
        values[key] as? String ?: defValue

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
        (values[key] as? MutableSet<String>) ?: defValues

    override fun getInt(key: String, defValue: Int): Int = values[key] as? Int ?: defValue

    override fun getLong(key: String, defValue: Long): Long = values[key] as? Long ?: defValue

    override fun getFloat(key: String, defValue: Float): Float = values[key] as? Float ?: defValue

    override fun getBoolean(key: String, defValue: Boolean): Boolean =
        values[key] as? Boolean ?: defValue

    override fun contains(key: String): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = FakeEditor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    private inner class FakeEditor : SharedPreferences.Editor {
        private val pending = mutableMapOf<String, Any?>()
        private val removed = mutableSetOf<String>()

        override fun putString(key: String, value: String?): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putStringSet(key: String, values: MutableSet<String>?): SharedPreferences.Editor {
            pending[key] = values
            return this
        }

        override fun putInt(key: String, value: Int): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putLong(key: String, value: Long): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putFloat(key: String, value: Float): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun remove(key: String): SharedPreferences.Editor {
            removed += key
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            pending.clear()
            removed.clear()
            return this
        }

        override fun commit(): Boolean {
            log += "commit:$name"
            if (failCommit) return false
            flush()
            return true
        }

        override fun apply() {
            log += "apply:$name"
            flush()
        }

        private fun flush() {
            pending.forEach { (key, value) -> values[key] = value }
            removed.forEach { values.remove(it) }
            pending.clear()
            removed.clear()
        }
    }
}
