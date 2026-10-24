package com.nexa.pipe

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals the credentials this app keeps at rest: TOTP seeds, enrollment tokens
 * and the relay bearer token.
 *
 * The key lives in the Android keystore and never enters the process heap as
 * material, so reading the preferences file — from a backup, a rooted shell or
 * a pulled APK's private data — yields ciphertext that only this installation
 * can open. That is the property the keystore buys and a hard-coded key would
 * not: the app is not shipped with the means to decrypt its own storage.
 *
 * This replaces the `EncryptedSharedPreferences` of `androidx.security`, whose
 * API was deprecated in whole with 1.1.0 and which Google no longer publishes.
 *
 * Values are `AES-256-GCM` with a fresh 12-byte nonce per call, stored
 * alongside the ciphertext. GCM fails closed on tampering, so a corrupted
 * value surfaces as "no credential" rather than as a wrong one.
 */
class SecretStore {
    companion object {
        private const val TAG = "SecretStore"
        private const val ALIAS = "nexapipe_credentials"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val NONCE_BYTES = 12
        private const val TAG_BITS = 128

        /**
         * Marks a value as sealed. Anything without it is plaintext: either a
         * value an older version wrote, or one that could not be sealed at the
         * time it was saved.
         *
         * The marker on its own does not say that a value is sealed — see
         * [isSealed] — it says that the value was *meant* to be sealed.
         */
        const val MARKER = "v1:"

        /** The GCM authentication tag, in bytes: 128 bits. */
        private const val TAG_BYTES = TAG_BITS / 8

        /**
         * The body of a sealed value: Base64 in the standard alphabet, with
         * the padding a strict encoder writes and nothing else in it.
         *
         * A plaintext credential cannot produce this shape by accident, which
         * is what [isSealed] leans on.
         */
        private val SEALED_BODY = Regex("^[A-Za-z0-9+/]+={0,2}$")

        /** Sealed and thrown away by [canSeal]. Never stored. */
        private const val PROBE = "probe"
    }

    /**
     * What became of the last credential this class was asked to protect.
     *
     * The fallback to plaintext is deliberate — refusing to store would cut the
     * user off from their own endpoint — but it was silent, which left a device
     * with a broken keystore looking exactly like a working one. This is what
     * lets the rest of the app say so out loud instead.
     */
    enum class Protection {
        /** Stored as ciphertext under a keystore key. */
        Sealed,

        /** No key at all: the keystore could not be opened, or none was created. */
        NoKeystore,

        /** There is a key, but this value could not be sealed with it. */
        SealFailed,
    }

    /**
     * The outcome of the last [seal].
     *
     * Per instance rather than per value, because the question the UI asks is
     * "is this device protecting credentials at all", and one value that failed
     * is enough to answer it — the next [seal] overwrites this, so a transient
     * failure is not reported forever.
     */
    @Volatile
    private var lastProtection: Protection = Protection.Sealed

    fun protection(): Protection = lastProtection

    /**
     * Whether this device can seal a credential at all, right now.
     *
     * [protection] reports what last happened; this answers *before* anything
     * is stored, which is what a caller needs in order to ask first instead of
     * discovering afterwards that a credential went down in the clear.
     *
     * Deliberately not [seal] on a throwaway value: that would report the
     * failure in the log and move [protection], so the act of asking would
     * itself look like a credential having been stored unprotected. This
     * repeats the steps instead, and stays quiet whatever the answer is.
     */
    fun canSeal(): Boolean {
        val key = key() ?: return false
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.doFinal(PROBE.toByteArray(Charsets.UTF_8))
            true
        } catch (e: GeneralSecurityException) {
            false
        } catch (e: ProviderException) {
            false
        } catch (e: IllegalStateException) {
            false
        }
    }

    private val keyStore: KeyStore? = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    } catch (e: Exception) {
        Log.e(TAG, "The keystore is unavailable, credentials will stay in plaintext", e)
        null
    }

    private var cachedKey: SecretKey? = null

    /**
     * Wraps [plain] for storage.
     *
     * Returns [plain] unchanged when there is no key to use. Sealing can only
     * fail on a device whose keystore is broken, and the alternative — refusing
     * to store the credential — would silently disconnect the user from their
     * own endpoint. Losing the ciphertext on such a device is a smaller
     * failure than losing the credential, and the file holding it is excluded
     * from backups either way.
     *
     * Every path that touches the keystore also catches [ProviderException] and
     * [IllegalStateException], neither of which is a [GeneralSecurityException]:
     * they are how AndroidKeyStore reports a Keymaster that cannot be reached,
     * a key it cannot use or a keystore that is not unlocked yet. Left to
     * escape, one of them turns a device with a broken keystore into a crash at
     * startup — `SettingsManager.init` seals on its migration path — instead of
     * the plaintext fallback this class exists to provide.
     */
    fun seal(plain: String): String = sealOrNull(plain) ?: plain

    /**
     * Wraps [plain] for storage, or returns null when this device cannot seal
     * it.
     *
     * [seal] falls back to plaintext rather than lose a credential, which is
     * the right default for a value the app already holds — refusing there
     * would disconnect the user from their own endpoint — and the wrong one
     * for a write nobody has agreed to. This is the same work with that
     * fallback taken away: a caller that must not put a credential on disk in
     * the clear asks here, instead of sealing and discovering afterwards that
     * [seal] chose for it.
     *
     * A keystore that works on one call and fails on the next is exactly the
     * case this exists for, so the question is asked of the write itself and
     * not of a probe that could have been answered by a different call.
     */
    fun sealOrNull(plain: String): String? {
        if (plain.isEmpty()) return plain
        val key = key() ?: run {
            lastProtection = Protection.NoKeystore
            return null
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            // No GCMParameterSpec here on purpose: the keystore generates the
            // nonce and refuses one supplied by the caller, which is what
            // keeps two encryptions of the same secret from producing the same
            // bytes. It is then read back off the cipher.
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val nonce = cipher.iv
            val body = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            // Recorded on the way out, so a device whose keystore came back is
            // not reported as unprotected by one failure from last week.
            lastProtection = Protection.Sealed
            MARKER + Base64.getEncoder().encodeToString(nonce + body)
        } catch (e: GeneralSecurityException) {
            Log.e(TAG, "Could not seal a credential", e)
            lastProtection = Protection.SealFailed
            null
        } catch (e: ProviderException) {
            // Keymaster unreachable: the key is gone, not merely unusable once.
            Log.e(TAG, "The keystore failed to seal a credential", e)
            lastProtection = Protection.NoKeystore
            null
        } catch (e: IllegalStateException) {
            Log.e(TAG, "The keystore is not ready, could not seal a credential", e)
            lastProtection = Protection.NoKeystore
            null
        }
    }

    /**
     * Whether [stored] is a value this class sealed.
     *
     * The marker alone does not say so. A plaintext credential that happens to
     * start with "v1:" — the legacy client id did — would be taken for
     * ciphertext, fail the length check and be handed back as absent: the
     * credential is lost, and the value stays in the clear in the secrets
     * file, because the migration skips everything that carries the marker.
     *
     * So a value is ciphertext only when it also has the *shape* of
     * ciphertext: the marker, then a strict Base64 body, then enough bytes
     * for the nonce and the GCM tag. A plaintext value does not produce that
     * shape by accident, and one that fails it is plaintext to be migrated
     * rather than a credential to be lost.
     */
    fun isSealed(stored: String?): Boolean {
        val value = stored ?: ""
        if (!value.startsWith(MARKER)) return false
        val body = value.removePrefix(MARKER)
        if (!SEALED_BODY.matches(body)) return false
        // The Base64 of a whole number of groups: the padding is part of it.
        if (body.length % 4 != 0) return false
        val packed = try {
            Base64.getDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            return false
        }
        // The nonce, the ciphertext and the GCM tag, and at least one byte of
        // what was sealed: a shorter value is not a sealed one.
        return packed.size > NONCE_BYTES + TAG_BYTES
    }

    /**
     * Reads back a value written by [seal], or "" if it cannot be read.
     *
     * A value without the marker is returned as it stands. Those are the
     * plaintext credentials older versions left behind, and they are the user's
     * only copy: treating them as absent would lock them out of their
     * endpoints, which is worse than leaving them readable until they are next
     * saved. The same goes for a value that carries the marker but does not
     * have the shape of a sealed value: it is plaintext that starts with the
     * marker, and it is handed back for the migration to seal.
     *
     * A sealed value that does not open is treated as absent — the key is
     * gone or the record was damaged, and in both cases there is no
     * credential to be had.
     */
    fun unseal(stored: String?): String {
        val value = stored ?: ""
        if (!value.startsWith(MARKER)) return value
        if (!isSealed(value)) {
            // The marker, but not the shape of a sealed value. Handing this
            // back as "" would lose the credential and leave it in the clear
            // where it was, so it is returned as the plaintext it is.
            Log.w(TAG, "A value carries the sealed marker but is not ciphertext, treating it as plaintext")
            return value
        }
        val key = key() ?: return ""
        return try {
            val packed = Base64.getDecoder().decode(value.removePrefix(MARKER))
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(TAG_BITS, packed, 0, NONCE_BYTES)
            )
            String(cipher.doFinal(packed, NONCE_BYTES, packed.size - NONCE_BYTES), Charsets.UTF_8)
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "A sealed credential is malformed, treating it as unset")
            ""
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "Could not unseal a credential, treating it as unset")
            ""
        } catch (e: ProviderException) {
            Log.w(TAG, "The keystore failed, treating a credential as unset", e)
            ""
        } catch (e: IllegalStateException) {
            Log.w(TAG, "The keystore is not ready, treating a credential as unset", e)
            ""
        }
    }

    /**
     * The credential key, generating it the first time there is none.
     *
     * A read that *throws* is not the same as a read that found no key, and the
     * two must not reach [generate] together. On API 26, the lowest supported
     * version, generating a key under an alias that already exists deletes that
     * entry first, so a key generated because the keystore was momentarily
     * unreachable replaces the key every stored credential is sealed under and
     * makes all of them unreadable. Only a read that succeeded and came back
     * empty means there is no key yet.
     *
     * Two threads must not reach [generate] together either, and that is the
     * same hazard with a different cause: generating a key under an alias that
     * already exists replaces it, so of two keys created for an alias that had
     * none, the second makes everything the first sealed unreadable. The
     * settings writer seals from its own coroutine and the device-key
     * preparation from another, so two threads do reach this at once — hence
     * the lock, which also makes [cachedKey] safe to read here.
     */
    @Synchronized
    private fun key(): SecretKey? {
        cachedKey?.let { return it }
        val store = keyStore ?: return null
        val resolved = try {
            store.getKey(ALIAS, null) as? SecretKey
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "The credential key could not be loaded", e)
            return null
        } catch (e: ProviderException) {
            Log.w(TAG, "The keystore failed while loading the credential key", e)
            return null
        } catch (e: IllegalStateException) {
            Log.w(TAG, "The keystore is not ready, the credential key is unavailable", e)
            return null
        } ?: generate()
        cachedKey = resolved
        return resolved
    }

    private fun generate(): SecretKey? = try {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    // Deliberately not gated on user authentication: this app
                    // has to reopen its endpoints after a reboot without
                    // anyone present to unlock anything.
                    //
                    // What that costs is worth stating plainly, because the
                    // two are easy to confuse: the biometric gate in
                    // `CredentialGate` is a door on the *display* of a secret,
                    // not on its storage. The key is in the keystore and the
                    // app can use it without anyone authenticating, so an
                    // attacker who has code execution inside this app's
                    // process — root, a local exploit, `run-as` on a
                    // debuggable build — can read the ciphertext out of
                    // `NexaPipeSecrets.xml` and decrypt it with this key
                    // without ever seeing a fingerprint.
                    //
                    // A second key, gated on the user, would close that — and
                    // would also stop the tunnel from coming back on its own
                    // after a reboot, which is the thing this key exists for.
                    // The trade is a deployment's to make, and it is a
                    // deployment with `autoConnectOnBoot` turned on that
                    // wants the second key.
                    .build()
            )
            generateKey()
        }
    } catch (e: GeneralSecurityException) {
        Log.e(TAG, "Could not create the credential key", e)
        null
    } catch (e: ProviderException) {
        Log.e(TAG, "The keystore failed while creating the credential key", e)
        null
    } catch (e: IllegalStateException) {
        Log.e(TAG, "The keystore is not ready, the credential key was not created", e)
        null
    }
}
