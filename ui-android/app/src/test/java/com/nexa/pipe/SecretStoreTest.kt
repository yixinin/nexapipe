package com.nexa.pipe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The plaintext fallback is deliberate — refusing to store a credential would
 * cut the user off from their own endpoint — but it used to be silent, and a
 * device whose keystore would not take the key looked exactly like a working
 * one. These pin the part that makes it visible.
 */
class SecretStoreTest {
    /**
     * Off-device there is no `AndroidKeyStore` at all, which is the very case
     * the fallback exists for.
     */
    @Test
    fun a_keystore_that_will_not_take_the_key_is_reported() {
        val store = SecretStore()
        val plain = "JBSWY3DPEHPK3PXP"

        assertEquals("the value is still stored", plain, store.seal(plain))
        assertEquals(
            "but the caller is told it is not protected",
            SecretStore.Protection.NoKeystore,
            store.protection()
        )
    }

    /**
     * An empty value is returned before any key is looked for, so a node with
     * no 2FA must not be able to make the app look unprotected.
     */
    @Test
    fun an_empty_value_leaves_the_reported_state_alone() {
        val store = SecretStore()

        assertEquals("", store.seal(""))
        assertEquals(SecretStore.Protection.Sealed, store.protection())
    }

    /**
     * A value without the marker is the plaintext an older version wrote, and
     * it is the user's only copy, so it is handed back as it stands.
     */
    @Test
    fun an_unmarked_value_is_read_as_the_plaintext_it_is() {
        val store = SecretStore()

        assertEquals("JBSWY3DPEHPK3PXP", store.unseal("JBSWY3DPEHPK3PXP"))
        assertEquals("", store.unseal(null))
        assertEquals("", store.unseal(""))
    }

    /**
     * A value that carries the marker but is not ciphertext is plaintext that
     * happens to start with it — the legacy client id did.
     *
     * It used to be taken for ciphertext: the length check failed, the value
     * was handed back as absent, and the credential was lost with nothing
     * but a warning. The migration skipped it as well, because the migration
     * skipped everything that carries the marker, so the value stayed in the
     * clear in the secrets file for good.
     *
     * It is handed back now, so the migration seals it.
     */
    @Test
    fun a_plaintext_value_that_carries_the_marker_is_not_lost() {
        val store = SecretStore()
        val plain = "v1:client-001"

        assertEquals(
            "the credential is the user's only copy, so it is handed back",
            plain,
            store.unseal(plain)
        )
    }

    /**
     * A value is ciphertext only when it has the shape of ciphertext: the
     * marker, a strict Base64 body, and enough bytes for the nonce and the
     * GCM tag.
     *
     * The marker alone is not a shape: a plaintext credential that starts
     * with it would be taken for ciphertext and lost.
     */
    @Test
    fun a_value_is_sealed_only_when_it_has_the_shape_of_one() {
        val store = SecretStore()

        assertFalse(store.isSealed(null))
        assertFalse(store.isSealed("JBSWY3DPEHPK3PXP"))
        assertFalse(store.isSealed("v1:"))
        assertFalse(store.isSealed("v1:client-001"))
        assertFalse(store.isSealed("v1:not base64 at all"))
        // The nonce, the tag and one byte of ciphertext: the shortest value
        // this class can have written.
        assertTrue(
            store.isSealed("v1:" + Base64.getEncoder().encodeToString(ByteArray(29)))
        )
        assertFalse(
            "one byte short of the nonce and the tag",
            store.isSealed("v1:" + Base64.getEncoder().encodeToString(ByteArray(28)))
        )
    }
}
