package com.nexa.pipe

import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * The notification permission is requested by the permission guide, with a
 * launcher that lives in the composition.
 *
 * The helpers that used to live here were never called, and one of them
 * would have crashed the screen it was wired into: a launcher has to be
 * registered before the activity reaches RESUMED, and an object that is
 * reached from a click handler is reached long after that.
 *
 * The check is that the trap is not there: a helper that registers a launcher
 * outside a composition is the kind of thing that looks right and fails at
 * runtime, and the only thing that catches it is its absence.
 */
class PermissionManagerTest {

    @Test
    fun there_is_no_launcher_to_register_outside_a_composition() {
        val names = PermissionManager::class.java.declaredMethods.map { it.name }

        assertFalse(
            "a launcher registered outside a composition throws when it is wired up",
            names.contains("createNotificationPermissionLauncher")
        )
        assertFalse(
            "the request helper was never called, and it asks for a permission " +
                "the guide asks for with a launcher of its own",
            names.contains("requestNotificationPermission")
        )
    }

    @Test
    fun the_notification_settings_page_has_no_helper_nobody_calls() {
        val names = PermissionManager::class.java.declaredMethods.map { it.name }

        assertFalse(
            "the guide deep-links to the app settings page; a helper for the " +
                "notification page that nothing calls is only a trap",
            names.contains("openNotificationSettings")
        )
    }
}
