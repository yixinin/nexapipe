package com.nexa.pipe

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings

/**
 * What the app asks the operating system for.
 *
 * The notification permission is requested by the permission guide itself,
 * with a launcher that lives in the composition: a launcher registered here
 * would have to be registered before the activity reaches RESUMED, which is
 * not when this object is reached, and the platform refuses it with an
 * IllegalStateException. The request helpers that used to live here were
 * never called, and wiring one of them up would have crashed the screen it
 * was wired into.
 */
object PermissionManager {

    private const val TAG = "PermissionManager"

    fun checkNotificationPermission(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
            return notificationManager.areNotificationsEnabled()
        }
        return true
    }

    /**
     * The page where the app's own settings are: the VPN permission, the
     * background restrictions, and everything else that is not a notification
     * permission.
     */
    fun openAppSettings(context: Context) {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", context.packageName, null)
        }
        context.startActivity(intent)
    }
}
