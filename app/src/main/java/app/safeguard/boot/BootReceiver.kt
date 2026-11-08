package app.safeguard.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import app.safeguard.R
import app.safeguard.service.Notifications
import app.safeguard.service.SafeguardVpnService
import app.safeguard.storage.SafeguardPrefs

/** Restores protection after reboot / app update if the user had it enabled and VPN consent still holds. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val prefs = SafeguardPrefs(context)
        if (!prefs.enabled) return
        if (VpnService.prepare(context) != null) {
            prefs.enabled = false
            Notifications.postAttention(context, context.getString(R.string.attention_permission))
            return
        }
        try {
            context.startForegroundService(
                Intent(context, SafeguardVpnService::class.java).setAction(SafeguardVpnService.ACTION_START),
            )
        } catch (e: Exception) {
            Log.w("SafeguardBoot", "cannot start service", e)
        }
    }
}
