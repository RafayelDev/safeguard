package app.safeguard.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import app.safeguard.MainActivity
import app.safeguard.R

object Notifications {
    const val CHANNEL_VPN = "safeguard_vpn"
    const val CHANNEL_ATTENTION = "safeguard_attention"
    const val ID_VPN = 1
    const val ID_ATTENTION = 2

    fun ensureChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_VPN, context.getString(R.string.channel_vpn), NotificationManager.IMPORTANCE_LOW),
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ATTENTION, context.getString(R.string.channel_attention), NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
    }

    fun build(context: Context, channel: String, text: String, ongoing: Boolean): Notification {
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setOngoing(ongoing)
            .setAutoCancel(!ongoing)
            .setOnlyAlertOnce(true)
            .build()
    }

    fun postAttention(context: Context, text: String) {
        ensureChannels(context)
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.notify(ID_ATTENTION, build(context, CHANNEL_ATTENTION, text, false))
    }
}
