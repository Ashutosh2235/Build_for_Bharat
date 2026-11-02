package com.scamshield.sms.notify

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.Person
import androidx.core.app.RemoteInput
import androidx.core.content.ContextCompat
import com.scamshield.sms.R
import com.scamshield.sms.container
import com.scamshield.sms.core.network.Reason
import com.scamshield.sms.core.telephony.SmsMessage
import com.scamshield.sms.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class Notifier(private val context: Context) {
    companion object {
        const val CH_MESSAGES = "messages"
        const val CH_SCAM = "scam_alerts"
        const val CH_REPORTS = "reports"
        const val CH_BACKGROUND = "background"
        const val KEY_REPLY = "reply_text"
        const val EXTRA_THREAD = "thread_id"
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_MESSAGE = "message_id"
        private const val MMS_ID = 9_000_001
    }

    private val nm = NotificationManagerCompat.from(context)

    fun createChannels() {
        val m = context.getSystemService(NotificationManager::class.java)
        m.createNotificationChannels(listOf(
            NotificationChannel(CH_MESSAGES, context.getString(R.string.channel_messages), NotificationManager.IMPORTANCE_HIGH),
            NotificationChannel(CH_SCAM, context.getString(R.string.channel_scam), NotificationManager.IMPORTANCE_HIGH).apply {
                enableVibration(true)
            },
            NotificationChannel(CH_REPORTS, context.getString(R.string.channel_reports), NotificationManager.IMPORTANCE_LOW),
            NotificationChannel(CH_BACKGROUND, context.getString(R.string.channel_background), NotificationManager.IMPORTANCE_MIN),
        ))
    }

    private fun canPost() = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED

    private fun openThread(threadId: Long, messageId: Long? = null): PendingIntent {
        val i = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_THREAD, threadId)
            messageId?.let { putExtra(EXTRA_MESSAGE, it) }
        }
        return PendingIntent.getActivity(context, threadId.toInt(), i,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }

    private fun action(action: String, threadId: Long, address: String, mutable: Boolean): PendingIntent {
        val i = Intent(context, NotificationActionReceiver::class.java).apply {
            this.action = action
            putExtra(EXTRA_THREAD, threadId)
            putExtra(EXTRA_ADDRESS, address)
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            (if (mutable) PendingIntent.FLAG_MUTABLE else PendingIntent.FLAG_IMMUTABLE)
        return PendingIntent.getBroadcast(context, (threadId.toInt() shl 2) + action.hashCode() % 4, i, flags)
    }

    @SuppressLint("MissingPermission") // guarded by canPost()
    /** Normal incoming-message notification with direct reply. Shown before the scan finishes. */
    fun showMessage(msg: SmsMessage, displayName: String?) {
        if (!canPost()) return
        val sender = Person.Builder().setName(displayName ?: msg.address).setKey(msg.address).build()
        val style = NotificationCompat.MessagingStyle(Person.Builder().setName("Me").build())
            .addMessage(msg.body, msg.date, sender)
        val reply = NotificationCompat.Action.Builder(
            R.drawable.ic_stat_shield, context.getString(R.string.reply),
            action(NotificationActionReceiver.ACTION_REPLY, msg.threadId, msg.address, mutable = true),
        ).addRemoteInput(RemoteInput.Builder(KEY_REPLY).setLabel(context.getString(R.string.reply)).build())
            .setAllowGeneratedReplies(false).build()
        val markRead = NotificationCompat.Action.Builder(
            R.drawable.ic_stat_shield, context.getString(R.string.mark_read),
            action(NotificationActionReceiver.ACTION_MARK_READ, msg.threadId, msg.address, mutable = false),
        ).build()
        val n = NotificationCompat.Builder(context, CH_MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setStyle(style)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setContentIntent(openThread(msg.threadId, msg.id))
            .setAutoCancel(true)
            .addAction(reply)
            .addAction(markRead)
            .build()
        nm.notify(msg.threadId.toInt(), n)
    }

    @SuppressLint("MissingPermission")
    /**
     * Called ONLY after the server decided FRAUD ("Surely fraud") or SPAM ("Surely spam").
     * Replaces the normal message notification. Scam messages get no Reply action.
     */
    fun showVerdict(msg: SmsMessage, displayName: String?, verdict: String, reasons: List<Reason>, statusLine: String?) {
        if (!canPost() || (verdict != "FRAUD" && verdict != "SPAM")) return
        val who = displayName ?: msg.address
        val fraud = verdict == "FRAUD"
        val title = if (fraud) context.getString(R.string.fraud_alert_title, who) else context.getString(R.string.spam_alert_title, who)
        val body = buildString {
            append(reasons.take(3).joinToString("\n") { "• ${it.text}" })
            if (statusLine != null) append("\n").append(statusLine)
            if (fraud) append("\n\n").append(context.getString(R.string.fraud_advice))
        }
        val n = NotificationCompat.Builder(context, if (fraud) CH_SCAM else CH_MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setColor(if (fraud) 0xFFB3261E.toInt() else 0xFF8A5A00.toInt())
            .setContentTitle(title)
            .setContentText(statusLine ?: reasons.firstOrNull()?.text ?: "")
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setCategory(if (fraud) NotificationCompat.CATEGORY_ALARM else NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(if (fraud) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setSilent(!fraud)                       // spam: update quietly
            .setContentIntent(openThread(msg.threadId, msg.id))
            .setAutoCancel(true)
            .build()
        nm.notify(msg.threadId.toInt(), n)
    }

    @SuppressLint("MissingPermission")
    fun showMmsPlaceholder() {
        if (!canPost()) return
        nm.notify(MMS_ID, NotificationCompat.Builder(context, CH_MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle("Multimedia message received")
            .setContentText("MMS viewing arrives in the next build.")
            .setAutoCancel(true).build())
    }

    fun backgroundNotification(): android.app.Notification =
        NotificationCompat.Builder(context, CH_BACKGROUND)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(context.getString(R.string.scanning))
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setSilent(true)
            .build()

    fun cancel(threadId: Long) = nm.cancel(threadId.toInt())
}

class NotificationActionReceiver : BroadcastReceiver() {
    companion object {
        const val ACTION_REPLY = "com.scamshield.sms.REPLY"
        const val ACTION_MARK_READ = "com.scamshield.sms.MARK_READ"
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    override fun onReceive(context: Context, intent: Intent) {
        val threadId = intent.getLongExtra(Notifier.EXTRA_THREAD, -1)
        val address = intent.getStringExtra(Notifier.EXTRA_ADDRESS) ?: return
        val c = context.container
        val pending = goAsync()
        scope.launch {
            try {
                when (intent.action) {
                    ACTION_REPLY -> {
                        val text = RemoteInput.getResultsFromIntent(intent)?.getCharSequence(Notifier.KEY_REPLY)?.toString()
                        if (!text.isNullOrBlank()) c.smsSender.send(address, text)
                        c.sms.markThreadRead(threadId)
                        c.notifier.cancel(threadId)
                    }
                    ACTION_MARK_READ -> {
                        c.sms.markThreadRead(threadId)
                        c.notifier.cancel(threadId)
                    }
                }
            } finally {
                pending.finish()
            }
        }
    }
}
