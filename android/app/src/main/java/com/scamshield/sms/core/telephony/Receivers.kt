package com.scamshield.sms.core.telephony

import android.app.Activity
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.provider.Telephony
import android.telephony.SubscriptionManager
import com.scamshield.sms.container
import com.scamshield.sms.work.ScanWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

private val receiverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

/** Runs [block] off the main thread while keeping the broadcast alive (goAsync). */
private fun BroadcastReceiver.launchAsync(block: suspend () -> Unit) {
    val pending = goAsync()
    receiverScope.launch {
        try { block() } finally { pending.finish() }
    }
}

/** Store an incoming SMS, notify, and queue the scam scan. Shared by the receiver and the test tool. */
suspend fun deliverIncoming(context: Context, address: String, body: String, sentAt: Long, subId: Int): Long? {
    val c = context.container
    val uri = c.sms.insertIncoming(address, body, sentAt, subId) ?: return null
    val id = uri.lastPathSegment?.toLongOrNull() ?: return null
    val msg = c.sms.message(id) ?: return null
    c.notifier.showMessage(msg, c.sms.contactName(address))
    ScanWorker.enqueue(context, id)
    return msg.threadId
}

/**
 * Default-SMS requirement #1. Only the default SMS app receives SMS_DELIVER, and it must write
 * the message to the provider itself. Then: show the normal notification immediately and
 * enqueue the scam scan (context file §4.4) — delivery is never blocked by the scan.
 */
class SmsDeliverReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_DELIVER_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        if (parts.isEmpty()) return
        val address = parts[0].displayOriginatingAddress ?: parts[0].originatingAddress ?: return
        val body = parts.joinToString("") { it.displayMessageBody ?: it.messageBody ?: "" }
        val sentAt = parts[0].timestampMillis
        val subId = intent.getIntExtra(
            SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX,
            intent.getIntExtra("subscription", SubscriptionManager.INVALID_SUBSCRIPTION_ID),
        )
        launchAsync { deliverIncoming(context, address, body, sentAt, subId) }
    }
}

/**
 * Default-SMS requirement #2. Phase 1 acknowledges MMS but does not download it yet
 * (MMS download/encode arrives in phase 3 — context file §15, day 5).
 */
class MmsWapPushReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.WAP_PUSH_DELIVER_ACTION) return
        context.container.notifier.showMmsPlaceholder()
    }
}

/** Default-SMS requirement #4: quick replies from the dialer ("respond via message"). */
class HeadlessSmsSendService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val text = intent?.getStringExtra(Intent.EXTRA_TEXT)
        val address = intent?.data?.schemeSpecificPart?.substringBefore('?')
        if (!text.isNullOrBlank() && !address.isNullOrBlank()) {
            receiverScope.launch {
                container.smsSender.send(address, text)
                stopSelf(startId)
            }
        } else {
            stopSelf(startId)
        }
        return START_NOT_STICKY
    }
}

/** Sent / delivered callbacks for outgoing SMS. */
class SmsStatusReceiver : BroadcastReceiver() {
    companion object {
        const val ACTION_SENT = "com.scamshield.sms.SMS_SENT"
        const val ACTION_DELIVERED = "com.scamshield.sms.SMS_DELIVERED"
        const val EXTRA_LAST_PART = "last_part"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val uri = intent.data ?: return
        if (!intent.getBooleanExtra(EXTRA_LAST_PART, true)) return
        val repo = context.container.sms
        val code = resultCode
        launchAsync {
            when (intent.action) {
                ACTION_SENT -> if (code == Activity.RESULT_OK) {
                    repo.updateType(uri, Telephony.Sms.MESSAGE_TYPE_SENT)
                } else {
                    repo.updateType(uri, Telephony.Sms.MESSAGE_TYPE_FAILED, code)
                }
                ACTION_DELIVERED -> {
                    val status = if (code == Activity.RESULT_OK) Telephony.Sms.STATUS_COMPLETE else Telephony.Sms.STATUS_FAILED
                    repo.updateStatus(uri, status)
                }
            }
        }
    }
}
