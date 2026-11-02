package com.scamshield.sms.core.telephony

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.telephony.SmsManager
import android.telephony.SubscriptionInfo
import android.telephony.SubscriptionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SmsSender(private val context: Context, private val repo: SmsRepository) {

    /** Active SIMs (needs READ_PHONE_STATE). Empty list → use the default SMS subscription. */
    fun activeSims(): List<SubscriptionInfo> = try {
        context.getSystemService(SubscriptionManager::class.java).activeSubscriptionInfoList.orEmpty()
    } catch (e: SecurityException) {
        emptyList()
    }

    fun defaultSubId(): Int = SubscriptionManager.getDefaultSmsSubscriptionId()

    /** SmsManager for a SIM. `getSystemService(SmsManager)` only exists on API 31+, minSdk is 29. */
    @Suppress("DEPRECATION")
    fun manager(subId: Int = defaultSubId()): SmsManager {
        val valid = subId != SubscriptionManager.INVALID_SUBSCRIPTION_ID
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val base = context.getSystemService(SmsManager::class.java)
            if (valid) base.createForSubscriptionId(subId) else base
        } else {
            if (valid) SmsManager.getSmsManagerForSubscriptionId(subId) else SmsManager.getDefault()
        }
    }

    fun partsCount(body: String): Int = manager().divideMessage(body).size

    /**
     * Writes the message to the Outbox, sends it (multipart if needed) and lets
     * [SmsStatusReceiver] move it to Sent/Failed and record delivery.
     */
    suspend fun send(address: String, body: String, subId: Int = defaultSubId()): Uri? = withContext(Dispatchers.IO) {
        val uri = repo.insertOutgoing(address, body, subId) ?: return@withContext null
        val manager = manager(subId)
        val parts = manager.divideMessage(body)
        val sent = ArrayList<PendingIntent>()
        val delivered = ArrayList<PendingIntent>()
        parts.indices.forEach { i ->
            val last = i == parts.lastIndex
            sent += statusIntent(uri, SmsStatusReceiver.ACTION_SENT, i, last)
            delivered += statusIntent(uri, SmsStatusReceiver.ACTION_DELIVERED, i, last)
        }
        try {
            if (parts.size == 1) manager.sendTextMessage(address, null, body, sent[0], delivered[0])
            else manager.sendMultipartTextMessage(address, null, parts, sent, delivered)
        } catch (e: Exception) { // SecurityException (not default app / no SIM), IllegalArgumentException …
            repo.updateType(uri, android.provider.Telephony.Sms.MESSAGE_TYPE_FAILED)
        }
        uri
    }

    private fun statusIntent(uri: Uri, action: String, part: Int, last: Boolean): PendingIntent {
        val i = Intent(context, SmsStatusReceiver::class.java).apply {
            this.action = action
            data = uri
            putExtra(SmsStatusReceiver.EXTRA_LAST_PART, last)
        }
        return PendingIntent.getBroadcast(
            context, (uri.lastPathSegment?.toIntOrNull() ?: 0) * 100 + part, i,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
    }
}
