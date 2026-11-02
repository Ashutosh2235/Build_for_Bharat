package com.scamshield.sms.work

import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import android.provider.Telephony
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.scamshield.sms.container
import com.scamshield.sms.core.data.ScanResultEntity
import com.scamshield.sms.core.network.LocalResult
import com.scamshield.sms.core.network.Reason
import com.scamshield.sms.core.network.ReportLogIn
import com.scamshield.sms.core.network.ScanFeatures
import com.scamshield.sms.core.network.ScanIn
import com.scamshield.sms.core.network.ScanOut
import com.scamshield.sms.core.network.Check
import com.scamshield.sms.core.network.Portal
import com.scamshield.sms.core.network.UrlOut
import kotlinx.serialization.builtins.serializer
import kotlinx.coroutines.delay
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import retrofit2.HttpException
import java.io.IOException
import java.time.Instant
import java.util.concurrent.TimeUnit

/**
 * Checks one incoming SMS. NOTHING is shown to the user until the server has finished every
 * database lookup and link check and decided FRAUD ("Surely fraud") or SPAM ("Surely spam").
 *  1. on-device pass: only extracts the links + warning codes to send (never shown)
 *  2. server check (sender + links + codes; full text only if the user opted in)
 *  3. poll until the checks are complete (retried later if the server is slow or offline)
 *  4. FRAUD/SPAM → label + notification. Automatic reporting → upload this sender's messages.
 */
class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    companion object {
        private const val KEY_ID = "message_id"
        private const val POLL_EVERY_MS = 3_000L
        private const val POLL_MAX = 30          // ~90 s, then WorkManager retries with backoff

        fun enqueue(context: Context, messageId: Long, now: Boolean = false) {
            val req = OneTimeWorkRequestBuilder<ScanWorker>()
                .setInputData(workDataOf(KEY_ID to messageId))
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            // now = true replaces a check that is waiting out its retry pause, so it runs immediately
            WorkManager.getInstance(context).enqueueUniqueWork("scan-$messageId",
                if (now) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP, req)
        }

        /** After (re)connecting to a server: check again, right away, every message still without a decision. */
        suspend fun recheckUnfinished(context: Context) {
            context.container.db.scanDao().unfinished().forEach { enqueue(context, it.messageId, now = true) }
        }
    }

    private val c = ctx.container

    override suspend fun getForegroundInfo(): ForegroundInfo {
        val n = c.notifier.backgroundNotification()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(42, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            ForegroundInfo(42, n)
        }
    }

    override suspend fun doWork(): Result {
        val id = inputData.getLong(KEY_ID, -1)
        val msg = c.sms.message(id) ?: return Result.success()
        if (msg.type != Telephony.Sms.MESSAGE_TYPE_INBOX) return Result.success()
        val s = c.settings.snapshot()
        // No server checks → no decision → nothing is ever shown for this message.
        if (!s.consentServer || s.deviceToken == null) return Result.success()

        val dao = c.db.scanDao()
        var row = dao.get(id) ?: ScanResultEntity(
            messageId = id, threadId = msg.threadId, sender = msg.address,
            status = "PENDING", verdict = "PENDING", score = 0, reasonsJson = "[]",
        ).also { dao.upsert(it) }
        if (row.status == "COMPLETE") return Result.success()

        val name = c.sms.contactName(msg.address)
        // 1. on-device pass — only decides WHAT to send, never shown
        val local = c.scanner.scan(msg.address, msg.body, inContacts = name != null)

        // 2 + 3. server decision
        val out: ScanOut = try {
            var res = c.api.service.scan(ScanIn(
                messageId = id.toString(),
                sender = msg.address,
                receivedAt = Instant.ofEpochMilli(msg.date).toString(),
                simSlot = msg.subId.takeIf { it >= 0 },
                urls = local.urls,
                local = LocalResult(local.score.score, local.reasonCodes),
                features = ScanFeatures(inContacts = name != null),
                text = if (s.shareText) msg.body else null,
            ))
            var polls = 0
            while (res.status != "complete" && polls++ < POLL_MAX) {
                delay(POLL_EVERY_MS)
                res = c.api.service.getScan(res.scanId)
            }
            res
        } catch (e: IOException) {
            return Result.retry()                  // offline / server down: stays unlabelled, tries again later
        } catch (e: HttpException) {
            return if (e.code() >= 500) Result.retry() else Result.success()
        }
        if (out.status != "complete") {
            dao.upsert(row.copy(status = "PARTIAL", serverScanId = out.scanId, updatedAt = System.currentTimeMillis()))
            return Result.retry()
        }

        row = save(c, row, out)
        // 4. tell the user — only for a decision
        if (row.verdict == "FRAUD" || row.verdict == "SPAM") {
            c.notifier.showVerdict(msg, name, row.verdict, out.reasons, Reporting.statusLine(row))
        }
        val rep = out.report
        if (rep != null && rep.needsLog) {        // automatic mode: the server asks for this sender's messages
            try {
                val ref = c.api.service.reportLog(ReportLogIn(out.scanId, Reporting.smsLog(c, msg.threadId, msg.address)))
                dao.upsert(row.copy(reportStatus = ref.status, updatedAt = System.currentTimeMillis()))
            } catch (e: IOException) {
                return Result.retry()
            }
        }
        return Result.success()
    }
}

/** Saves a server decision into the local cache that the UI observes. */
suspend fun save(c: com.scamshield.sms.AppContainer, row: ScanResultEntity, out: ScanOut): ScanResultEntity {
    val json = c.api.json
    val strings = ListSerializer(String.serializer())
    val updated = row.copy(
        status = if (out.status == "complete") "COMPLETE" else "PARTIAL",
        verdict = out.verdict,
        score = out.score,
        reasonsJson = json.encodeToString(ListSerializer(Reason.serializer()), out.reasons),
        urlsJson = json.encodeToString(ListSerializer(UrlOut.serializer()), out.urls),
        serverScanId = out.scanId,
        impersonatedBrand = out.impersonatedBrand,
        reportId = out.report?.id ?: row.reportId,
        reportStatus = out.report?.status ?: row.reportStatus,
        reportMode = out.report?.mode ?: row.reportMode,
        reportIntendedJson = out.report?.let { json.encodeToString(ListSerializer(JsonObject.serializer()), it.intended) }
            ?: row.reportIntendedJson,
        portalsJson = json.encodeToString(ListSerializer(Portal.serializer()), out.portals),
        canReport = out.canReport,
        reportPreviewJson = json.encodeToString(strings, out.reportPreview),
        checksJson = json.encodeToString(ListSerializer(Check.serializer()), out.checks),
        evidenceJson = json.encodeToString(strings, out.evidence),
        updatedAt = System.currentTimeMillis(),
    )
    c.db.scanDao().upsert(updated)
    return updated
}

/** Daily download of blocked senders + phishing domain hashes for offline checks. */
class BlocklistSyncWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    companion object {
        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<BlocklistSyncWorker>(12, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork("blocklist-sync", ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun runNow(context: Context) {
            WorkManager.getInstance(context).enqueueUniqueWork(
                "blocklist-sync-now", ExistingWorkPolicy.REPLACE,
                OneTimeWorkRequestBuilder<BlocklistSyncWorker>().build(),
            )
        }
    }

    override suspend fun doWork(): Result {
        val c = applicationContext.container
        val s = c.settings.snapshot()
        if (s.deviceToken == null) return Result.success()
        return try {
            val out = c.api.service.blocklist(s.blocklistVersion)
            c.blocklist.replace(out.full, out.senders, out.domainHashes)
            c.settings.update { it.copy(blocklistVersion = out.version) }
            Result.success()
        } catch (e: IOException) {
            Result.retry()
        } catch (e: HttpException) {
            Result.retry()
        }
    }
}
