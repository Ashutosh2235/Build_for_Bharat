package com.scamshield.sms.work

import com.scamshield.sms.AppContainer
import com.scamshield.sms.core.data.ScanResultEntity
import com.scamshield.sms.core.network.LogMessage
import com.scamshield.sms.core.network.ManualReportIn
import java.time.Instant

/** Reporting a "surely fraud" message (automatic mode uploads the log from ScanWorker). */
object Reporting {

    /** The "SMS log" of a report: ONLY the messages from this sender in this thread (max 50). */
    fun smsLog(c: AppContainer, threadId: Long, address: String): List<LogMessage> =
        c.sms.messagesFromSender(threadId, address).takeLast(50).map {
            LogMessage(it.address, it.body, Instant.ofEpochMilli(it.date).toString(), it.subId.takeIf { s -> s >= 0 })
        }

    /** Manual mode: the user confirmed the Report dialog. Returns null on success, else an error text. */
    suspend fun reportNow(c: AppContainer, row: ScanResultEntity): String? {
        val scanId = row.serverScanId ?: return "This message hasn't been checked by the server yet."
        return try {
            val ref = c.api.service.report(ManualReportIn(scanId, smsLog(c, row.threadId, row.sender)))
            c.db.scanDao().upsert(row.copy(
                reportId = ref.id, reportStatus = ref.status, reportMode = ref.mode, canReport = false,
                reportIntendedJson = c.api.json.encodeToString(
                    kotlinx.serialization.builtins.ListSerializer(kotlinx.serialization.json.JsonObject.serializer()), ref.intended,
                ),
                updatedAt = System.currentTimeMillis(),
            ))
            null
        } catch (e: retrofit2.HttpException) {
            if (e.code() == 409) "Only messages decided as surely fraud can be reported." else "Server error (${e.code()}). Try again."
        } catch (e: java.io.IOException) {
            "Server not reachable. Check the connection and try again."
        }
    }

    /** One line for the notification / thread banner. */
    fun statusLine(row: ScanResultEntity): String? = when {
        row.verdict != "FRAUD" -> null
        row.reportId != null && row.reportStatus == "duplicate" -> "Already reported by ScamShield (${row.reportId})"
        row.reportId != null -> if (row.reportMode == "demo") "Report ${row.reportId} sent to the team inbox (demo mode)"
        else "Reported automatically (${row.reportId})"
        row.canReport -> "Tap to review and report it"
        else -> null
    }
}
