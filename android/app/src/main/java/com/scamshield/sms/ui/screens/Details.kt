package com.scamshield.sms.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.scamshield.sms.R
import com.scamshield.sms.container
import com.scamshield.sms.core.data.ScanResultEntity
import com.scamshield.sms.core.network.Check
import com.scamshield.sms.core.network.FeedbackIn
import com.scamshield.sms.core.network.Portal
import com.scamshield.sms.core.network.Reason
import com.scamshield.sms.core.network.UrlOut
import com.scamshield.sms.ui.ScamRed
import com.scamshield.sms.ui.VerdictChip
import com.scamshield.sms.ui.isShown
import com.scamshield.sms.ui.verdictColor
import com.scamshield.sms.work.Reporting
import kotlinx.coroutines.launch
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

private val DEFAULT_PORTALS = listOf(
    Portal("ncrp", "National Cyber Crime Reporting Portal — Report Suspect", "https://cybercrime.gov.in"),
    Portal("chakshu", "Sanchar Saathi — Chakshu", "https://sancharsaathi.gov.in/sfc/"),
    Portal("helpline", "Lost money? Call 1930", "tel:1930"),
)

private fun statusMark(status: String) = when (status) {
    "hit" -> "⚠"
    "clean" -> "✓"
    "unavailable" -> "?"
    else -> "–"
}

private fun statusWord(status: String) = when (status) {
    "hit" -> "flagged"
    "clean" -> "nothing found"
    "unavailable" -> "could not be reached"
    else -> "not used"
}

/**
 * "Why?" sheet — opened only for FRAUD / SPAM decisions. Shows what decided it, every database and
 * link check that was consulted, and the report section (automatic status or the manual Report button).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanDetailsSheet(initial: ScanResultEntity, address: String, messageBody: String, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val json = c.api.json
    val scope = rememberCoroutineScope()
    // Live: updates when a report is made or the decision arrives
    val scan by remember(initial.messageId) { c.db.scanDao().observe(initial.messageId) }.collectAsState(initial = initial)
    val row = scan ?: initial
    val strings = ListSerializer(String.serializer())
    val reasons = remember(row) { runCatching { json.decodeFromString(ListSerializer(Reason.serializer()), row.reasonsJson) }.getOrDefault(emptyList()) }
    val urls = remember(row) { runCatching { json.decodeFromString(ListSerializer(UrlOut.serializer()), row.urlsJson) }.getOrDefault(emptyList()) }
    val dbChecks = remember(row) { runCatching { json.decodeFromString(ListSerializer(Check.serializer()), row.checksJson) }.getOrDefault(emptyList()) }
    val preview = remember(row) { row.reportPreviewJson?.let { runCatching { json.decodeFromString(strings, it) }.getOrNull() }.orEmpty() }
    val portals = remember(row) {
        row.portalsJson?.let { runCatching { json.decodeFromString(ListSerializer(Portal.serializer()), it) }.getOrNull() }
            ?.takeIf { it.isNotEmpty() } ?: DEFAULT_PORTALS
    }
    val sentTo = remember(row) {
        row.reportIntendedJson?.let { runCatching { json.decodeFromString(ListSerializer(JsonObject.serializer()), it) }.getOrNull() }
            .orEmpty().mapNotNull { it["label"]?.jsonPrimitive?.content }.distinct()
    }
    val fraud = row.verdict == "FRAUD"
    var confirmReport by remember { mutableStateOf(false) }
    var confirm1909 by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }
    var feedbackSent by remember { mutableStateOf(row.feedback) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (!isShown(row.verdict)) {
                Text("No label for this message.", style = MaterialTheme.typography.bodyLarge)
                return@Column
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                VerdictChip(row.verdict)
                Text("Risk ${row.score}/100", fontWeight = FontWeight.SemiBold, color = verdictColor(row.verdict))
            }
            Text(
                if (fraud) "Confirmed by ScamShield's database or link checks." else
                    "Strong scam/spam signs from the sender and wording. No database or link check confirmed it, so it is not reported.",
                style = MaterialTheme.typography.bodyMedium,
            )

            Text("Why", style = MaterialTheme.typography.titleMedium)
            reasons.forEach { r -> Text("• ${r.text}" + (r.detail?.let { " ($it)" } ?: ""), style = MaterialTheme.typography.bodyMedium) }

            HorizontalDivider()
            Text("What was checked", style = MaterialTheme.typography.titleMedium)
            dbChecks.forEach { CheckRow(it) }
            if (urls.isEmpty()) Text("No links in this message.", style = MaterialTheme.typography.bodySmall)
            urls.forEach { u ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(u.input, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                        if (u.final != null && u.final != u.input) Text("→ ends at ${u.final}", style = MaterialTheme.typography.bodySmall)
                        if (u.hops > 1) Text("${u.hops} redirect steps", style = MaterialTheme.typography.labelSmall)
                        u.checks.forEach { CheckRow(it) }
                        u.screenshotUrl?.let {
                            Text("Opened in ScamShield's isolated browser (not on your phone):", style = MaterialTheme.typography.labelSmall)
                            AsyncImage(model = it, contentDescription = "Screenshot of the page from the sandbox",
                                contentScale = ContentScale.FillWidth, modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp))
                        }
                    }
                }
            }

            if (fraud) {
                HorizontalDivider()
                Text("Report", style = MaterialTheme.typography.titleMedium)
                when {
                    row.reportId != null -> {
                        Text("${row.reportId}: ${reportStatusText(row.reportStatus, row.reportMode)}")
                        if (sentTo.isNotEmpty()) Text("To: ${sentTo.joinToString()}", style = MaterialTheme.typography.bodySmall)
                    }
                    row.canReport -> {
                        Text("Reporting is set to manual. Nothing has been sent.", style = MaterialTheme.typography.bodySmall)
                        Button(
                            enabled = !busy, onClick = { confirmReport = true }, modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = ScamRed),
                        ) { Text(if (busy) "Reporting…" else "Report to authorities") }
                    }
                    else -> Text("Not reported (automatic reporting is off on the server).", style = MaterialTheme.typography.bodySmall)
                }
                note?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                Text("You can also report it yourself:", style = MaterialTheme.typography.bodySmall)
                portals.forEach { p -> OutlinedButton(onClick = { openUrl(ctx, p.url) }, modifier = Modifier.fillMaxWidth()) { Text(p.label) } }
            } else {
                HorizontalDivider()
                OutlinedButton(onClick = { confirm1909 = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("Forward to TRAI 1909 (spam complaint)")
                }
            }

            HorizontalDivider()
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = row.serverScanId != null && feedbackSent == null, onClick = {
                    scope.launch {
                        runCatching { c.api.service.feedback(FeedbackIn(row.serverScanId!!, "not_scam")) }
                        c.db.scanDao().upsert(row.copy(feedback = "not_scam"))
                        feedbackSent = "not_scam"
                    }
                }) { Text(if (feedbackSent != null) "Thanks!" else if (fraud) "Not fraud" else "Not spam") }
                if (c.sms.canBlock() && address.isNotEmpty()) {
                    OutlinedButton(onClick = { scope.launch { c.sms.block(address) }; onDismiss() }) { Text("Block sender") }
                }
            }
            Text(stringResource(R.string.disclaimer), style = MaterialTheme.typography.bodySmall)
        }
    }

    if (confirmReport) {
        AlertDialog(
            onDismissRequest = { confirmReport = false },
            title = { Text("Report this fraud?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("ScamShield will send this message, the other messages from $address in this conversation, " +
                        "and the analysis to:")
                    (preview.ifEmpty { listOf("the configured cyber-crime contacts") }).forEach { Text("• $it") }
                    Text("Your other conversations are never sent.", style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmReport = false
                    busy = true
                    scope.launch {
                        note = Reporting.reportNow(c, row)
                        busy = false
                    }
                }) { Text("Report") }
            },
            dismissButton = { TextButton(onClick = { confirmReport = false }) { Text("Cancel") } },
        )
    }
    if (confirm1909) {
        AlertDialog(
            onDismissRequest = { confirm1909 = false },
            title = { Text("Forward to 1909?") },
            text = { Text("Sends this message as an SMS from your SIM to TRAI's spam complaint number 1909 (normal SMS charges apply).") },
            confirmButton = {
                TextButton(onClick = {
                    confirm1909 = false
                    scope.launch { c.smsSender.send("1909", messageBody) }
                }) { Text("Forward") }
            },
            dismissButton = { TextButton(onClick = { confirm1909 = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun CheckRow(ch: Check) {
    Row {
        Text(statusMark(ch.status), modifier = Modifier.width(20.dp),
            color = if (ch.status == "hit") ScamRed else MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            "${ch.name}: ${statusWord(ch.status)}" + (ch.detail?.let { " — $it" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

fun reportStatusText(status: String?, mode: String?): String = when (status) {
    "awaiting_log" -> "preparing the report…"
    "queued" -> "report queued"
    "sent" -> "sent to the authorities"
    "demo_sent" -> "demo report sent to the team inbox (demo mode — authorities were not emailed)"
    "duplicate" -> "already reported (same sender and link) — added to the earlier report"
    "no_recipient" -> "no verified authority address for your state yet"
    "failed" -> "sending failed — the server will retry"
    "disabled" -> "automatic reports are switched off on the server"
    else -> status ?: "—"
} + if (mode == "demo" && status != "demo_sent") " (demo mode)" else ""
