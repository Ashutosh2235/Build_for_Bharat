package com.scamshield.sms.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import com.scamshield.sms.BuildConfig
import com.scamshield.sms.R
import com.scamshield.sms.container
import com.scamshield.sms.core.network.syncRegistration
import com.scamshield.sms.ui.VerdictChip
import com.scamshield.sms.work.BlocklistSyncWorker
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SimpleScaffold(title: String, onBack: () -> Unit, content: @Composable (Modifier) -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(title) },
            navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad -> content(Modifier.padding(pad)) }
}

@Composable
fun NewMessageScreen(initialAddress: String, initialBody: String, onBack: () -> Unit, onSent: (Long) -> Unit) {
    val c = LocalContext.current.container
    val scope = rememberCoroutineScope()
    var to by remember { mutableStateOf(initialAddress) }
    var body by remember { mutableStateOf(initialBody) }
    SimpleScaffold("New message", onBack) { m ->
        Column(m.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(to, { to = it }, label = { Text("To (phone number)") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone), modifier = Modifier.fillMaxWidth())
            OutlinedTextField(body, { body = it }, label = { Text("Message") }, minLines = 3, modifier = Modifier.fillMaxWidth())
            Button(enabled = to.isNotBlank() && body.isNotBlank(), modifier = Modifier.fillMaxWidth(), onClick = {
                scope.launch {
                    val address = to.trim()
                    c.smsSender.send(address, body)
                    onSent(c.sms.threadIdFor(address))
                }
            }) { Text("Send") }
        }
    }
}

@Composable
fun ReportsScreen(onBack: () -> Unit, onOpenThread: (Long) -> Unit) {
    val c = LocalContext.current.container
    val rows by remember { c.db.scanDao().observeReports() }.collectAsState(initial = emptyList())
    SimpleScaffold("Scam reports", onBack) { m ->
        if (rows.isEmpty()) {
            Column(m.fillMaxSize().padding(24.dp)) {
                Text("No reports yet. When a message is confirmed as a scam, the report appears here.")
            }
        } else {
            LazyColumn(m.fillMaxSize()) {
                items(rows, key = { it.messageId }) { r ->
                    Column(Modifier.fillMaxWidth().clickable { onOpenThread(r.threadId) }.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(r.reportId ?: "", style = MaterialTheme.typography.titleSmall)
                            VerdictChip(r.verdict)
                        }
                        Text("From ${r.sender}", style = MaterialTheme.typography.bodyMedium)
                        Text(reportStatusText(r.reportStatus, r.reportMode), style = MaterialTheme.typography.bodySmall)
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val scope = rememberCoroutineScope()
    val s by c.settings.flow.collectAsState(initial = null)
    var message by remember { mutableStateOf<String?>(null) }
    val settings = s ?: return
    fun save(block: (com.scamshield.sms.core.data.AppSettings) -> com.scamshield.sms.core.data.AppSettings) {
        scope.launch {
            c.settings.update(block)
            message = syncRegistration(c) ?: "Saved"
        }
    }
    SimpleScaffold("Settings", onBack) { m ->
        Column(m.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Privacy & reporting", style = MaterialTheme.typography.titleMedium)
            ConsentRow(stringResource(R.string.consent_server), settings.consentServer) { v ->
                save { it.copy(consentServer = v) }
            }
            if (!settings.consentServer) Text(stringResource(R.string.consent_server_needed),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            ReportModePicker(settings.reportMode, enabled = settings.consentServer) { m -> save { it.copy(reportMode = m) } }
            ConsentRow(stringResource(R.string.consent_share_text), settings.shareText, enabled = settings.consentServer) { v ->
                save { it.copy(shareText = v) }
            }
            StatePicker(settings.stateCode) { code -> save { it.copy(stateCode = code) } }
            HorizontalDivider()
            Text("Server", style = MaterialTheme.typography.titleMedium)
            ServerFields(settings) { url, key ->
                scope.launch {
                    // A different server doesn't know this phone: forget the old token and register again.
                    c.settings.update { it.copy(serverUrl = url, apiKey = key, deviceToken = null, blocklistVersion = null) }
                    message = syncRegistration(c)
                        ?: if (c.settings.snapshot().deviceToken == null) "Server checks are off — switch on the first option above"
                        else "Connected to ${url.ifBlank { BuildConfig.API_BASE_URL }}"
                }
            }
            Text(if (settings.deviceToken != null) "Connected" else "Not connected — no labels are shown until the server is connected",
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { scope.launch { message = syncRegistration(c) ?: "Connected" } }) { Text("Reconnect") }
                OutlinedButton(onClick = { BlocklistSyncWorker.runNow(ctx); message = "Blocklist update started" }) {
                    Text("Update blocklist")
                }
            }
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            HorizontalDivider()
            TestTools(onResult = { message = it })
            HorizontalDivider()
            Text("Rules v${c.ruleSet.version} · app ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.decision_rule), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.disclaimer), style = MaterialTheme.typography.bodySmall)
        }
    }
}


@Composable
private fun ServerFields(settings: com.scamshield.sms.core.data.AppSettings, onSave: (String, String) -> Unit) {
    var url by remember { mutableStateOf(settings.serverUrl ?: "") }
    var key by remember { mutableStateOf(settings.apiKey ?: "") }
    OutlinedTextField(url, { url = it.trim() }, label = { Text("Server URL") }, singleLine = true,
        placeholder = { Text(BuildConfig.API_BASE_URL) },
        supportingText = { Text("e.g. https://api.yourdomain.in  ·  empty = built-in default") },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth())
    OutlinedTextField(key, { key = it.trim() }, label = { Text("API key") }, singleLine = true,
        supportingText = { Text("API_KEY from the server's .env  ·  empty = built-in") },
        modifier = Modifier.fillMaxWidth())
    Button(onClick = { onSave(url, key) }) { Text("Save & connect") }
}

/** Test messages and what the server should decide for each (see docs/3_MANUAL_TESTING.md). */
private fun samples(server: String) = listOf(
    Triple("Fraud: fake bank KYC link", "9123456780",
        "Dear HDFC customer, your account will be blocked today. Update KYC at https://hdfcbank-kyc-update.co/login and share OTP to verify."),
    Triple("Fraud: demo phishing page", "9123456781",
        "Bharat Demo Bank: your account is suspended due to pending KYC. Verify immediately at ${server.trimEnd('/')}/demo/kyc"),
    Triple("Spam: OTP request, no link", "9123456782",
        "Sir I am from ICICI bank, your account will be blocked today. Please share the OTP to stop it."),
    Triple("No label: weak lottery text", "7300011223",
        "बधाई हो! आपने KBC लॉटरी में 25 लाख जीते हैं। इनाम पाने के लिए तुरंत संपर्क करें।"),
    Triple("No label: genuine bank OTP", "VM-HDFCBK-T",
        "482913 is your OTP for txn of Rs 500.00 at Amazon. Do not share it with anyone. -HDFC Bank"),
)

/**
 * Puts a fake INCOMING message into the inbox and runs the normal pipeline (notification, scan,
 * report). For testing on one phone without a second SIM. Delete the thread afterwards.
 */
@Composable
private fun TestTools(onResult: (String) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val settings by ctx.container.settings.flow.collectAsState(initial = null)
    val presets = samples(settings?.serverUrl?.takeIf { it.isNotBlank() } ?: BuildConfig.API_BASE_URL)
    var sender by remember { mutableStateOf(presets[0].second) }
    var text by remember { mutableStateOf(presets[0].third) }
    Text("Test tools", style = MaterialTheme.typography.titleMedium)
    Text("Simulate an incoming SMS (needs ScamShield to be the default SMS app). It appears in your inbox " +
        "like a real one and goes through the full server check. A label appears only once the check is complete.",
        style = MaterialTheme.typography.bodySmall)
    presets.chunked(2).forEach { row ->
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            row.forEach { (label, s, t) ->
                OutlinedButton(onClick = { sender = s; text = t }, modifier = Modifier.weight(1f)) {
                    Text(label, style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
    OutlinedTextField(sender, { sender = it }, label = { Text("From") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(text, { text = it }, label = { Text("Message") }, minLines = 3, modifier = Modifier.fillMaxWidth())
    Button(enabled = sender.isNotBlank() && text.isNotBlank(), onClick = {
        scope.launch {
            val thread = com.scamshield.sms.core.telephony.deliverIncoming(
                ctx, sender.trim(), text, System.currentTimeMillis(), android.telephony.SubscriptionManager.getDefaultSmsSubscriptionId(),
            )
            onResult(if (thread == null) "Could not add the message — is ScamShield the default SMS app?"
            else "Test message delivered — check the notification and the Messages list")
        }
    }) { Text("Simulate incoming SMS") }
}
