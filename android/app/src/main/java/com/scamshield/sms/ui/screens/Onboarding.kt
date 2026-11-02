package com.scamshield.sms.ui.screens

import android.Manifest
import android.app.Activity
import android.app.role.RoleManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.material3.MenuAnchorType
import com.scamshield.sms.BuildConfig
import com.scamshield.sms.R
import com.scamshield.sms.container
import com.scamshield.sms.core.network.syncRegistration
import com.scamshield.sms.ui.isDefaultSmsApp
import com.scamshield.sms.work.BlocklistSyncWorker
import kotlinx.coroutines.launch

val STATES = listOf(
    "PB" to "Punjab", "CH" to "Chandigarh", "HR" to "Haryana", "DL" to "Delhi", "HP" to "Himachal Pradesh",
    "JK" to "Jammu & Kashmir", "RJ" to "Rajasthan", "UP" to "Uttar Pradesh", "UK" to "Uttarakhand",
    "MH" to "Maharashtra", "GJ" to "Gujarat", "KA" to "Karnataka", "TN" to "Tamil Nadu", "KL" to "Kerala",
    "TG" to "Telangana", "AP" to "Andhra Pradesh", "WB" to "West Bengal", "BR" to "Bihar", "OD" to "Odisha",
    "MP" to "Madhya Pradesh", "CG" to "Chhattisgarh", "JH" to "Jharkhand", "AS" to "Assam", "GA" to "Goa",
)

@Composable
fun OnboardingScreen(onDone: () -> Unit) {
    var step by remember { mutableIntStateOf(0) }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(20.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        when (step) {
            0 -> Intro { step = 1 }
            1 -> DefaultAppStep { step = 2 }
            2 -> ConsentStep { step = 3 }
            else -> StateStep(onDone)
        }
    }
}

@Composable
private fun Intro(next: () -> Unit) {
    Spacer(Modifier.height(32.dp))
    Icon(Icons.Default.Shield, null, tint = MaterialTheme.colorScheme.primary,
        modifier = Modifier.fillMaxWidth().height(72.dp))
    Text("ScamShield SMS", style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth())
    Text(
        "A complete SMS app that checks every message for scams: the sender, the words used, and every link " +
            "(links are opened in a secure server sandbox, never on your phone).",
        style = MaterialTheme.typography.bodyLarge,
    )
    Text(stringResource(R.string.disclaimer), style = MaterialTheme.typography.bodySmall)
    Button(onClick = next, modifier = Modifier.fillMaxWidth()) { Text("Get started") }
}

@Composable
private fun DefaultAppStep(next: () -> Unit) {
    val ctx = LocalContext.current
    var isDefault by remember { mutableStateOf(ctx.isDefaultSmsApp()) }
    val perms = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { next() }
    val role = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        isDefault = r.resultCode == Activity.RESULT_OK || ctx.isDefaultSmsApp()
    }
    Text("Step 1 · Make ScamShield your SMS app", style = MaterialTheme.typography.titleLarge)
    Text(
        "Android only lets the default SMS app see every message as it arrives. Your existing messages stay " +
            "where they are, and you can switch back any time in Settings → Apps → Default apps.",
    )
    Card { Text(
        "Sideloaded APK? If the option is greyed out: App info → ⋮ → Allow restricted settings, then try again.",
        Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall,
    ) }
    if (!isDefault) {
        Button(onClick = {
            val rm = ctx.getSystemService(RoleManager::class.java)
            role.launch(rm.createRequestRoleIntent(RoleManager.ROLE_SMS))
        }, modifier = Modifier.fillMaxWidth()) { Text("Set as default SMS app") }
    } else {
        Text("✓ ScamShield is your default SMS app", color = MaterialTheme.colorScheme.primary)
        Button(onClick = {
            perms.launch(arrayOf(
                Manifest.permission.READ_CONTACTS, Manifest.permission.READ_PHONE_STATE,
                Manifest.permission.POST_NOTIFICATIONS,
            ))
        }, modifier = Modifier.fillMaxWidth()) { Text("Continue") }
    }
    OutlinedButton(onClick = next, modifier = Modifier.fillMaxWidth()) { Text("Skip for now") }
}

@Composable
private fun ConsentStep(next: () -> Unit) {
    val c = LocalContext.current.container
    val scope = rememberCoroutineScope()
    var server by remember { mutableStateOf(true) }
    var reportMode by remember { mutableStateOf("manual") }
    var shareText by remember { mutableStateOf(false) }
    Text("Step 2 · Your choices", style = MaterialTheme.typography.titleLarge)
    ConsentRow(stringResource(R.string.consent_server), server) { server = it }
    if (!server) Text(stringResource(R.string.consent_server_needed), style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.error)
    ConsentRow(stringResource(R.string.consent_share_text), shareText, enabled = server) { shareText = it }
    ReportModePicker(reportMode, enabled = server) { reportMode = it }
    Text(stringResource(R.string.decision_rule), style = MaterialTheme.typography.bodySmall)
    Text("You can change these any time in Settings. Withdrawing consent stops future checks and reports.",
        style = MaterialTheme.typography.bodySmall)
    Button(onClick = {
        scope.launch {
            c.settings.update {
                it.copy(consentServer = server, reportMode = reportMode, shareText = shareText,
                    consentVersion = BuildConfig.CONSENT_VERSION)
            }
            next()
        }
    }, modifier = Modifier.fillMaxWidth()) { Text("Continue") }
}

/** "When a message is surely fraud": report automatically, or ask me first (manual Report button). */
@Composable
fun ReportModePicker(mode: String, enabled: Boolean = true, onChange: (String) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp).selectableGroup(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.report_mode_title), style = MaterialTheme.typography.titleSmall)
            listOf(
                Triple("manual", R.string.report_mode_manual, R.string.report_mode_manual_desc),
                Triple("auto", R.string.report_mode_auto, R.string.report_mode_auto_desc),
            ).forEach { (value, label, desc) ->
                Row(
                    Modifier.fillMaxWidth().selectable(selected = mode == value, enabled = enabled, role = Role.RadioButton,
                        onClick = { onChange(value) }).padding(vertical = 4.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    RadioButton(selected = mode == value, onClick = null, enabled = enabled)
                    Column(Modifier.padding(start = 8.dp)) {
                        Text(stringResource(label), style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(desc), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
fun ConsentRow(text: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f).padding(end = 12.dp), style = MaterialTheme.typography.bodyMedium)
            Switch(checked = checked && enabled, onCheckedChange = onChange, enabled = enabled)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StatePicker(selected: String?, onSelect: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }) {
        OutlinedTextField(
            value = STATES.firstOrNull { it.first == selected }?.second ?: "Choose your state",
            onValueChange = {}, readOnly = true, label = { Text("State (for cyber-cell routing)") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(open) },
            modifier = Modifier.menuAnchor(MenuAnchorType.PrimaryNotEditable).fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            STATES.forEach { (code, name) ->
                DropdownMenuItem(text = { Text(name) }, onClick = { onSelect(code); open = false })
            }
        }
    }
}

@Composable
private fun StateStep(onDone: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<String?>("PB") }
    var name by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("") }
    var apiKey by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    Text("Step 3 · Where should reports go?", style = MaterialTheme.typography.titleLarge)
    StatePicker(state) { state = it }
    OutlinedTextField(name, { name = it }, label = { Text("Your name on reports (optional)") },
        modifier = Modifier.fillMaxWidth(), singleLine = true)
    Text("ScamShield server (leave empty to use ${BuildConfig.API_BASE_URL})", style = MaterialTheme.typography.bodySmall)
    OutlinedTextField(server, { server = it.trim() }, label = { Text("Server URL (optional)") },
        placeholder = { Text("https://api.yourdomain.in") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
    OutlinedTextField(apiKey, { apiKey = it.trim() }, label = { Text("API key (optional)") },
        modifier = Modifier.fillMaxWidth(), singleLine = true)
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    Button(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
        busy = true
        scope.launch {
            val retrying = error != null
            c.settings.update {
                it.copy(stateCode = state, reporterName = name.ifBlank { null },
                    serverUrl = server.ifBlank { null }, apiKey = apiKey.ifBlank { null })
            }
            error = syncRegistration(c)
            busy = false
            // Server problems never block the app: the second tap continues with on-device checks only.
            if (error == null || retrying) {
                c.settings.update { it.copy(onboarded = true) }
                if (c.settings.snapshot().deviceToken != null) BlocklistSyncWorker.runNow(ctx)
                BlocklistSyncWorker.schedule(ctx)
                onDone()
            }
        }
    }) { Text(if (busy) "Connecting…" else if (error != null) "Continue without server" else "Finish") }
}
