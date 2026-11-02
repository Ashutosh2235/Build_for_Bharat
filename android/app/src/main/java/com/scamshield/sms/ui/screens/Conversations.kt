package com.scamshield.sms.ui.screens

import android.app.role.RoleManager
import android.text.format.DateUtils
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material.icons.filled.Assignment
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.scamshield.sms.container
import com.scamshield.sms.core.telephony.Conversation
import com.scamshield.sms.ui.ScamRed
import com.scamshield.sms.ui.VerdictChip
import com.scamshield.sms.ui.isDefaultSmsApp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationsScreen(onOpen: (Long) -> Unit, onNew: () -> Unit, onReports: () -> Unit, onSettings: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val conversations by remember { c.sms.observeConversations() }.collectAsState(initial = null)
    val levels by remember { c.db.scanDao().observeThreadLevels() }.collectAsState(initial = emptyList())
    val levelMap = remember(levels) { levels.associate { it.threadId to it.level } }
    var isDefault by remember { mutableStateOf(ctx.isDefaultSmsApp()) }
    val role = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        isDefault = ctx.isDefaultSmsApp()
    }
    LaunchedEffect(Unit) { isDefault = ctx.isDefaultSmsApp() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Messages") },
                actions = {
                    IconButton(onClick = onReports) { Icon(Icons.Default.Assignment, "Reports") }
                    IconButton(onClick = onSettings) { Icon(Icons.Default.Settings, "Settings") }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(onClick = onNew, icon = { Icon(Icons.AutoMirrored.Filled.Message, null) },
                text = { Text("New") })
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            if (!isDefault) {
                Card(
                    Modifier.fillMaxWidth().padding(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("ScamShield is not your default SMS app, so new messages are not being checked.",
                            Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                        TextButton(onClick = {
                            role.launch(ctx.getSystemService(RoleManager::class.java).createRequestRoleIntent(RoleManager.ROLE_SMS))
                        }) { Text("Fix") }
                    }
                }
            }
            when (val list = conversations) {
                null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("Loading…") }
                else -> if (list.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("No messages yet") }
                } else {
                    LazyColumn {
                        items(list, key = { it.threadId }) { conv ->
                            ConversationRow(conv, levelMap[conv.threadId]) { onOpen(conv.threadId) }
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ConversationRow(conv: Conversation, level: Int?, onClick: () -> Unit) {
    val title = conv.displayName ?: conv.address
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            shape = CircleShape,
            color = if (level == 2) ScamRed else MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.size(42.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(title.take(1).uppercase(),
                    color = if (level == 2) MaterialTheme.colorScheme.onError else MaterialTheme.colorScheme.onPrimaryContainer)
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, fontWeight = if (conv.unread > 0) FontWeight.Bold else FontWeight.Normal,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (level != null && level > 0) {
                    Spacer(Modifier.width(6.dp))
                    VerdictChip(if (level == 2) "FRAUD" else "SPAM")
                }
            }
            Text(conv.snippet, maxLines = 1, overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(DateUtils.getRelativeTimeSpanString(conv.date).toString(), style = MaterialTheme.typography.labelSmall)
            if (conv.unread > 0) {
                Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primary) {
                    Text("${conv.unread}", color = MaterialTheme.colorScheme.onPrimary,
                        style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 6.dp))
                }
            }
        }
    }
}
