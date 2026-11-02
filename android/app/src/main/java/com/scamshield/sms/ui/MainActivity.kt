package com.scamshield.sms.ui

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.scamshield.sms.container
import com.scamshield.sms.core.data.AppSettings
import com.scamshield.sms.notify.Notifier
import com.scamshield.sms.ui.screens.ConversationsScreen
import com.scamshield.sms.ui.screens.NewMessageScreen
import com.scamshield.sms.ui.screens.OnboardingScreen
import com.scamshield.sms.ui.screens.ReportsScreen
import com.scamshield.sms.ui.screens.SettingsScreen
import com.scamshield.sms.ui.screens.ThreadScreen

fun Context.isDefaultSmsApp(): Boolean =
    getSystemService(RoleManager::class.java).isRoleHeld(RoleManager.ROLE_SMS)

/** Where an incoming intent should take the user. */
sealed interface Deeplink {
    data class Thread(val threadId: Long) : Deeplink
    data class Compose(val address: String, val body: String) : Deeplink
}

class MainActivity : ComponentActivity() {
    private val pending = mutableStateOf<Deeplink?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        pending.value = parse(intent)
        setContent {
            ScamShieldTheme {
                val settings by container.settings.flow.collectAsState(initial = null)
                settings?.let { App(it, pending.value) { pending.value = null } }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pending.value = parse(intent)
    }

    private fun parse(intent: Intent?): Deeplink? {
        intent ?: return null
        val thread = intent.getLongExtra(Notifier.EXTRA_THREAD, -1)
        if (thread > 0) return Deeplink.Thread(thread)
        val data: Uri? = intent.data
        val text = intent.getStringExtra(Intent.EXTRA_TEXT) ?: intent.getStringExtra("sms_body") ?: ""
        return when {
            data != null && data.scheme in setOf("sms", "smsto", "mms", "mmsto") -> {
                val ssp = data.schemeSpecificPart ?: ""
                val body = Uri.parse("x:?" + ssp.substringAfter('?', "")).getQueryParameter("body") ?: text
                Deeplink.Compose(ssp.substringBefore('?').substringBefore(',').trim(), body)
            }
            intent.action == Intent.ACTION_SEND && text.isNotEmpty() -> Deeplink.Compose("", text)
            else -> null
        }
    }
}

object Routes {
    const val ONBOARDING = "onboarding"
    const val CONVERSATIONS = "conversations"
    const val THREAD = "thread/{threadId}"
    const val NEW = "new?address={address}&body={body}"
    const val REPORTS = "reports"
    const val SETTINGS = "settings"
    fun thread(id: Long) = "thread/$id"
    fun new(address: String = "", body: String = "") = "new?address=${Uri.encode(address)}&body=${Uri.encode(body)}"
}

@Composable
private fun App(settings: AppSettings, deeplink: Deeplink?, consumed: () -> Unit) {
    val nav: NavHostController = rememberNavController()
    val start = if (settings.onboarded) Routes.CONVERSATIONS else Routes.ONBOARDING
    LaunchedEffect(deeplink, settings.onboarded) {
        if (deeplink != null && settings.onboarded) {
            when (deeplink) {
                is Deeplink.Thread -> nav.navigate(Routes.thread(deeplink.threadId))
                is Deeplink.Compose -> nav.navigate(Routes.new(deeplink.address, deeplink.body))
            }
            consumed()
        }
    }
    NavHost(nav, startDestination = start) {
        composable(Routes.ONBOARDING) {
            OnboardingScreen(onDone = {
                nav.navigate(Routes.CONVERSATIONS) { popUpTo(Routes.ONBOARDING) { inclusive = true } }
            })
        }
        composable(Routes.CONVERSATIONS) {
            ConversationsScreen(
                onOpen = { nav.navigate(Routes.thread(it)) },
                onNew = { nav.navigate(Routes.new()) },
                onReports = { nav.navigate(Routes.REPORTS) },
                onSettings = { nav.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.THREAD, arguments = listOf(navArgument("threadId") { type = NavType.LongType })) {
            ThreadScreen(threadId = it.arguments!!.getLong("threadId"), onBack = { nav.popBackStack() })
        }
        composable(
            Routes.NEW,
            arguments = listOf(
                navArgument("address") { type = NavType.StringType; defaultValue = "" },
                navArgument("body") { type = NavType.StringType; defaultValue = "" },
            ),
        ) {
            NewMessageScreen(
                initialAddress = it.arguments?.getString("address").orEmpty(),
                initialBody = it.arguments?.getString("body").orEmpty(),
                onBack = { nav.popBackStack() },
                onSent = { threadId -> nav.navigate(Routes.thread(threadId)) { popUpTo(Routes.CONVERSATIONS) } },
            )
        }
        composable(Routes.REPORTS) { ReportsScreen(onBack = { nav.popBackStack() }, onOpenThread = { nav.navigate(Routes.thread(it)) }) }
        composable(Routes.SETTINGS) { SettingsScreen(onBack = { nav.popBackStack() }) }
    }
}
