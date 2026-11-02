package com.scamshield.sms

import android.app.Application
import android.content.Context
import com.scamshield.sms.core.data.AppDatabase
import com.scamshield.sms.core.data.RoomBlocklist
import com.scamshield.sms.core.data.SettingsStore
import com.scamshield.sms.core.network.ApiClient
import com.scamshield.sms.core.security.LocalScanner
import com.scamshield.sms.core.security.RuleSet
import com.scamshield.sms.core.telephony.SmsRepository
import com.scamshield.sms.core.telephony.SmsSender
import com.scamshield.sms.notify.Notifier
import com.scamshield.sms.work.BlocklistSyncWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Manual dependency container (simpler than Hilt for a hackathon; swap later if wanted). */
class AppContainer(context: Context) {
    val app: Context = context.applicationContext
    val appScope = CoroutineScope(SupervisorJob())
    val settings = SettingsStore(app)
    val db = AppDatabase.build(app)
    val ruleSet: RuleSet by lazy {
        RuleSet.parse(
            app.assets.open("rules.json").bufferedReader().use { it.readText() },
            app.assets.open("brands.json").bufferedReader().use { it.readText() },
        )
    }
    val blocklist = RoomBlocklist(db.blocklistDao())
    val scanner: LocalScanner by lazy { LocalScanner(ruleSet, blocklist) }
    val sms = SmsRepository(app)
    val smsSender = SmsSender(app, sms)
    val api = ApiClient(settings)
    val notifier = Notifier(app)
}

class ScamShieldApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        container.notifier.createChannels()
        container.appScope.launch {
            container.blocklist.load()
            if (container.settings.snapshot().deviceToken != null) BlocklistSyncWorker.schedule(this@ScamShieldApp)
        }
    }
}

val Context.container: AppContainer
    get() = (applicationContext as ScamShieldApp).container
