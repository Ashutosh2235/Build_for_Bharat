package com.scamshield.sms.core.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "settings")

data class AppSettings(
    val onboarded: Boolean = false,
    val deviceToken: String? = null,
    val stateCode: String? = null,
    val consentVersion: Int = 0,
    val consentServer: Boolean = false,
    /** What happens with a "surely fraud" message: "auto" (report without asking) or "manual" (Report button). */
    val reportMode: String = "manual",
    val shareText: Boolean = false,
    val reporterName: String? = null,
    val reporterPhone: String? = null,
    val blocklistVersion: String? = null,
    /** Overrides BuildConfig.API_BASE_URL / API_KEY (Settings → Server). Lets one APK talk to any backend. */
    val serverUrl: String? = null,
    val apiKey: String? = null,
)

class SettingsStore(private val context: Context) {
    private object K {
        val onboarded = booleanPreferencesKey("onboarded")
        val token = stringPreferencesKey("device_token")
        val state = stringPreferencesKey("state_code")
        val consentVersion = intPreferencesKey("consent_version")
        val consentServer = booleanPreferencesKey("consent_server")
        val reportMode = stringPreferencesKey("report_mode")
        val shareText = booleanPreferencesKey("share_text")
        val name = stringPreferencesKey("reporter_name")
        val phone = stringPreferencesKey("reporter_phone")
        val blVersion = stringPreferencesKey("blocklist_version")
        val serverUrl = stringPreferencesKey("server_url")
        val apiKey = stringPreferencesKey("api_key")
    }

    val flow: Flow<AppSettings> = context.dataStore.data.map { it.toSettings() }

    suspend fun snapshot(): AppSettings = flow.first()

    private fun Preferences.toSettings() = AppSettings(
        onboarded = this[K.onboarded] ?: false,
        deviceToken = this[K.token],
        stateCode = this[K.state],
        consentVersion = this[K.consentVersion] ?: 0,
        consentServer = this[K.consentServer] ?: false,
        reportMode = this[K.reportMode] ?: "manual",
        shareText = this[K.shareText] ?: false,
        reporterName = this[K.name],
        reporterPhone = this[K.phone],
        blocklistVersion = this[K.blVersion],
        serverUrl = this[K.serverUrl],
        apiKey = this[K.apiKey],
    )

    suspend fun update(block: (AppSettings) -> AppSettings) {
        context.dataStore.edit { p ->
            val s = block(p.toSettings())
            p[K.onboarded] = s.onboarded
            s.deviceToken?.let { p[K.token] = it } ?: p.remove(K.token)
            s.stateCode?.let { p[K.state] = it } ?: p.remove(K.state)
            p[K.consentVersion] = s.consentVersion
            p[K.consentServer] = s.consentServer
            p[K.reportMode] = if (s.reportMode == "auto") "auto" else "manual"
            p[K.shareText] = s.shareText
            s.reporterName?.let { p[K.name] = it } ?: p.remove(K.name)
            s.reporterPhone?.let { p[K.phone] = it } ?: p.remove(K.phone)
            s.blocklistVersion?.let { p[K.blVersion] = it } ?: p.remove(K.blVersion)
            s.serverUrl?.takeIf { it.isNotBlank() }?.let { p[K.serverUrl] = it } ?: p.remove(K.serverUrl)
            s.apiKey?.takeIf { it.isNotBlank() }?.let { p[K.apiKey] = it } ?: p.remove(K.apiKey)
        }
    }
}
