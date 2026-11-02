package com.scamshield.sms.core.network

import com.scamshield.sms.AppContainer
import com.scamshield.sms.BuildConfig
import com.scamshield.sms.work.ScanWorker

/**
 * Registers the device (first time) or pushes updated consent/state (later).
 * Returns null on success, or a human-readable error. The app keeps working on-device either way.
 */
suspend fun syncRegistration(c: AppContainer): String? {
    val s = c.settings.snapshot()
    // Never registered and no consent → nothing to send (on-device protection only).
    // Already registered → always push, so withdrawn consent reaches the server too.
    if (!s.consentServer && s.deviceToken == null) return null
    val body = RegisterIn(
        appVersion = BuildConfig.VERSION_NAME,
        stateCode = s.stateCode,
        consentVersion = s.consentVersion,
        consentServerCheck = s.consentServer,
        reportMode = s.reportMode,
        reporterName = s.reporterName,
        reporterPhone = s.reporterPhone,
    )
    return try {
        if (s.deviceToken == null) {
            val out = c.api.service.register(body)
            c.settings.update { it.copy(deviceToken = out.deviceToken) }
        } else {
            val r = c.api.service.updateConsent(body)
            if (r.code() == 401) { // server forgot us (DB reset) → register again
                c.settings.update { it.copy(deviceToken = null) }
                return syncRegistration(c)
            }
        }
        if (s.consentServer) ScanWorker.recheckUnfinished(c.app)
        null
    } catch (e: Exception) {
        "Server not reachable (${e.javaClass.simpleName}). Messages arrive normally but get no label until it is reachable; retry from Settings."
    }
}
