package com.scamshield.sms.core.network

import com.scamshield.sms.BuildConfig
import com.scamshield.sms.core.data.SettingsStore
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query
import java.util.concurrent.TimeUnit

// ----------------------------------------------------------------- DTOs (mirror backend/app/schemas.py)
@Serializable
data class RegisterIn(
    @SerialName("app_version") val appVersion: String,
    @SerialName("state_code") val stateCode: String?,
    @SerialName("consent_version") val consentVersion: Int,
    @SerialName("consent_server_check") val consentServerCheck: Boolean,
    /** "auto" = surely-fraud messages are reported without asking; "manual" = the user taps Report */
    @SerialName("report_mode") val reportMode: String,
    @SerialName("reporter_name") val reporterName: String? = null,
    @SerialName("reporter_phone") val reporterPhone: String? = null,
)

@Serializable
data class RegisterOut(@SerialName("device_token") val deviceToken: String)

@Serializable
data class LocalResult(val score: Int, val reasons: List<String>)

@Serializable
data class ScanFeatures(@SerialName("in_contacts") val inContacts: Boolean, val lang: String? = null)

@Serializable
data class ScanIn(
    @SerialName("message_id") val messageId: String,
    val sender: String,
    @SerialName("received_at") val receivedAt: String?,
    @SerialName("sim_slot") val simSlot: Int?,
    val urls: List<String>,
    val local: LocalResult,
    val features: ScanFeatures,
    val text: String? = null,
)

@Serializable
data class Reason(val code: String, val text: String, val points: Int = 0, val detail: String? = null)

/** One database or link check the server consulted: status = hit | clean | unavailable | skipped */
@Serializable
data class Check(val name: String, val status: String, val detail: String? = null)

@Serializable
data class UrlOut(
    val input: String,
    val final: String? = null,
    val host: String? = null,
    val hops: Int = 0,
    @SerialName("screenshot_url") val screenshotUrl: String? = null,
    @SerialName("feed_hits") val feedHits: List<String> = emptyList(),
    val verdict: String? = null,
    val checks: List<Check> = emptyList(),
)

@Serializable
data class ReportRef(
    val id: String,
    val status: String,
    val mode: String,
    @SerialName("needs_log") val needsLog: Boolean = false,
    val intended: List<JsonObject> = emptyList(),
)

@Serializable
data class Portal(val id: String, val label: String, val url: String)

/**
 * verdict: PENDING (checks still running) | FRAUD ("Surely fraud") | SPAM ("Surely spam") | NONE.
 * The app shows something ONLY for FRAUD and SPAM, and only once status == "complete".
 */
@Serializable
data class ScanOut(
    @SerialName("scan_id") val scanId: String,
    val status: String,
    val verdict: String,
    val label: String? = null,
    val score: Int,
    val reasons: List<Reason>,
    val urls: List<UrlOut> = emptyList(),
    val report: ReportRef? = null,
    @SerialName("impersonated_brand") val impersonatedBrand: String? = null,
    val portals: List<Portal> = emptyList(),
    val checks: List<Check> = emptyList(),
    val evidence: List<String> = emptyList(),
    @SerialName("report_mode") val reportMode: String = "manual",
    @SerialName("can_report") val canReport: Boolean = false,
    @SerialName("report_preview") val reportPreview: List<String> = emptyList(),
)

@Serializable
data class ManualReportIn(@SerialName("scan_id") val scanId: String, val messages: List<LogMessage>)

@Serializable
data class LogMessage(
    val sender: String,
    val text: String,
    @SerialName("received_at") val receivedAt: String?,
    @SerialName("sim_slot") val simSlot: Int? = null,
)

@Serializable
data class ReportLogIn(@SerialName("scan_id") val scanId: String, val messages: List<LogMessage>)

@Serializable
data class FeedbackIn(@SerialName("scan_id") val scanId: String, val label: String)

@Serializable
data class BlocklistOut(
    val version: String,
    val senders: List<String>,
    @SerialName("domain_hashes") val domainHashes: List<String>,
    val full: Boolean,
)

// ----------------------------------------------------------------- Retrofit API
interface ScamShieldApi {
    @POST("v1/devices/register")
    suspend fun register(@Body body: RegisterIn): RegisterOut

    @PUT("v1/devices/me")
    suspend fun updateConsent(@Body body: RegisterIn): Response<Unit>

    @POST("v1/scan")
    suspend fun scan(@Body body: ScanIn): ScanOut

    @GET("v1/scan/{id}")
    suspend fun getScan(@Path("id") id: String): ScanOut

    @POST("v1/report/log")
    suspend fun reportLog(@Body body: ReportLogIn): ReportRef

    /** Manual mode: the user tapped Report on a "surely fraud" message. */
    @POST("v1/reports")
    suspend fun report(@Body body: ManualReportIn): ReportRef

    @GET("v1/reports")
    suspend fun reports(): List<ReportRef>

    @POST("v1/feedback")
    suspend fun feedback(@Body body: FeedbackIn): Response<Unit>

    @GET("v1/sync/blocklist")
    suspend fun blocklist(@Query("since") since: String?): BlocklistOut
}

class ApiClient(private val settings: SettingsStore) {
    val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    private val auth = Interceptor { chain ->
        // Tiny DataStore read; network calls already run off the main thread.
        val s = runBlocking { settings.snapshot() }
        var url = chain.request().url
        // Settings → Server overrides the build-time server (scheme/host/port only).
        s.serverUrl?.toHttpUrlOrNull()?.let { base ->
            url = url.newBuilder().scheme(base.scheme).host(base.host).port(base.port).build()
        }
        val req = chain.request().newBuilder()
            .url(url)
            .header("X-Api-Key", s.apiKey ?: BuildConfig.API_KEY)
            .apply { s.deviceToken?.let { header("X-Device-Token", it) } }
            .build()
        chain.proceed(req)
    }

    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .addInterceptor(auth)
        .apply {
            if (BuildConfig.DEBUG) {
                // Headers only: never log bodies (they may contain message text).
                addInterceptor(HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.HEADERS).apply {
                    redactHeader("X-Api-Key"); redactHeader("X-Device-Token")
                })
            }
        }
        .build()

    val service: ScamShieldApi = Retrofit.Builder()
        .baseUrl(BuildConfig.API_BASE_URL.toHttpUrlOrNull() ?: "http://10.0.2.2:8000/".toHttpUrlOrNull()!!)
        .client(http)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()
        .create(ScamShieldApi::class.java)
}
