package com.scamshield.sms.core.security

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.regex.Pattern

/**
 * Typed view of assets/rules.json + assets/brands.json (exported from the YAML files in shared/).
 * Mirrors backend/app/services/ruleset.py — keep both in sync.
 * Pure Kotlin (no Android imports) so it can be compiled and parity-tested on the JVM.
 */
data class ContentCategory(
    val code: String,
    val points: Int,
    val text: String,
    val group: String?,
    val patterns: List<Regex>,
    val negations: List<Regex>,
)

data class Brand(
    val id: String,
    val name: String,
    val category: String,
    val tokens: List<String>,
    val domains: List<String>,
    val headers: List<Pair<String, Boolean>>, // HEADER (upper case) to verified
)

class RuleSet(
    val version: Int,
    val content: Map<String, ContentCategory>,
    val brandClaim: List<Regex>,
    val shorteners: Set<String>,
    val riskyTlds: Set<String>,
    val commonTlds: List<String>,
    val multiSuffixes: Set<String>,
    val downloadExtensions: Set<String>,
    val messagingHosts: Set<String>,
    val points: Map<String, Int>,
    val weakSignalCap: Int,
    val thresholdSuspicious: Int,
    val thresholdScam: Int,
    val thresholdAutoReport: Int,
    val brands: Map<String, Brand>,
    val trustedSuffixes: List<String>,
) {
    /** official domain → brand id */
    val officialDomains: Map<String, String> =
        brands.values.flatMap { b -> b.domains.map { it to b.id } }.toMap()

    /** HEADER → (brand id, verified) */
    val headerIndex: Map<String, Pair<String, Boolean>> =
        brands.values.flatMap { b -> b.headers.map { (h, v) -> h to (b.id to v) } }.toMap()

    fun pts(code: String): Int = points[code] ?: error("unknown points code $code")

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        /** Same flags on server (Python re.IGNORECASE | re.UNICODE) as far as Java allows. */
        fun compile(p: String): Regex =
            Pattern.compile(p, Pattern.CASE_INSENSITIVE or Pattern.UNICODE_CASE).toRegex()

        fun parse(rulesJson: String, brandsJson: String): RuleSet {
            val r = json.parseToJsonElement(rulesJson).jsonObject
            val b = json.parseToJsonElement(brandsJson).jsonObject
            val url = r.obj("url")
            val thresholds = r.obj("thresholds")

            val content = r.obj("content").mapValues { (code, el) ->
                val c = el.jsonObject
                ContentCategory(
                    code = code,
                    points = c.getValue("points").jsonPrimitive.int,
                    text = c.str("text"),
                    group = c["group"]?.jsonPrimitive?.content,
                    patterns = c.strList("patterns").map(::compile),
                    negations = c.strList("negations").map(::compile),
                )
            }
            val brands = b.obj("brands").mapValues { (id, el) ->
                val o = el.jsonObject
                Brand(
                    id = id,
                    name = o.str("name"),
                    category = o.str("category"),
                    tokens = o.strList("tokens").map { it.lowercase() },
                    domains = o.strList("domains").map { it.lowercase() },
                    headers = (o["headers"] as? JsonArray).orEmpty().map { h ->
                        val ho = h.jsonObject
                        ho.str("id").uppercase() to (ho["verified"]?.jsonPrimitive?.boolean ?: false)
                    },
                )
            }
            return RuleSet(
                version = r.getValue("version").jsonPrimitive.int,
                content = content,
                brandClaim = r.strList("brand_claim_patterns").map(::compile),
                shorteners = url.strList("shorteners").map { it.lowercase() }.toSet(),
                riskyTlds = url.strList("risky_tlds").map { it.lowercase() }.toSet(),
                commonTlds = url.strList("common_tlds").map { it.lowercase() },
                multiSuffixes = url.strList("multi_suffixes").map { it.lowercase() }.toSet(),
                downloadExtensions = url.strList("download_extensions").map { it.lowercase() }.toSet(),
                messagingHosts = url.strList("messaging_hosts").map { it.lowercase() }.toSet(),
                points = r.obj("points").mapValues { it.value.jsonPrimitive.int },
                weakSignalCap = r.getValue("weak_signal_cap").jsonPrimitive.int,
                thresholdSuspicious = thresholds.getValue("suspicious").jsonPrimitive.int,
                thresholdScam = thresholds.getValue("scam").jsonPrimitive.int,
                thresholdAutoReport = thresholds.getValue("auto_report").jsonPrimitive.int,
                brands = brands,
                trustedSuffixes = b.strList("trusted_suffixes").map { it.lowercase() },
            )
        }

        private fun JsonObject.obj(key: String): JsonObject = getValue(key).jsonObject
        private fun JsonObject.str(key: String): String = getValue(key).jsonPrimitive.content
        private fun JsonObject.strList(key: String): List<String> =
            (this[key] as? JsonArray).orEmpty().map { (it as JsonElement).jsonPrimitive.content }
    }
}
