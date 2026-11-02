package com.scamshield.sms.core.security

import java.security.MessageDigest
import java.text.Normalizer

/** One explainable reason. Mirrors backend/app/services/signals.py. */
data class Signal(
    val code: String,
    val points: Int,
    val text: String,
    val source: String,
    val absolute: Boolean = false,
    val group: String? = null,
    val detail: String? = null,
)

enum class Verdict { SAFE, SUSPICIOUS, SCAM }

val WEAK_CODES = setOf("URGENCY", "NO_HTTPS", "RISKY_TLD", "SHORTENER", "MESSAGING_LINK")

object TextUtils {
    private val SKELETON = listOf(
        "rn" to "m", "vv" to "w", "0" to "o", "1" to "l", "3" to "e",
        "4" to "a", "5" to "s", "7" to "t", "8" to "b", "i" to "l",
    )

    fun normalize(text: String): String =
        Normalizer.normalize(text, Normalizer.Form.NFKC).replace(Regex("\\s+"), " ").trim()

    fun levenshtein(a: String, b: String, limit: Int = 3): Int {
        if (kotlin.math.abs(a.length - b.length) > limit) return limit + 1
        var prev = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            val cur = IntArray(b.length + 1)
            cur[0] = i
            var rowMin = cur[0]
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
                rowMin = minOf(rowMin, cur[j])
            }
            if (rowMin > limit) return limit + 1
            prev = cur
        }
        return prev[b.length]
    }

    fun skeleton(s: String): String {
        var out = s.lowercase()
        for ((a, b) in SKELETON) out = out.replace(a, b)
        return out
    }

    fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    /** Matches backend text_utils.domain_hash — first 16 hex chars of sha256(domain). */
    fun domainHash(domain: String): String = sha256Hex(domain.lowercase().trim('.')).take(16)
}
