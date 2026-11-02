package com.scamshield.sms.core.security

import java.net.IDN

/** Mirrors backend/app/services/url_intel.py (extraction + static checks). */
data class ParsedUrl(
    val raw: String,
    val url: String,
    val scheme: String,
    val host: String,
    val path: String,
    val registeredDomain: String,
    val tld: String,
    val hadScheme: Boolean,
    val hasUserinfo: Boolean,
    val isIp: Boolean,
    val isUpi: Boolean = false,
    val upiPayee: String? = null,
    val unicodeHost: Boolean = false,
)

data class UrlStatic(
    val parsed: ParsedUrl,
    val signals: List<Signal>,
    val official: String?,
    val imitates: String?,
)

object UrlAnalyzer {
    private const val TRAILING = ".,;:!?)]}'\"»”’>"
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private var cachedTlds: List<String>? = null
    private var cachedRe: Regex? = null

    private fun extractRe(tlds: List<String>): Regex {
        if (cachedTlds == tlds && cachedRe != null) return cachedRe!!
        val alt = tlds.sortedByDescending { it.length }.joinToString("|") { Regex.escape(it) }
        val re = RuleSet.compile(
            "(?:https?://|www\\.)[^\\s<>\"']+" +
                "|upi://[^\\s<>\"']+" +
                "|(?<![@\\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:$alt)(?![a-z0-9-])(?::\\d{2,5})?(?:/[^\\s<>\"']*)?",
        )
        cachedTlds = tlds
        cachedRe = re
        return re
    }

    fun extract(text: String, rs: RuleSet): List<String> {
        val out = mutableListOf<String>()
        for (m in extractRe(rs.commonTlds).findAll(text)) {
            val u = m.value.trimEnd { it in TRAILING }
            if (u.isNotEmpty() && out.none { it.equals(u, ignoreCase = true) }) out += u
        }
        return out
    }

    fun registeredDomain(host: String, rs: RuleSet): String {
        val labels = host.lowercase().trim('.').split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return labels.joinToString(".")
        val last2 = labels.takeLast(2).joinToString(".")
        val last3 = labels.takeLast(3).joinToString(".")
        if (last3 in rs.multiSuffixes && labels.size >= 4) return labels.takeLast(4).joinToString(".")
        if (last2 in rs.multiSuffixes) return last3
        return last2
    }

    fun parse(rawIn: String, rs: RuleSet): ParsedUrl? {
        val raw = rawIn.trim()
        if (raw.lowercase().startsWith("upi://")) {
            val payee = Regex("[?&]pa=([^&\\s]+)", RegexOption.IGNORE_CASE).find(raw)?.groupValues?.get(1)
            return ParsedUrl(raw, raw, "upi", "", "", "", "", true, false, false, true, payee)
        }
        val hadScheme = Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE).containsMatchIn(raw)
        val url = if (hadScheme) raw else "http://$raw"
        val schemeEnd = url.indexOf("://")
        val scheme = url.substring(0, schemeEnd).lowercase()
        val rest = url.substring(schemeEnd + 3)
        val authEnd = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }.let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, authEnd)
        val afterAuth = rest.substring(authEnd)
        val pathAndQuery = afterAuth.substringBefore('#')
        val path = pathAndQuery.substringBefore('?').ifEmpty { "/" }
        val query = if ('?' in pathAndQuery) pathAndQuery.substringAfter('?') else ""
        val hostPort = authority.substringAfterLast('@')
        var host: String
        var port: String? = null
        if (hostPort.startsWith("[")) {
            host = hostPort.substringBefore(']').trimStart('[')
            port = hostPort.substringAfter("]:", "").ifEmpty { null }
        } else {
            host = hostPort.substringBefore(':')
            port = if (':' in hostPort) hostPort.substringAfter(':').ifEmpty { null } else null
        }
        host = host.lowercase().trim('.')
        if (host.isEmpty()) return null
        val unicodeHost = host.any { it.code > 127 }
        val hostAscii = if (unicodeHost) {
            try { IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).lowercase() } catch (e: IllegalArgumentException) { host }
        } else host
        val isIp = IPV4.matches(hostAscii) || hostAscii.contains(':')
        val reg = if (isIp) hostAscii else registeredDomain(hostAscii, rs)
        val tld = if (isIp) "" else hostAscii.substringAfterLast('.')
        var norm = "$scheme://$hostAscii${port?.let { ":$it" } ?: ""}$path"
        if (query.isNotEmpty()) norm += "?$query"
        return ParsedUrl(raw, norm, scheme, hostAscii, path, reg, tld, hadScheme, '@' in authority, isIp,
            unicodeHost = unicodeHost)
    }

    fun officialBrand(p: ParsedUrl, rs: RuleSet): String? {
        for ((dom, bid) in rs.officialDomains) {
            if (p.host == dom || p.host.endsWith(".$dom")) return bid
        }
        for (suf in rs.trustedSuffixes) if (p.host.endsWith(".$suf")) return "TRUSTED_SUFFIX"
        return null
    }

    fun lookalikeBrand(p: ParsedUrl, rs: RuleSet): String? {
        if (p.isIp || p.host.isEmpty()) return null
        val reg = p.registeredDomain
        val regLabel = reg.substringBefore('.')
        val prefix = p.host.substring(0, p.host.length - reg.length)
        val parts = (prefix + regLabel).split('-', '.').filter { it.isNotEmpty() }
        for (b in rs.brands.values) {
            for (tok in b.tokens) {
                if (tok.length < 3) continue
                if (parts.any { part -> part == tok || (tok.length >= 5 && part.contains(tok)) }) return b.id
            }
            for (dom in b.domains) {
                val off = dom.substringBefore('.')
                if (off.length < 6 || regLabel == off) continue
                val maxDist = if (off.length < 8) 1 else 2
                if (TextUtils.levenshtein(regLabel, off, maxDist) <= maxDist) return b.id
                if (TextUtils.skeleton(regLabel) == TextUtils.skeleton(off)) return b.id
            }
        }
        return null
    }

    fun staticSignals(raw: String, rs: RuleSet): UrlStatic? {
        val p = parse(raw, rs) ?: return null
        val sig = mutableListOf<Signal>()
        if (p.isUpi) {
            sig += Signal("UPI_LINK", 0, "Contains a UPI payment link", "url", detail = p.upiPayee)
            return UrlStatic(p, sig, null, null)
        }
        val official = officialBrand(p, rs)
        var imitates: String? = null
        if (official != null) {
            sig += Signal("OFFICIAL_DOMAIN", rs.pts("OFFICIAL_DOMAIN"),
                "Link goes to an official domain (${p.registeredDomain})", "url", detail = p.host)
        } else {
            imitates = lookalikeBrand(p, rs)
            if (imitates != null) {
                sig += Signal("LOOKALIKE_DOMAIN", rs.pts("LOOKALIKE_DOMAIN"),
                    "Link imitates ${rs.brands.getValue(imitates).name} (${p.host})", "url", detail = p.host)
            }
        }
        if (p.isIp || p.hasUserinfo || p.host.contains("xn--") || p.unicodeHost) {
            sig += Signal("IP_OR_PUNYCODE_URL", rs.pts("IP_OR_PUNYCODE_URL"),
                "Link hides its real address (IP address, look-alike characters or '@' trick)", "url", detail = p.host)
        }
        val lastSeg = p.path.substringAfterLast('/')
        val ext = if ('.' in lastSeg) p.path.substringAfterLast('.').lowercase() else ""
        if (ext in rs.downloadExtensions) {
            sig += Signal("DOWNLOAD_LINK", rs.pts("DOWNLOAD_LINK"),
                "Link downloads a file (.$ext) — scam apps are spread this way", "url", detail = p.url)
        }
        if (p.host in rs.shorteners) {
            sig += Signal("SHORTENER", rs.pts("SHORTENER"), "Uses a link shortener that hides the destination",
                "url", detail = p.host)
        }
        if (p.host in rs.messagingHosts) {
            sig += Signal("MESSAGING_LINK", rs.pts("MESSAGING_LINK"), "Moves the conversation to WhatsApp/Telegram",
                "url", detail = p.host)
        }
        if (p.hadScheme && p.scheme == "http" && official == null) {
            sig += Signal("NO_HTTPS", rs.pts("NO_HTTPS"), "Link is not encrypted (http)", "url", detail = p.host)
        }
        if (p.tld in rs.riskyTlds && official == null) {
            sig += Signal("RISKY_TLD", rs.pts("RISKY_TLD"), "Uses a domain ending (.${p.tld}) common in scams",
                "url", detail = p.host)
        }
        return UrlStatic(p, sig, official, imitates)
    }
}
