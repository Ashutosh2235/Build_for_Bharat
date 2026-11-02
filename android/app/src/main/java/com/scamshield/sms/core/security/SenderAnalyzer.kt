package com.scamshield.sms.core.security

/** Mirrors backend/app/services/sender_intel.py. */
data class SenderInfo(
    val raw: String,
    val norm: String,
    val kind: String, // header | mobile | intl | short | other
    val prefix: String? = null,
    val header: String? = null,
    val suffix: String? = null,
)

object SenderAnalyzer {
    private val HEADER_RE = Regex("^([A-Z]{2})-([A-Z0-9]{3,9})(?:-([PSTG]))?$")
    private val BARE_HEADER_RE = Regex("^(?=.*[A-Z])[A-Z0-9]{3,9}$")
    private val NUMERIC_RE = Regex("^[\\d+\\-\\s()]+$")
    private val SENSITIVE_FOR_PROMO = setOf("OTP_REQUEST", "KYC_BLOCK_THREAT")
    private val COMMERCIAL_LURES = setOf("PRIZE_LOTTERY", "REFUND_CASHBACK", "JOB_LOAN_FEE")

    fun classify(raw: String): SenderInfo {
        val s = raw.trim()
        val up = s.uppercase().replace(" ", "")
        HEADER_RE.matchEntire(up)?.let { m ->
            val header = m.groupValues[2]
            return SenderInfo(raw, "HDR:$header", "header", m.groupValues[1], header, m.groupValues[3].ifEmpty { null })
        }
        var digits = s.filter { it.isDigit() }
        val plus = s.startsWith("+") || s.startsWith("00")
        if (digits.isNotEmpty()) {
            if (s.startsWith("00")) digits = digits.drop(2)
            if (digits.length <= 6 && !plus) return SenderInfo(raw, "SHORT:$digits", "short")
            if (digits.length == 10 && digits[0] in "6789" && !plus) return SenderInfo(raw, "+91$digits", "mobile")
            if (digits.length == 11 && digits[0] == '0' && digits[1] in "6789") {
                return SenderInfo(raw, "+91${digits.drop(1)}", "mobile")
            }
            if (digits.length == 12 && digits.startsWith("91") && digits[2] in "6789") {
                return SenderInfo(raw, "+91${digits.drop(2)}", "mobile")
            }
            if (plus || digits.length > 10) return SenderInfo(raw, "+$digits", "intl")
            if (NUMERIC_RE.matches(s)) return SenderInfo(raw, "NUM:$digits", "other")
        }
        if (BARE_HEADER_RE.matches(up)) return SenderInfo(raw, "HDR:$up", "header", null, up, null)
        return SenderInfo(raw, "RAW:$up", "other")
    }

    /** brand id this header impersonates, or null (exact known headers return null). */
    private fun impersonatedBrand(header: String, suffix: String?, rs: RuleSet): String? {
        if (rs.headerIndex.containsKey(header)) return null
        val h = header.lowercase()
        for ((kh, info) in rs.headerIndex) {
            if (kh.length >= 5 && TextUtils.levenshtein(h, kh.lowercase(), 2) <= 1) return info.first
        }
        if (suffix == "G") return null
        for (b in rs.brands.values) {
            for (tok in b.tokens) if (tok.length >= 3 && h.contains(tok)) return b.id
        }
        return null
    }

    data class Result(val signals: List<Signal>, val impersonated: String?)

    fun signals(
        info: SenderInfo,
        rs: RuleSet,
        brandClaimed: Boolean,
        contentCodes: Set<String>,
        inContacts: Boolean = false,
    ): Result {
        val out = mutableListOf<Signal>()
        var impersonated: String? = null
        when {
            info.kind == "mobile" && brandClaimed && !inContacts -> out += Signal(
                "MOBILE_BRAND_CLAIM", rs.pts("MOBILE_BRAND_CLAIM"),
                "Claims to be a bank/company/government office but comes from a personal mobile number",
                "sender", detail = info.norm,
            )
            info.kind == "mobile" && !inContacts && contentCodes.any { it in COMMERCIAL_LURES } -> out += Signal(
                "MOBILE_COMMERCIAL", rs.pts("MOBILE_COMMERCIAL"),
                "Prize, job, loan or refund offer from a personal number — genuine businesses use registered sender IDs",
                "sender", detail = info.norm,
            )
            info.kind == "intl" -> out += Signal(
                "INTL_SENDER", rs.pts("INTL_SENDER"), "Sent from an international number", "sender", detail = info.norm,
            )
            info.kind == "header" && info.header != null -> {
                val imp = impersonatedBrand(info.header, info.suffix, rs)
                if (imp != null) {
                    impersonated = imp
                    out += Signal(
                        "HEADER_IMPERSONATION", rs.pts("HEADER_IMPERSONATION"),
                        "Sender ID '${info.header}' looks like ${rs.brands.getValue(imp).name} but is not its registered header",
                        "sender", detail = info.header,
                    )
                }
                if (info.suffix == "P" && contentCodes.any { it in SENSITIVE_FOR_PROMO }) {
                    out += Signal(
                        "HEADER_SUFFIX_MISMATCH", rs.pts("HEADER_SUFFIX_MISMATCH"),
                        "Promotional sender (-P) is asking about OTP/KYC/account security", "sender", detail = info.raw,
                    )
                }
            }
        }
        if (inContacts) out += Signal("IN_CONTACTS", rs.pts("IN_CONTACTS"), "Sender is in your contacts", "sender")
        return Result(out, impersonated)
    }
}
