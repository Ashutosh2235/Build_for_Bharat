package com.scamshield.sms.core.security

/** Mirrors backend/app/services/content_rules.py. */
object ContentRules {

    fun signals(text: String, rs: RuleSet): List<Signal> {
        val t = TextUtils.normalize(text)
        val out = mutableListOf<Signal>()
        for (cat in rs.content.values) {
            var subject = t
            for (neg in cat.negations) subject = neg.replace(subject, " ")
            if (cat.patterns.any { it.containsMatchIn(subject) }) {
                out += Signal(cat.code, cat.points, cat.text, "content", group = cat.group)
            }
        }
        return out
    }

    fun claimsBrand(text: String, rs: RuleSet): Boolean {
        val t = TextUtils.normalize(text)
        return rs.brandClaim.any { it.containsMatchIn(t) }
    }

    fun brandsMentioned(text: String, rs: RuleSet): List<String> {
        val t = TextUtils.normalize(text).lowercase()
        return rs.brands.values.filter { b ->
            b.tokens.any { tok ->
                tok.length >= 3 && Regex("(?<![a-z0-9])${Regex.escape(tok)}(?![a-z0-9])").containsMatchIn(t)
            }
        }.map { it.id }
    }
}
