package com.scamshield.sms.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** JVM unit tests for the on-device scanner (same assets the app ships). */
class LocalScannerTest {
    private val assets = File("src/main/assets")
    private val rs = RuleSet.parse(File(assets, "rules.json").readText(), File(assets, "brands.json").readText())
    private val scanner = LocalScanner(rs)

    @Test fun kycPhishingFromMobileIsScam() {
        val r = scanner.scan("9876543210",
            "Dear HDFC customer, your account will be blocked today. Update KYC: https://hdfcbank-kyc-update.co/login")
        assertEquals(Verdict.SCAM, r.score.verdict)
        assertEquals(75, r.score.score)
        assertEquals("HDFC", r.impersonatedBrand)
        assertTrue("BRAND_CLAIM" in r.reasonCodes)
    }

    @Test fun genuineBankOtpIsSafe() {
        val r = scanner.scan("VM-HDFCBK-T", "482913 is your OTP for txn of Rs 500. Do not share it with anyone. -HDFC Bank")
        assertEquals(Verdict.SAFE, r.score.verdict)
    }

    @Test fun blockedSenderIsInstantScam() {
        val blocked = object : BlocklistLookup {
            override fun isSenderBlocked(senderNorm: String) = senderNorm == "+917000000001"
            override fun isDomainBlocked(domainHash: String) = false
        }
        val r = LocalScanner(rs, blocked).scan("+91 70000 00001", "hello")
        assertEquals(100, r.score.score)
    }

    @Test fun blockedDomainHashMatchesServerHash() {
        // backend: text_utils.domain_hash("evil-feed.top")
        val h = TextUtils.domainHash("evil-feed.top")
        val blocked = object : BlocklistLookup {
            override fun isSenderBlocked(senderNorm: String) = false
            override fun isDomainBlocked(domainHash: String) = domainHash == h
        }
        val r = LocalScanner(rs, blocked).scan("VM-ABCDEF", "Track at https://www.evil-feed.top/x")
        assertEquals(Verdict.SCAM, r.score.verdict)
    }

    @Test fun headerParsing() {
        val i = SenderAnalyzer.classify("JD-HDFCBK-S")
        assertEquals("HDR:HDFCBK", i.norm)
        assertEquals("S", i.suffix)
        assertEquals("+919876543210", SenderAnalyzer.classify("+91 98765 43210").norm)
    }
}
