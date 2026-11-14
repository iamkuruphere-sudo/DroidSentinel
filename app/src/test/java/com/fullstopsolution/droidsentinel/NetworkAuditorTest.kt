package com.fullstopsolution.droidsentinel

import com.fullstopsolution.droidsentinel.auditor.NetworkAuditor
import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkAuditorTest {

    @Test
    fun testEmptyUrlReturnsNoFindings() {
        val findings = NetworkAuditor.analyzeUrl("")
        assertTrue("Empty URL should produce no findings", findings.isEmpty())
    }

    @Test
    fun testCleartextHttpProducesCriticalFinding() {
        val findings = NetworkAuditor.analyzeUrl("http://example.com/login")
        assertTrue("Cleartext HTTP must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("Cleartext", ignoreCase = true) })
    }

    @Test
    fun testSecureHttpsProducesSecureFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://example.com")
        assertTrue("Legitimate HTTPS must produce secure finding",
            findings.any { it.severity == Severity.SECURE })
    }

    @Test
    fun testDeceptiveAtRedirectProducesCriticalFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://bank.com@malicious-host.xyz/auth")
        assertTrue("Deceptive @ redirect must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("@") })
    }

    @Test
    fun testRawNumericIpProducesCriticalFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://192.168.1.100/admin")
        assertTrue("Raw numeric IP must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("Raw Numeric IP", ignoreCase = true) })
    }

    @Test
    fun testObfuscatedHexIpProducesCriticalFinding() {
        val findings = NetworkAuditor.analyzeUrl("http://0x7f000001/payload")
        assertTrue("Hex IP must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("Hexadecimal", ignoreCase = true) })
    }

    @Test
    fun testNonStandardPortProducesWarningFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://legit-site.com:8080/test")
        assertTrue("Non-standard port must produce warning finding",
            findings.any { it.severity == Severity.WARNING && it.title.contains("Non-Standard Port", ignoreCase = true) })
    }

    @Test
    fun testPunycodeDomainProducesCriticalFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://xn--pple-43d.com/secure")
        assertTrue("Punycode homograph must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("Punycode", ignoreCase = true) })
    }

    @Test
    fun testConfusableCyrillicHomoglyphProducesCriticalFinding() {
        // Contains Cyrillic 'а' (\u0430) instead of Latin 'a'
        val findings = NetworkAuditor.analyzeUrl("https://p\u0430ypal.com/signin")
        assertTrue("Cyrillic lookalike character must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("Homoglyph", ignoreCase = true) })
    }

    @Test
    fun testUrlShortenerProducesWarningFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://bit.ly/3XYZ123")
        assertTrue("URL shortener must produce warning finding",
            findings.any { it.severity == Severity.WARNING && it.title.contains("Shortener", ignoreCase = true) })
    }

    @Test
    fun testSuspiciousTldProducesWarningFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://free-bonus.top/claim")
        assertTrue("Suspicious TLD must produce warning finding",
            findings.any { it.severity == Severity.WARNING && it.title.contains("Top-Level Domain", ignoreCase = true) })
    }

    @Test
    fun testBrandSpoofingSubdomainProducesCriticalFinding() {
        val findings = NetworkAuditor.analyzeUrl("https://paypal.com.verify-billing.xyz/login")
        assertTrue("Brand spoofing subdomain must produce critical finding",
            findings.any { it.severity == Severity.CRITICAL && it.title.contains("Brand Impersonation", ignoreCase = true) })
    }
}
