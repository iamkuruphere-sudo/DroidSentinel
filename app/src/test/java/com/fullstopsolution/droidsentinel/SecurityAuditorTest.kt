package com.fullstopsolution.droidsentinel

import com.fullstopsolution.droidsentinel.auditor.NetworkAuditor
import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityAuditorTest {

    @Test
    fun testUnicodeHomographPhishingDetection() {
        // Raw Cyrillic 'р' (U+0440) spoofing 'paypal.com'
        val cyrillicPaypal = "https://\u0440aypal.com/login"
        val findings = NetworkAuditor.analyzeUrl(cyrillicPaypal)

        val homographFinding = findings.find { it.title.contains("Homograph", ignoreCase = true) }
        assertTrue("Cyrillic homograph must be detected", homographFinding != null)
        assertEquals(Severity.CRITICAL, homographFinding?.severity)
    }

    @Test
    fun testPunycodeEncodedDomainDetection() {
        val punycodeUrl = "https://xn--pple-43d.com"
        val findings = NetworkAuditor.analyzeUrl(punycodeUrl)

        val homographFinding = findings.find { it.title.contains("Homograph", ignoreCase = true) }
        assertTrue("Punycode domain must be detected", homographFinding != null)
        assertEquals(Severity.CRITICAL, homographFinding?.severity)
    }

    @Test
    fun testNumericIpAndHttpDetection() {
        val rawIpUrl = "http://192.168.1.1/login"
        val findings = NetworkAuditor.analyzeUrl(rawIpUrl)

        val httpFinding = findings.find { it.title.contains("HTTP", ignoreCase = true) }
        val ipFinding = findings.find { it.title.contains("Numeric IP", ignoreCase = true) }

        assertTrue("Insecure HTTP must be flagged", httpFinding != null)
        assertTrue("Raw numeric IP must be flagged", ipFinding != null)
        assertEquals(Severity.CRITICAL, httpFinding?.severity)
        assertEquals(Severity.CRITICAL, ipFinding?.severity)
    }

    @Test
    fun testAtSignRedirectSyntaxDetection() {
        val redirectUrl = "https://trusted-bank.com@phishing-target.xyz/auth"
        val findings = NetworkAuditor.analyzeUrl(redirectUrl)

        val atFinding = findings.find { it.title.contains("@", ignoreCase = true) }
        assertTrue("Deceptive '@' syntax must be flagged", atFinding != null)
        assertEquals(Severity.CRITICAL, atFinding?.severity)
    }

    @Test
    fun testBrandSpoofingSubdomainDetection() {
        val spoofUrl = "https://paypal.com.verify-account.top/login"
        val findings = NetworkAuditor.analyzeUrl(spoofUrl)

        val spoofFinding = findings.find { it.title.contains("Brand Spoofing", ignoreCase = true) }
        assertTrue("Brand spoofing subdomain must be flagged", spoofFinding != null)
        assertEquals(Severity.CRITICAL, spoofFinding?.severity)
    }

    @Test
    fun testLegitimateHttpsUrlReturnsSecure() {
        val legitUrl = "https://www.fullstopsolution.in"
        val findings = NetworkAuditor.analyzeUrl(legitUrl)

        assertEquals(1, findings.size)
        assertEquals(Severity.SECURE, findings[0].severity)
    }
}
