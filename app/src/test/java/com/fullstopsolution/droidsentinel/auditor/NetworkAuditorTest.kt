package com.fullstopsolution.droidsentinel.auditor

import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkAuditorTest {
    @Test
    fun opportunisticPrivateDnsIsNotReportedAsGuaranteedEncryption() {
        val assessment = assessPrivateDnsMode("opportunistic")

        assertFalse(assessment.requiresDnsOverTls)
        assertEquals(Severity.WARNING, assessment.finding.severity)
        assertTrue(assessment.finding.description.contains("may fall back"))
    }

    @Test
    fun hostnamePrivateDnsRequiresDnsOverTls() {
        val assessment = assessPrivateDnsMode("hostname")

        assertTrue(assessment.requiresDnsOverTls)
        assertEquals(Severity.SECURE, assessment.finding.severity)
    }

    @Test
    fun flagsUnicodeHostnameAfterIdnNormalization() {
        val findings = NetworkAuditor.analyzeUrl("https://раypal.com")

        assertTrue(findings.any { it.title == "Punycode / IDN Homograph Attack Vector" })
        assertTrue(findings.none { it.severity == Severity.SECURE })
    }

    @Test
    fun doesNotCallUnparseableHostnameSecure() {
        val findings = NetworkAuditor.analyzeUrl("https://[invalid")

        assertEquals("Unable to Verify URL Hostname", findings.first().title)
        assertTrue(findings.none { it.severity == Severity.SECURE })
    }

    @Test
    fun keepsOrdinaryHttpsHostnamesClearOfIdnWarnings() {
        val findings = NetworkAuditor.analyzeUrl("https://example.com")

        assertTrue(findings.any { it.severity == Severity.SECURE })
        assertTrue(findings.none { it.title == "Punycode / IDN Homograph Attack Vector" })
    }
}
