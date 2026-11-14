package com.fullstopsolution.droidsentinel

import com.fullstopsolution.droidsentinel.model.SecurityScorer
import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Test

class SecurityScoreTest {

    @Test
    fun testPristineDeviceScores100Secure() {
        val (score, status) = SecurityScorer.evaluateScore()
        assertEquals(100, score)
        assertEquals(Severity.SECURE, status)
    }

    @Test
    fun testRootedDeviceDocks40Points() {
        val (score, status) = SecurityScorer.evaluateScore(isRooted = true)
        assertEquals(60, score)
        assertEquals(Severity.WARNING, status)
    }

    @Test
    fun testSeverelyCompromisedDeviceClampsAtZeroCritical() {
        val (score, status) = SecurityScorer.evaluateScore(
            isRooted = true,
            selinuxMode = "Permissive",
            isAdbEnabled = true,
            isAdbWifiEnabled = true,
            isDeviceLocked = false,
            hasHardwareKeystore = false,
            highRiskAppsCount = 5,
            storageThreatsCount = 4,
            isVpnActive = false,
            isPrivateDnsActive = false
        )
        assertEquals(0, score)
        assertEquals(Severity.CRITICAL, status)
    }

    @Test
    fun testScoreBoundaries() {
        // Exactly 80 should be SECURE
        val (_, status80) = SecurityScorer.evaluateScore(isAdbWifiEnabled = true) // 100 - 20 = 80
        assertEquals(Severity.SECURE, status80)

        // Exactly 75 should be WARNING
        val (_, status75) = SecurityScorer.evaluateScore(selinuxMode = "Permissive") // 100 - 25 = 75
        assertEquals(Severity.WARNING, status75)

        // Exactly 50 should be WARNING
        val (_, status50) = SecurityScorer.evaluateScore(
            isRooted = true,
            isAdbEnabled = true
        ) // 100 - 40 - 10 = 50
        assertEquals(Severity.WARNING, status50)

        // 49 or below should be CRITICAL
        val (_, statusCritical) = SecurityScorer.evaluateScore(
            isRooted = true,
            isAdbWifiEnabled = true
        ) // 100 - 40 - 20 = 40
        assertEquals(Severity.CRITICAL, statusCritical)
    }
}
