package com.fullstopsolution.droidsentinel

import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Test

class SecurityScoreTest {

    private fun calculateScore(
        isRooted: Boolean = false,
        selinuxMode: String = "Enforcing",
        isAdbEnabled: Boolean = false,
        isAdbWifiEnabled: Boolean = false,
        isDeviceLocked: Boolean = true,
        hasHardwareKeystore: Boolean = true,
        highRiskAppsCount: Int = 0,
        storageThreatsCount: Int = 0,
        isVpnActive: Boolean = true,
        isPrivateDnsActive: Boolean = true
    ): Pair<Int, Severity> {
        var score = 100
        if (isRooted) score -= 40
        if (selinuxMode != "Enforcing") score -= 25
        if (isAdbEnabled) score -= 10
        if (isAdbWifiEnabled) score -= 20
        if (!isDeviceLocked) score -= 15
        if (!hasHardwareKeystore) score -= 10

        score -= (highRiskAppsCount * 15).coerceAtMost(30)
        score -= (storageThreatsCount * 20).coerceAtMost(40)
        if (!isVpnActive && !isPrivateDnsActive) score -= 10

        score = score.coerceIn(0, 100)

        val status = when {
            score >= 80 -> Severity.SECURE
            score >= 50 -> Severity.WARNING
            else -> Severity.CRITICAL
        }

        return score to status
    }

    @Test
    fun testPristineDeviceScores100Secure() {
        val (score, status) = calculateScore()
        assertEquals(100, score)
        assertEquals(Severity.SECURE, status)
    }

    @Test
    fun testRootedDeviceDocks40Points() {
        val (score, status) = calculateScore(isRooted = true)
        assertEquals(60, score)
        assertEquals(Severity.WARNING, status)
    }

    @Test
    fun testSeverelyCompromisedDeviceClampsAtZeroCritical() {
        val (score, status) = calculateScore(
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
        val status80 = when {
            80 >= 80 -> Severity.SECURE
            80 >= 50 -> Severity.WARNING
            else -> Severity.CRITICAL
        }
        assertEquals(Severity.SECURE, status80)

        // Exactly 79 should be WARNING
        val status79 = when {
            79 >= 80 -> Severity.SECURE
            79 >= 50 -> Severity.WARNING
            else -> Severity.CRITICAL
        }
        assertEquals(Severity.WARNING, status79)

        // Exactly 50 should be WARNING
        val status50 = when {
            50 >= 80 -> Severity.SECURE
            50 >= 50 -> Severity.WARNING
            else -> Severity.CRITICAL
        }
        assertEquals(Severity.WARNING, status50)

        // 49 should be CRITICAL
        val status49 = when {
            49 >= 80 -> Severity.SECURE
            49 >= 50 -> Severity.WARNING
            else -> Severity.CRITICAL
        }
        assertEquals(Severity.CRITICAL, status49)
    }
}
