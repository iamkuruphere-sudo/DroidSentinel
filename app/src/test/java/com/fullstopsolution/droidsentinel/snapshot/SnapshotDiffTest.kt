package com.fullstopsolution.droidsentinel.snapshot

import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SnapshotDiffTest {
    @Test
    fun reportsScoreAndFindingChangesBetweenSnapshots() {
        val previous = snapshot(
            timestamp = 1L,
            score = 72,
            isPrivateDnsStrict = false,
            findings = listOf(
                finding("Unsafe app", Severity.WARNING),
                finding("ADB enabled", Severity.WARNING)
            )
        )
        val current = snapshot(
            timestamp = 2L,
            score = 86,
            highRiskAppCount = 2,
            findings = listOf(
                finding("Strict DNS configured", Severity.SECURE),
                finding("ADB enabled", Severity.WARNING)
            )
        )

        val diff = compareSnapshots(previous, current)

        assertEquals(14, diff.scoreChange)
        assertTrue(diff.statusChanged)
        assertEquals(listOf("Strict DNS configured"), diff.addedFindings.map { it.title })
        assertEquals(listOf("Unsafe app"), diff.resolvedFindings.map { it.title })
        assertTrue(diff.metricChanges.any { it.label == "High-risk apps" && it.currentValue == "2" })
        assertTrue(diff.metricChanges.any { it.label == "Strict Private DNS" && it.currentValue == "Configured" })
    }

    @Test
    fun identicalFindingsProduceAnEmptyDiff() {
        val findings = listOf(finding("Screen lock configured", Severity.SECURE))

        val diff = compareSnapshots(
            snapshot(1L, 90, findings = findings),
            snapshot(2L, 90, findings = findings)
        )

        assertEquals(0, diff.scoreChange)
        assertFalse(diff.statusChanged)
        assertTrue(diff.metricChanges.isEmpty())
        assertTrue(diff.addedFindings.isEmpty())
        assertTrue(diff.resolvedFindings.isEmpty())
    }

    private fun snapshot(
        timestamp: Long,
        score: Int,
        highRiskAppCount: Int = 0,
        isPrivateDnsStrict: Boolean = true,
        findings: List<Finding>
    ) = AuditSnapshot(
        timestamp = timestamp,
        timestampIso = "2026-11-14T00:00:00Z",
        deviceModel = "Test device",
        androidVersion = "17",
        securityPatch = "2026-08-05",
        overallScore = score,
        overallStatus = when {
            score >= 80 -> Severity.SECURE
            score >= 50 -> Severity.WARNING
            else -> Severity.CRITICAL
        },
        isRooted = false,
        selinuxMode = "Enforcing",
        isAdbEnabled = false,
        isAdbWifiEnabled = false,
        isDeviceLocked = true,
        hasStrongBox = true,
        hasHardwareKeystore = true,
        highRiskAppCount = highRiskAppCount,
        sideloadedAppCount = 0,
        storageThreatCount = 0,
        isVpnActive = true,
        isPrivateDnsStrict = isPrivateDnsStrict,
        findings = findings
    )

    private fun finding(title: String, severity: Severity) = Finding(
        title = title,
        description = "$title description",
        severity = severity
    )
}
