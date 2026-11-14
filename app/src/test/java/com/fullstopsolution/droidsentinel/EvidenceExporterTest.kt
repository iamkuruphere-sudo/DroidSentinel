package com.fullstopsolution.droidsentinel

import com.fullstopsolution.droidsentinel.export.EvidenceExporter
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.AppAuditResult
import com.fullstopsolution.droidsentinel.model.AppThreatInfo
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.DeviceIntegrityResult
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.FindingCategory
import com.fullstopsolution.droidsentinel.model.NetworkAuditResult
import com.fullstopsolution.droidsentinel.model.Severity
import com.fullstopsolution.droidsentinel.model.StorageAuditResult
import com.fullstopsolution.droidsentinel.model.StorageThreatInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceExporterTest {

    private fun createSampleAssessment(): CompleteSecurityAssessment {
        val sampleFinding = Finding(
            title = "Test Finding",
            description = "Test description",
            severity = Severity.CRITICAL,
            recommendation = "Test fix",
            actionType = ActionType.OPEN_DEVELOPER_OPTIONS,
            actionLabel = "Open Dev",
            category = FindingCategory.INTEGRITY
        )

        return CompleteSecurityAssessment(
            timestamp = 1731570000000L,
            timestampIso = "2026-11-14T09:00:00Z",
            deviceModel = "Pixel 8 Pro",
            deviceManufacturer = "Google",
            androidVersion = "14",
            securityPatch = "2026-11-01",
            overallScore = 85,
            overallStatus = Severity.SECURE,
            integrity = DeviceIntegrityResult(
                isRooted = false,
                rootSignals = emptyList(),
                selinuxMode = "Enforcing",
                buildTags = "release-keys",
                isAdbEnabled = false,
                isAdbWifiEnabled = false,
                isDeviceLocked = true,
                hasStrongBox = true,
                hasHardwareKeystore = true,
                isKeystoreHardwareBacked = true,
                biometricStatus = "Enrolled & Active",
                isTestKeysBuild = false,
                isSystemDebuggable = false,
                findings = listOf(sampleFinding)
            ),
            appAudit = AppAuditResult(
                totalAppsScanned = 150,
                sideloadedApps = listOf(
                    AppThreatInfo(
                        appName = "UntrustedApp",
                        packageName = "com.untrusted.app",
                        versionName = "1.0",
                        targetSdk = 34,
                        installerPackage = null,
                        isSideloaded = true,
                        isDebuggable = false,
                        isBootCompleted = false,
                        dangerousPermissions = listOf("android.permission.CAMERA"),
                        riskFindings = emptyList(),
                        riskScore = 25
                    )
                ),
                highRiskApps = emptyList(),
                autorunApps = emptyList(),
                findings = emptyList()
            ),
            storageAudit = StorageAuditResult(
                filesScannedCount = 42,
                threatsFound = listOf(
                    StorageThreatInfo(
                        fileName = "invoice.pdf.apk",
                        filePath = "/sdcard/Download/invoice.pdf.apk",
                        fileSize = 1048576L,
                        threatType = "DECEPTIVE_EXTENSION",
                        details = "Deceptive double extension",
                        severity = Severity.CRITICAL,
                        sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    )
                ),
                isStorageAccessGranted = true,
                findings = emptyList()
            ),
            networkAudit = NetworkAuditResult(
                isConnected = true,
                connectionType = "Wi-Fi",
                isWifiEncrypted = true,
                wifiSecurityType = "WPA3",
                isVpnActive = true,
                isPrivateDnsActive = true,
                privateDnsServer = "dns.google",
                findings = emptyList()
            ),
            allFindings = listOf(sampleFinding)
        )
    }

    @Test
    fun testJsonEvidenceSchemaCompleteness() {
        val assessment = createSampleAssessment()
        val json = EvidenceExporter.buildAssessmentJson(assessment)

        assertTrue(json.has("metadata"))
        assertTrue(json.has("device_integrity"))
        assertTrue(json.has("application_audit"))
        assertTrue(json.has("storage_audit"))
        assertTrue(json.has("network_audit"))
        assertTrue(json.has("security_findings"))

        val metadata = json.getJSONObject("metadata")
        assertEquals("Fullstop Solution (www.fullstopsolution.in)", metadata.getString("vendor"))
        assertEquals("Pixel 8 Pro", metadata.getString("device_model"))
        assertEquals(85, metadata.getInt("overall_security_score"))
        assertEquals("SECURE", metadata.getString("overall_status"))

        val integrity = json.getJSONObject("device_integrity")
        assertEquals(false, integrity.getBoolean("is_rooted"))
        assertEquals("Enforcing", integrity.getString("selinux_mode"))
        assertEquals(true, integrity.getBoolean("strongbox_keystore_supported"))

        val findings = json.getJSONArray("security_findings")
        assertEquals(1, findings.length())
        assertEquals("Test Finding", findings.getJSONObject(0).getString("title"))
    }

    @Test
    fun testMarkdownReportCompleteness() {
        val assessment = createSampleAssessment()
        val md = EvidenceExporter.buildAssessmentMarkdown(assessment)

        assertTrue("Must contain Fullstop Solution banner", md.contains("Fullstop Solution"))
        assertTrue("Must contain Executive Summary", md.contains("## Executive Summary"))
        assertTrue("Must contain Overall Posture Score", md.contains("`85/100` (SECURE)"))
        assertTrue("Must contain Defense Pillar Posture table", md.contains("## Defense Pillar Posture"))
        assertTrue("Must contain Security Findings section", md.contains("## Security Findings (1)"))
        assertTrue("Must contain specific finding title", md.contains("Test Finding"))
    }
}
