package com.fullstopsolution.droidsentinel.export

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.core.content.FileProvider
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Severity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object EvidenceExporter {

    fun buildAssessmentJson(assessment: CompleteSecurityAssessment): JSONObject {
        val root = JSONObject()

        // 1. Ecosystem Metadata
        val meta = JSONObject().apply {
            put("suite", "Fullstop Solution Mobile Precision Security Suite")
            put("tool", "DroidSentinel Endpoint Security")
            put("version", "1.0.0")
            put("vendor", "Fullstop Solution (www.fullstopsolution.in)")
            put("support_email", "contact@fullstopsolution.in")
            put("timestamp", assessment.timestampIso)
            put("device_model", assessment.deviceModel)
            put("device_manufacturer", assessment.deviceManufacturer)
            put("android_version", assessment.androidVersion)
            put("security_patch", assessment.securityPatch)
            put("overall_security_score", assessment.overallScore)
            put("overall_status", assessment.overallStatus.name)
        }
        root.put("metadata", meta)

        // 2. Device Integrity
        val integrity = JSONObject().apply {
            put("is_rooted", assessment.integrity.isRooted)
            put("selinux_mode", assessment.integrity.selinuxMode)
            put("build_tags", assessment.integrity.buildTags)
            put("usb_debugging_active", assessment.integrity.isAdbEnabled)
            put("wireless_debugging_active", assessment.integrity.isAdbWifiEnabled)
            put("secure_screen_lock_configured", assessment.integrity.isDeviceLocked)
            put("strongbox_keystore_supported", assessment.integrity.hasStrongBox)
            put("hardware_keystore_supported", assessment.integrity.hasHardwareKeystore)
            put("is_keystore_hardware_backed", assessment.integrity.isKeystoreHardwareBacked)
            put("biometric_status", assessment.integrity.biometricStatus)
        }
        root.put("device_integrity", integrity)

        // 3. Application Audit
        val appAudit = JSONObject().apply {
            put("total_applications_reviewed", assessment.appAudit.totalAppsScanned)
            put("sideloaded_applications_count", assessment.appAudit.sideloadedApps.size)
            put("high_risk_applications_count", assessment.appAudit.highRiskApps.size)
            put("boot_autorun_applications_count", assessment.appAudit.autorunApps.size)
            put("cleartext_http_applications_count", assessment.appAudit.cleartextApps.size)

            val appsArray = JSONArray()
            for (app in assessment.appAudit.highRiskApps + assessment.appAudit.sideloadedApps.take(25)) {
                val appObj = JSONObject().apply {
                    put("name", app.appName)
                    put("package", app.packageName)
                    put("version", app.versionName)
                    put("target_sdk", app.targetSdk)
                    put("installer", app.installerPackage ?: "Direct/Sideload")
                    put("is_sideloaded", app.isSideloaded)
                    put("is_debuggable", app.isDebuggable)
                    put("is_boot_autorun", app.isBootCompleted)
                    put("uses_cleartext_traffic", app.usesCleartextTraffic)
                    put("exported_components_count", app.exportedComponentsCount)
                    put("risk_score", app.riskScore)
                    put("dangerous_permissions", JSONArray(app.dangerousPermissions))
                }
                appsArray.put(appObj)
            }
            put("flagged_applications", appsArray)
        }
        root.put("application_audit", appAudit)

        // 4. Storage Audit
        val storageAudit = JSONObject().apply {
            put("files_scanned", assessment.storageAudit.filesScannedCount)
            put("storage_access_granted", assessment.storageAudit.isStorageAccessGranted)
            val threatsArray = JSONArray()
            for (t in assessment.storageAudit.threatsFound) {
                val threatObj = JSONObject().apply {
                    put("file_name", t.fileName)
                    put("file_size_bytes", t.fileSize)
                    put("threat_type", t.threatType)
                    put("details", t.details)
                    put("severity", t.severity.name)
                    if (t.sha256Hash != null) put("sha256", t.sha256Hash)
                }
                threatsArray.put(threatObj)
            }
            put("threats_detected", threatsArray)
        }
        root.put("storage_audit", storageAudit)

        // 5. Network Audit
        val netAudit = JSONObject().apply {
            put("is_connected", assessment.networkAudit.isConnected)
            put("connection_type", assessment.networkAudit.connectionType)
            put("vpn_tunnel_active", assessment.networkAudit.isVpnActive)
            put("private_dns_enabled", assessment.networkAudit.isPrivateDnsActive)
            put("private_dns_server", assessment.networkAudit.privateDnsServer ?: "None")
            put("captive_portal_detected", assessment.networkAudit.isCaptivePortal)
        }
        root.put("network_audit", netAudit)

        // 6. Consolidated Findings
        val findingsArray = JSONArray()
        for (f in assessment.allFindings) {
            val fObj = JSONObject().apply {
                put("title", f.title)
                put("category", f.category.name)
                put("severity", f.severity.name)
                put("description", f.description)
                put("recommendation", f.recommendation)
                if (f.actionLabel != null) put("action_label", f.actionLabel)
            }
            findingsArray.put(fObj)
        }
        root.put("security_findings", findingsArray)
        return root
    }

    fun exportToJson(context: Context, assessment: CompleteSecurityAssessment): File {
        val root = buildAssessmentJson(assessment)
        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val dateStr = SimpleDateFormat("yyyy-MM-dd_HHmmss", Locale.US).format(Date())
        val reportFile = File(reportsDir, "DroidSentinel-Evidence-$dateStr.json")
        reportFile.writeText(root.toString(2))
        return reportFile
    }

    fun buildAssessmentMarkdown(assessment: CompleteSecurityAssessment): String {
        val sb = StringBuilder()
        sb.appendLine("# DroidSentinel Mobile Endpoint Security Audit Report")
        sb.appendLine("Part of the **Fullstop Solution** Precision Ecosystem (www.fullstopsolution.in)")
        sb.appendLine("Generated: ${assessment.timestampIso}\n")

        sb.appendLine("## Executive Summary")
        sb.appendLine("* **Overall Posture Score**: `${assessment.overallScore}/100` (${assessment.overallStatus.name})")
        sb.appendLine("* **Target Device**: ${assessment.deviceManufacturer} ${assessment.deviceModel}")
        sb.appendLine("* **Android Platform**: ${assessment.androidVersion} (Patch: ${assessment.securityPatch})")
        sb.appendLine("* **Root Status**: ${if (assessment.integrity.isRooted) "COMPROMISED (Root detected)" else "CLEAN"}")
        sb.appendLine("* **SELinux Mode**: ${assessment.integrity.selinuxMode}")
        sb.appendLine("* **Hardware Keystore**: ${if (assessment.integrity.hasHardwareKeystore) "Hardware-Backed TEE" else "Software"}")
        sb.appendLine("* **StrongBox HSM**: ${if (assessment.integrity.hasStrongBox) "Supported" else "Not Present"}\n")

        sb.appendLine("## Defense Pillar Posture")
        sb.appendLine("| Pillar | Metric | Status |")
        sb.appendLine("| :--- | :--- | :--- |")
        sb.appendLine("| **OS Integrity** | SELinux: ${assessment.integrity.selinuxMode}, ADB: ${if (assessment.integrity.isAdbEnabled) "Active" else "Disabled"} | ${if (assessment.integrity.isRooted) "CRITICAL" else "SECURE"} |")
        sb.appendLine("| **Application Audit** | ${assessment.appAudit.totalAppsScanned} scanned, ${assessment.appAudit.highRiskApps.size} high risk, ${assessment.appAudit.sideloadedApps.size} sideloaded | ${if (assessment.appAudit.highRiskApps.isNotEmpty()) "CRITICAL" else "SECURE"} |")
        sb.appendLine("| **Storage & Macros** | ${assessment.storageAudit.filesScannedCount} files reviewed, ${assessment.storageAudit.threatsFound.size} threats found | ${if (assessment.storageAudit.threatsFound.isNotEmpty()) "CRITICAL" else "SECURE"} |")
        sb.appendLine("| **Network Defense** | ${assessment.networkAudit.connectionType}, VPN: ${assessment.networkAudit.isVpnActive}, DoT: ${assessment.networkAudit.isPrivateDnsActive} | ${if (assessment.networkAudit.isVpnActive) "SECURE" else "INFO"} |\n")

        sb.appendLine("## Security Findings (${assessment.allFindings.size})")
        for (f in assessment.allFindings) {
            sb.appendLine("### [${f.severity.name}] ${f.title}")
            sb.appendLine("* **Category**: `${f.category.name}`")
            sb.appendLine("* **Description**: ${f.description}")
            if (f.recommendation.isNotEmpty()) {
                sb.appendLine("* **Remediation Action**: ${f.recommendation}")
            }
            sb.appendLine()
        }

        sb.appendLine("---")
        sb.appendLine("Fullstop Solution Mobile Precision Security Suite • Zero-Cloud Read-Only Audit Standard")
        return sb.toString()
    }

    fun exportToMarkdown(context: Context, assessment: CompleteSecurityAssessment): File {
        val content = buildAssessmentMarkdown(assessment)
        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val dateStr = SimpleDateFormat("yyyy-MM-dd_HHmmss", Locale.US).format(Date())
        val reportFile = File(reportsDir, "DroidSentinel-Executive-Report-$dateStr.md")
        reportFile.writeText(content)
        return reportFile
    }

    fun copySummaryToClipboard(context: Context, assessment: CompleteSecurityAssessment) {
        val summary = """
            [DroidSentinel Security Audit]
            Score: ${assessment.overallScore}/100 (${assessment.overallStatus.name})
            Device: ${assessment.deviceManufacturer} ${assessment.deviceModel} (Android ${assessment.androidVersion})
            Root: ${if (assessment.integrity.isRooted) "COMPROMISED" else "CLEAN"}
            SELinux: ${assessment.integrity.selinuxMode}
            High Risk Apps: ${assessment.appAudit.highRiskApps.size}
            Storage Threats: ${assessment.storageAudit.threatsFound.size}
            VPN: ${if (assessment.networkAudit.isVpnActive) "Active" else "Disabled"} | Private DNS: ${if (assessment.networkAudit.isPrivateDnsActive) "Enabled" else "Off"}
            Total Findings: ${assessment.allFindings.size}
            Fullstop Solution Mobile Precision Suite (www.fullstopsolution.in)
        """.trimIndent()

        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = ClipData.newPlainText("DroidSentinel Audit Summary", summary)
        clipboard?.setPrimaryClip(clip)
        Toast.makeText(context, "Audit summary copied to clipboard!", Toast.LENGTH_SHORT).show()
    }

    fun shareEvidence(context: Context, assessment: CompleteSecurityAssessment) {
        val file = exportToJson(context, assessment)
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )

        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "DroidSentinel Security Audit Evidence")
            putExtra(Intent.EXTRA_TEXT, "Generated DroidSentinel Endpoint Evidence Report (${assessment.timestampIso}). Overall Security Score: ${assessment.overallScore}/100 (${assessment.overallStatus.name}).")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val chooser = Intent.createChooser(intent, "Export Security Audit Evidence (JSON)")
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
    }

    fun shareMarkdownReport(context: Context, assessment: CompleteSecurityAssessment) {
        val file = exportToMarkdown(context, assessment)
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )

        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/markdown"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "DroidSentinel Executive Security Audit Report")
            putExtra(Intent.EXTRA_TEXT, "Executive Security Audit Report for ${assessment.deviceManufacturer} ${assessment.deviceModel}. Score: ${assessment.overallScore}/100.")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val chooser = Intent.createChooser(intent, "Export Executive Report (Markdown)")
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
    }
}
