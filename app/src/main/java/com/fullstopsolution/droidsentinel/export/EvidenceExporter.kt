package com.fullstopsolution.droidsentinel.export

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object EvidenceExporter {

    fun exportToJson(context: Context, assessment: CompleteSecurityAssessment): File {
        val root = JSONObject()

        // 1. Ecosystem Metadata
        val meta = JSONObject().apply {
            put("suite", "Fullstop Solution Mobile Precision Security Suite")
            put("tool", "DroidSentinel Endpoint Security")
            put("version", "2.0.0")
            put("vendor", "Fullstop Solution (www.fullstopsolution.in)")
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
        }
        root.put("device_integrity", integrity)

        // 3. Application Audit
        val appAudit = JSONObject().apply {
            put("total_applications_reviewed", assessment.appAudit.totalAppsScanned)
            put("sideloaded_applications_count", assessment.appAudit.sideloadedApps.size)
            put("high_risk_applications_count", assessment.appAudit.highRiskApps.size)
            put("boot_autorun_applications_count", assessment.appAudit.autorunApps.size)

            val appsArray = JSONArray()
            for (app in assessment.appAudit.highRiskApps + assessment.appAudit.sideloadedApps.take(15)) {
                val appObj = JSONObject().apply {
                    put("name", app.appName)
                    put("package", app.packageName)
                    put("version", app.versionName)
                    put("target_sdk", app.targetSdk)
                    put("installer", app.installerPackage ?: "Direct/Sideload")
                    put("is_sideloaded", app.isSideloaded)
                    put("is_debuggable", app.isDebuggable)
                    put("is_boot_autorun", app.isBootCompleted)
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
        }
        root.put("network_audit", netAudit)

        // 6. Consolidated Findings
        val findingsArray = JSONArray()
        for (f in assessment.allFindings) {
            val fObj = JSONObject().apply {
                put("title", f.title)
                put("severity", f.severity.name)
                put("description", f.description)
                put("recommendation", f.recommendation)
            }
            findingsArray.put(fObj)
        }
        root.put("security_findings", findingsArray)

        // Write to cache file
        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val dateStr = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
        val reportFile = File(reportsDir, "DroidSentinel-Evidence-$dateStr.json")
        reportFile.writeText(root.toString(2))
        return reportFile
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
            putExtra(Intent.EXTRA_TEXT, "Generated DroidSentinel Endpoint Evidence Report (${assessment.timestampIso}). Overall Health Score: ${assessment.overallScore}/100.")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val chooser = Intent.createChooser(intent, "Export Security Audit Evidence")
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
    }
}
