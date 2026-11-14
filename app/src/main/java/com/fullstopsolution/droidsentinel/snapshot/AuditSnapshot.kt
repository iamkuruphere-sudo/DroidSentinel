package com.fullstopsolution.droidsentinel.snapshot

import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity

data class AuditSnapshot(
    val timestamp: Long,
    val timestampIso: String,
    val deviceModel: String,
    val androidVersion: String,
    val securityPatch: String,
    val overallScore: Int,
    val overallStatus: Severity,
    val isRooted: Boolean,
    val selinuxMode: String,
    val isAdbEnabled: Boolean,
    val isAdbWifiEnabled: Boolean,
    val isDeviceLocked: Boolean,
    val hasStrongBox: Boolean,
    val hasHardwareKeystore: Boolean,
    val highRiskAppCount: Int,
    val sideloadedAppCount: Int,
    val storageThreatCount: Int,
    val isVpnActive: Boolean,
    val isPrivateDnsStrict: Boolean,
    val findings: List<Finding>
) {
    companion object {
        fun fromAssessment(assessment: CompleteSecurityAssessment) = AuditSnapshot(
            timestamp = assessment.timestamp,
            timestampIso = assessment.timestampIso,
            deviceModel = "${assessment.deviceManufacturer} ${assessment.deviceModel}",
            androidVersion = assessment.androidVersion,
            securityPatch = assessment.securityPatch,
            overallScore = assessment.overallScore,
            overallStatus = assessment.overallStatus,
            isRooted = assessment.integrity.isRooted,
            selinuxMode = assessment.integrity.selinuxMode,
            isAdbEnabled = assessment.integrity.isAdbEnabled,
            isAdbWifiEnabled = assessment.integrity.isAdbWifiEnabled,
            isDeviceLocked = assessment.integrity.isDeviceLocked,
            hasStrongBox = assessment.integrity.hasStrongBox,
            hasHardwareKeystore = assessment.integrity.hasHardwareKeystore,
            highRiskAppCount = assessment.appAudit.highRiskApps.size,
            sideloadedAppCount = assessment.appAudit.sideloadedApps.size,
            storageThreatCount = assessment.storageAudit.threatsFound.size,
            isVpnActive = assessment.networkAudit.isVpnActive,
            isPrivateDnsStrict = assessment.networkAudit.isPrivateDnsActive,
            findings = assessment.allFindings
        )
    }
}
