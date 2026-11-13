package com.fullstopsolution.droidsentinel.model

enum class Severity {
    SECURE,
    INFO,
    WARNING,
    CRITICAL
}

data class Finding(
    val title: String,
    val description: String,
    val severity: Severity,
    val recommendation: String = ""
)

data class DeviceIntegrityResult(
    val isRooted: Boolean,
    val rootSignals: List<Finding>,
    val selinuxMode: String,
    val buildTags: String,
    val isAdbEnabled: Boolean,
    val isAdbWifiEnabled: Boolean,
    val isDeviceLocked: Boolean,
    val hasStrongBox: Boolean,
    val hasHardwareKeystore: Boolean,
    val findings: List<Finding>
)

data class AppThreatInfo(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val targetSdk: Int,
    val installerPackage: String?,
    val isSideloaded: Boolean,
    val isDebuggable: Boolean,
    val isBootCompleted: Boolean,
    val dangerousPermissions: List<String>,
    val riskFindings: List<Finding>,
    val riskScore: Int
)

data class AppAuditResult(
    val totalAppsScanned: Int,
    val sideloadedApps: List<AppThreatInfo>,
    val highRiskApps: List<AppThreatInfo>,
    val autorunApps: List<AppThreatInfo>,
    val findings: List<Finding>
)

data class StorageThreatInfo(
    val fileName: String,
    val filePath: String,
    val fileSize: Long,
    val threatType: String,
    val details: String,
    val severity: Severity
)

data class StorageAuditResult(
    val filesScannedCount: Int,
    val threatsFound: List<StorageThreatInfo>,
    val isStorageAccessGranted: Boolean,
    val findings: List<Finding>
)

data class NetworkAuditResult(
    val isConnected: Boolean,
    val connectionType: String,
    val isWifiEncrypted: Boolean,
    val wifiSecurityType: String,
    val isVpnActive: Boolean,
    val isPrivateDnsActive: Boolean,
    val findings: List<Finding>
)

data class CompleteSecurityAssessment(
    val timestamp: Long,
    val timestampIso: String,
    val deviceModel: String,
    val deviceManufacturer: String,
    val androidVersion: String,
    val securityPatch: String,
    val overallScore: Int,
    val overallStatus: Severity,
    val integrity: DeviceIntegrityResult,
    val appAudit: AppAuditResult,
    val storageAudit: StorageAuditResult,
    val networkAudit: NetworkAuditResult,
    val allFindings: List<Finding>
)
