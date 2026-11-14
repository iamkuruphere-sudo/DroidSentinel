package com.fullstopsolution.droidsentinel.model

enum class Severity {
    SECURE,
    INFO,
    WARNING,
    CRITICAL
}

enum class ActionType {
    NONE,
    OPEN_DEVELOPER_OPTIONS,
    OPEN_SECURITY_SETTINGS,
    OPEN_BIOMETRIC_ENROLL,
    OPEN_WIRELESS_SETTINGS,
    OPEN_PRIVATE_DNS_SETTINGS,
    OPEN_APP_SETTINGS,
    UNINSTALL_APP,
    MANAGE_STORAGE,
    OPEN_PLAY_PROTECT
}

enum class FindingCategory {
    INTEGRITY,
    APPS,
    STORAGE,
    NETWORK
}

data class Finding(
    val title: String,
    val description: String,
    val severity: Severity,
    val recommendation: String = "",
    val actionType: ActionType = ActionType.NONE,
    val actionPayload: String? = null,
    val actionLabel: String? = null,
    val category: FindingCategory = FindingCategory.INTEGRITY
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
    val isKeystoreHardwareBacked: Boolean = hasHardwareKeystore,
    val biometricStatus: String = "Unknown",
    val isTestKeysBuild: Boolean = buildTags.contains("test-keys"),
    val isSystemDebuggable: Boolean = false,
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
    val usesCleartextTraffic: Boolean = false,
    val exportedComponentsCount: Int = 0,
    val dangerousPermissions: List<String>,
    val riskFindings: List<Finding>,
    val riskScore: Int
)

data class AppAuditResult(
    val totalAppsScanned: Int,
    val sideloadedApps: List<AppThreatInfo>,
    val highRiskApps: List<AppThreatInfo>,
    val autorunApps: List<AppThreatInfo>,
    val cleartextApps: List<AppThreatInfo> = emptyList(),
    val findings: List<Finding>
)

data class StorageThreatInfo(
    val fileName: String,
    val filePath: String,
    val fileSize: Long,
    val threatType: String,
    val details: String,
    val severity: Severity,
    val sha256Hash: String? = null
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
    val privateDnsServer: String? = null,
    val isCaptivePortal: Boolean = false,
    val findings: List<Finding>
)

enum class ScanStage {
    IDLE,
    INTEGRITY_AUDIT,
    APPLICATION_AUDIT,
    STORAGE_INSPECTION,
    NETWORK_AUDIT,
    FINALIZING,
    COMPLETED,
    CANCELLED
}

data class ScanProgress(
    val isScanning: Boolean = false,
    val isPaused: Boolean = false,
    val stage: ScanStage = ScanStage.IDLE,
    val stageProgress: Float = 0f,
    val percentage: Int = 0,
    val detailText: String = "System ready for on-device security audit"
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
