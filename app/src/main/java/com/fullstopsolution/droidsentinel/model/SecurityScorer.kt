package com.fullstopsolution.droidsentinel.model

object SecurityScorer {

    fun calculateScore(
        integrity: DeviceIntegrityResult,
        appAudit: AppAuditResult,
        storageAudit: StorageAuditResult,
        networkAudit: NetworkAuditResult
    ): Pair<Int, Severity> {
        return evaluateScore(
            isRooted = integrity.isRooted,
            selinuxMode = integrity.selinuxMode,
            isAdbEnabled = integrity.isAdbEnabled,
            isAdbWifiEnabled = integrity.isAdbWifiEnabled,
            isDeviceLocked = integrity.isDeviceLocked,
            hasHardwareKeystore = integrity.hasHardwareKeystore,
            highRiskAppsCount = appAudit.highRiskApps.size,
            storageThreatsCount = storageAudit.threatsFound.size,
            isVpnActive = networkAudit.isVpnActive,
            isPrivateDnsActive = networkAudit.isPrivateDnsActive
        )
    }

    fun evaluateScore(
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
}
