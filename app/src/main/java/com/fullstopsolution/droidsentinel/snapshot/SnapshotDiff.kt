package com.fullstopsolution.droidsentinel.snapshot

import com.fullstopsolution.droidsentinel.model.Finding

data class SnapshotDiff(
    val scoreChange: Int,
    val statusChanged: Boolean,
    val metricChanges: List<SnapshotMetricChange>,
    val addedFindings: List<Finding>,
    val resolvedFindings: List<Finding>
)

data class SnapshotMetricChange(
    val label: String,
    val previousValue: String,
    val currentValue: String
)

fun compareSnapshots(previous: AuditSnapshot, current: AuditSnapshot): SnapshotDiff {
    val previousFindings = previous.findings.associateBy(::findingIdentity)
    val currentFindings = current.findings.associateBy(::findingIdentity)

    return SnapshotDiff(
        scoreChange = current.overallScore - previous.overallScore,
        statusChanged = previous.overallStatus != current.overallStatus,
        metricChanges = changedMetrics(previous, current),
        addedFindings = currentFindings.filterKeys { it !in previousFindings }.values.toList(),
        resolvedFindings = previousFindings.filterKeys { it !in currentFindings }.values.toList()
    )
}

private fun changedMetrics(previous: AuditSnapshot, current: AuditSnapshot): List<SnapshotMetricChange> = buildList {
    addIfChanged("Root status", previous.isRooted.toStatus(), current.isRooted.toStatus())
    addIfChanged("Android version", previous.androidVersion, current.androidVersion)
    addIfChanged("Security patch", previous.securityPatch, current.securityPatch)
    addIfChanged("SELinux", previous.selinuxMode, current.selinuxMode)
    addIfChanged("USB debugging", previous.isAdbEnabled.toStatus("Enabled", "Disabled"), current.isAdbEnabled.toStatus("Enabled", "Disabled"))
    addIfChanged(
        "Wireless debugging",
        previous.isAdbWifiEnabled.toStatus("Enabled", "Disabled"),
        current.isAdbWifiEnabled.toStatus("Enabled", "Disabled")
    )
    addIfChanged(
        "Screen lock",
        previous.isDeviceLocked.toStatus("Configured", "Not configured"),
        current.isDeviceLocked.toStatus("Configured", "Not configured")
    )
    addIfChanged(
        "StrongBox",
        previous.hasStrongBox.toStatus("Supported", "Unavailable"),
        current.hasStrongBox.toStatus("Supported", "Unavailable")
    )
    addIfChanged(
        "Hardware keystore",
        previous.hasHardwareKeystore.toStatus("Available", "Unavailable"),
        current.hasHardwareKeystore.toStatus("Available", "Unavailable")
    )
    addIfChanged("High-risk apps", previous.highRiskAppCount.toString(), current.highRiskAppCount.toString())
    addIfChanged("Sideloaded apps", previous.sideloadedAppCount.toString(), current.sideloadedAppCount.toString())
    addIfChanged("Storage threats", previous.storageThreatCount.toString(), current.storageThreatCount.toString())
    addIfChanged("VPN", previous.isVpnActive.toStatus("Active", "Inactive"), current.isVpnActive.toStatus("Active", "Inactive"))
    addIfChanged(
        "Strict Private DNS",
        previous.isPrivateDnsStrict.toStatus("Configured", "Not configured"),
        current.isPrivateDnsStrict.toStatus("Configured", "Not configured")
    )
}

private fun MutableList<SnapshotMetricChange>.addIfChanged(label: String, previous: String, current: String) {
    if (previous != current) add(SnapshotMetricChange(label, previous, current))
}

private fun Boolean.toStatus(trueValue: String = "Detected", falseValue: String = "Clear"): String =
    if (this) trueValue else falseValue

private fun findingIdentity(finding: Finding): String = "${finding.severity.name}\u0000${finding.title}"
