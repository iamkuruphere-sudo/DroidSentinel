package com.fullstopsolution.droidsentinel.snapshot

import android.content.Context
import android.util.Log
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException

class SnapshotStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun loadSnapshots(): List<AuditSnapshot> {
        return readSnapshots() ?: emptyList()
    }

    fun saveSnapshot(assessment: CompleteSecurityAssessment): List<AuditSnapshot> {
        val existingSnapshots = readSnapshots()
            ?: throw IOException("Saved snapshot history is unreadable; no changes were made.")
        val snapshots = (listOf(AuditSnapshot.fromAssessment(assessment)) + existingSnapshots)
            .distinctBy { it.timestamp }
            .sortedByDescending { it.timestamp }
            .take(MAX_SNAPSHOTS)
        val serialized = JSONArray().apply {
            snapshots.forEach { put(it.toJson()) }
        }.toString()

        if (!preferences.edit().putString(SNAPSHOTS_KEY, serialized).commit()) {
            throw IOException("Unable to persist audit snapshot.")
        }
        return snapshots
    }

    private fun readSnapshots(): List<AuditSnapshot>? {
        val serialized = preferences.getString(SNAPSHOTS_KEY, null) ?: return emptyList()
        return try {
            decodeSnapshots(JSONArray(serialized))
        } catch (error: JSONException) {
            Log.e(TAG, "Saved audit snapshots could not be decoded.", error)
            null
        }
    }

    private fun decodeSnapshots(array: JSONArray): List<AuditSnapshot> = buildList {
        for (index in 0 until array.length()) {
            try {
                add(array.getJSONObject(index).toSnapshot())
            } catch (error: JSONException) {
                Log.e(TAG, "Skipping a malformed saved audit snapshot.", error)
            } catch (error: IllegalArgumentException) {
                Log.e(TAG, "Skipping a saved audit snapshot with an unknown severity.", error)
            }
        }
    }.sortedByDescending { it.timestamp }

    private fun AuditSnapshot.toJson() = JSONObject().apply {
        put("timestamp", timestamp)
        put("timestamp_iso", timestampIso)
        put("device_model", deviceModel)
        put("android_version", androidVersion)
        put("security_patch", securityPatch)
        put("overall_score", overallScore)
        put("overall_status", overallStatus.name)
        put("is_rooted", isRooted)
        put("selinux_mode", selinuxMode)
        put("adb_enabled", isAdbEnabled)
        put("adb_wifi_enabled", isAdbWifiEnabled)
        put("device_locked", isDeviceLocked)
        put("strongbox_supported", hasStrongBox)
        put("hardware_keystore_available", hasHardwareKeystore)
        put("high_risk_app_count", highRiskAppCount)
        put("sideloaded_app_count", sideloadedAppCount)
        put("storage_threat_count", storageThreatCount)
        put("vpn_active", isVpnActive)
        put("private_dns_strict", isPrivateDnsStrict)
        put("findings", JSONArray().apply {
            findings.forEach { finding ->
                put(JSONObject().apply {
                    put("title", finding.title)
                    put("description", finding.description)
                    put("severity", finding.severity.name)
                    put("recommendation", finding.recommendation)
                })
            }
        })
    }

    private fun JSONObject.toSnapshot(): AuditSnapshot {
        val findings = getJSONArray("findings")
        return AuditSnapshot(
            timestamp = getLong("timestamp"),
            timestampIso = getString("timestamp_iso"),
            deviceModel = getString("device_model"),
            androidVersion = getString("android_version"),
            securityPatch = getString("security_patch"),
            overallScore = getInt("overall_score"),
            overallStatus = Severity.valueOf(getString("overall_status")),
            isRooted = getBoolean("is_rooted"),
            selinuxMode = getString("selinux_mode"),
            isAdbEnabled = getBoolean("adb_enabled"),
            isAdbWifiEnabled = getBoolean("adb_wifi_enabled"),
            isDeviceLocked = getBoolean("device_locked"),
            hasStrongBox = getBoolean("strongbox_supported"),
            hasHardwareKeystore = getBoolean("hardware_keystore_available"),
            highRiskAppCount = getInt("high_risk_app_count"),
            sideloadedAppCount = getInt("sideloaded_app_count"),
            storageThreatCount = getInt("storage_threat_count"),
            isVpnActive = getBoolean("vpn_active"),
            isPrivateDnsStrict = getBoolean("private_dns_strict"),
            findings = buildList {
                for (index in 0 until findings.length()) {
                    val finding = findings.getJSONObject(index)
                    add(
                        Finding(
                            title = finding.getString("title"),
                            description = finding.getString("description"),
                            severity = Severity.valueOf(finding.getString("severity")),
                            recommendation = finding.getString("recommendation")
                        )
                    )
                }
            }
        )
    }

    private companion object {
        const val PREFERENCES_NAME = "droidsentinel_audit_snapshots"
        const val SNAPSHOTS_KEY = "snapshots"
        const val MAX_SNAPSHOTS = 20
        const val TAG = "SnapshotStore"
    }
}
