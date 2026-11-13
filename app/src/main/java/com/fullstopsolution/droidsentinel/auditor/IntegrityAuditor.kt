package com.fullstopsolution.droidsentinel.auditor

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.fullstopsolution.droidsentinel.model.DeviceIntegrityResult
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.KeyStore

object IntegrityAuditor {

    private val KNOWN_SU_PATHS = arrayOf(
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/system/app/Superuser.apk",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu",
        "/data/adb/ksu",
        "/data/adb/magisk"
    )

    private val ROOT_PACKAGES = arrayOf(
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "io.github.a13e300.ksu",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.chelpus.lackypatch"
    )

    fun audit(context: Context): DeviceIntegrityResult {
        val rootFindings = mutableListOf<Finding>()
        val generalFindings = mutableListOf<Finding>()

        // 1. Filesystem binary presence
        for (path in KNOWN_SU_PATHS) {
            try {
                if (File(path).exists()) {
                    rootFindings.add(
                        Finding(
                            title = "Root Binary Detected",
                            description = "Privileged execution binary identified at $path",
                            severity = Severity.CRITICAL,
                            recommendation = "Device firmware has been altered. Re-flash official stock firmware."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }
        }

        // 2. Command execution test ('which su')
        if (canExecuteSu()) {
            rootFindings.add(
                Finding(
                    title = "Superuser Shell Available",
                    description = "'su' execution succeeded in local process environment.",
                    severity = Severity.CRITICAL,
                    recommendation = "Device possesses unconfined superuser access."
                )
            )
        }

        // 3. Test-keys / Custom ROM signature
        val buildTags = Build.TAGS ?: ""
        if (buildTags.contains("test-keys")) {
            rootFindings.add(
                Finding(
                    title = "Custom ROM / Test-Keys Build",
                    description = "Build tags indicate an unofficial or developer test-signed OS build ($buildTags).",
                    severity = Severity.WARNING,
                    recommendation = "Use manufacturer release-keys builds for secure enterprise operations."
                )
            )
        }

        // 4. Root management apps installed
        val pm = context.packageManager
        for (pkg in ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                rootFindings.add(
                    Finding(
                        title = "Root Management Package Installed",
                        description = "Identified package '$pkg' on device.",
                        severity = Severity.CRITICAL,
                        recommendation = "Root managers grant arbitrary apps root filesystem permissions."
                    )
                )
            } catch (_: PackageManager.NameNotFoundException) {
            }
        }

        // 5. SELinux enforcement state
        val selinuxMode = querySELinuxMode()
        if (selinuxMode != "Enforcing") {
            generalFindings.add(
                Finding(
                    title = "SELinux Permissive or Disabled",
                    description = "SELinux is operating in mode '$selinuxMode' instead of Enforcing.",
                    severity = Severity.CRITICAL,
                    recommendation = "Enable SELinux Enforcing mode to maintain mandatory access controls."
                )
            )
        }

        // 6. USB Debugging & ADB
        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        } catch (_: Exception) {
            false
        }

        if (adbEnabled) {
            generalFindings.add(
                Finding(
                    title = "USB Debugging Active",
                    description = "Android Debug Bridge (ADB) interface is enabled over USB.",
                    severity = Severity.WARNING,
                    recommendation = "Disable USB Debugging in Developer Options when not actively testing."
                )
            )
        }

        // 7. Wireless ADB
        val adbWifiEnabled = try {
            Settings.Global.getInt(context.contentResolver, "adb_wifi_enabled", 0) != 0
        } catch (_: Exception) {
            false
        }
        if (adbWifiEnabled) {
            generalFindings.add(
                Finding(
                    title = "Wireless Debugging Active",
                    description = "ADB daemon is listening for network connections over Wi-Fi.",
                    severity = Severity.CRITICAL,
                    recommendation = "Disable Wireless Debugging to prevent remote lateral movement."
                )
            )
        }

        // 8. Keyguard / Screen Lock security
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val isDeviceLocked = keyguardManager?.isDeviceSecure ?: false
        if (!isDeviceLocked) {
            generalFindings.add(
                Finding(
                    title = "No Secure Screen Lock Configured",
                    description = "Device does not require a PIN, Password, or Biometric to unlock.",
                    severity = Severity.CRITICAL,
                    recommendation = "Set a secure device lock in Settings to encrypt keystore credentials."
                )
            )
        }

        // 9. Hardware Keystore & StrongBox Keystore
        val hasStrongBox = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val hasHardwareKeystore = try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            true
        } catch (_: Exception) {
            false
        }

        if (!hasStrongBox) {
            generalFindings.add(
                Finding(
                    title = "Dedicated StrongBox HSM Not Available",
                    description = "Device hardware lacks a separate discrete secure element (StrongBox).",
                    severity = Severity.INFO,
                    recommendation = "Keys are backed by standard TEE rather than dedicated HSM."
                )
            )
        }

        val isRooted = rootFindings.any { it.severity == Severity.CRITICAL }

        return DeviceIntegrityResult(
            isRooted = isRooted,
            rootSignals = rootFindings,
            selinuxMode = selinuxMode,
            buildTags = buildTags,
            isAdbEnabled = adbEnabled,
            isAdbWifiEnabled = adbWifiEnabled,
            isDeviceLocked = isDeviceLocked,
            hasStrongBox = hasStrongBox,
            hasHardwareKeystore = hasHardwareKeystore,
            findings = rootFindings + generalFindings
        )
    }

    private fun canExecuteSu(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                val line = reader.readLine()
                process.destroy()
                line != null && line.trim().isNotEmpty()
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun querySELinuxMode(): String {
        return try {
            val process = Runtime.getRuntime().exec("/system/bin/getenforce")
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                val line = reader.readLine()?.trim()
                process.destroy()
                if (line.isNullOrEmpty()) "Enforcing" else line
            }
        } catch (_: Exception) {
            "Enforcing"
        }
    }
}
