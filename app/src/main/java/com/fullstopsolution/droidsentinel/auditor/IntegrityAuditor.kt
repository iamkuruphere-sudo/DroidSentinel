package com.fullstopsolution.droidsentinel.auditor

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.DeviceIntegrityResult
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.FindingCategory
import com.fullstopsolution.droidsentinel.model.Severity
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.InputStreamReader
import java.lang.reflect.Method
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory

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
        "/vendor/bin/su",
        "/product/bin/su",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/system/bin/ksud",
        "/data/adb/ap",
        "/data/adb/apd",
        "/data/adb/magisk",
        "/sbin/.magisk",
        "/cache/magisk.log",
        "/data/adb/magisk.db",
        "/system/bin/busybox",
        "/system/xbin/busybox",
        "/vendor/bin/busybox"
    )

    private val ROOT_PACKAGES = arrayOf(
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "io.github.a13e300.ksu",
        "me.bmax.apatch",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.chelpus.lackypatch",
        "org.lsposed.manager",
        "de.robv.android.xposed.installer",
        "io.github.lsposed"
    )

    fun audit(context: Context): DeviceIntegrityResult {
        val rootFindings = mutableListOf<Finding>()
        val generalFindings = mutableListOf<Finding>()

        // 1. Filesystem binary presence
        for (path in KNOWN_SU_PATHS) {
            try {
                val f = File(path)
                if (f.exists()) {
                    rootFindings.add(
                        Finding(
                            title = "Root Binary Detected",
                            description = "Privileged superuser execution binary identified at $path",
                            severity = Severity.CRITICAL,
                            recommendation = "Device firmware has been altered. Re-flash official stock firmware.",
                            actionType = ActionType.OPEN_SECURITY_SETTINGS,
                            actionLabel = "Open Security",
                            category = FindingCategory.INTEGRITY
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
                    recommendation = "Device possesses unconfined superuser access.",
                    actionType = ActionType.OPEN_SECURITY_SETTINGS,
                    actionLabel = "Open Security",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 3. Mount namespace inspection (Magisk / KernelSU / Overlay mounts)
        val mountSignal = checkSuspiciousMounts()
        if (mountSignal != null) {
            rootFindings.add(
                Finding(
                    title = "Root Overlay Mount Detected",
                    description = mountSignal,
                    severity = Severity.CRITICAL,
                    recommendation = "Active Magisk or KernelSU overlay mount identified in /proc/mounts.",
                    actionType = ActionType.OPEN_SECURITY_SETTINGS,
                    actionLabel = "Open Security",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 4. Kernel version check (KernelSU / APatch string)
        val kernelSignal = checkKernelVersionString()
        if (kernelSignal != null) {
            rootFindings.add(
                Finding(
                    title = "Custom Kernel Hook Detected",
                    description = kernelSignal,
                    severity = Severity.CRITICAL,
                    recommendation = "Kernel image modified with kernel-level root hooks (KernelSU / APatch).",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 5. Test-keys / Custom ROM signature
        val buildTags = Build.TAGS ?: ""
        if (buildTags.contains("test-keys")) {
            rootFindings.add(
                Finding(
                    title = "Custom ROM / Test-Keys Build",
                    description = "Build tags indicate an unofficial or developer test-signed OS build ($buildTags).",
                    severity = Severity.WARNING,
                    recommendation = "Use manufacturer release-keys builds for secure enterprise operations.",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 6. System Properties: ro.debuggable / ro.secure
        val isDebuggableProp = getSystemProperty("ro.debuggable") == "1"
        val isSecurePropZero = getSystemProperty("ro.secure") == "0"
        if (isDebuggableProp || isSecurePropZero) {
            rootFindings.add(
                Finding(
                    title = "Insecure OS Build Configuration",
                    description = "Dangerous build flags active: ro.debuggable=$isDebuggableProp, ro.secure=${if (isSecurePropZero) "0 (insecure)" else "1"}.",
                    severity = Severity.CRITICAL,
                    recommendation = "Production firmware must have ro.debuggable=0 and ro.secure=1.",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 7. Writable system partition probe
        if (isSystemPartitionWritable()) {
            rootFindings.add(
                Finding(
                    title = "System Partition Mounted Read-Write",
                    description = "/system or /vendor is writeable by unprivileged user process.",
                    severity = Severity.CRITICAL,
                    recommendation = "Lock filesystem mounts to Read-Only enforced by DM-Verity.",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 8. Root management & Hooking apps installed
        val pm = context.packageManager
        for (pkg in ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                rootFindings.add(
                    Finding(
                        title = "Root / Hooking Package Installed",
                        description = "Identified package '$pkg' on device.",
                        severity = Severity.CRITICAL,
                        recommendation = "Root/Hooking managers allow arbitrary apps to bypass Android sandboxing.",
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg,
                        actionLabel = "Inspect App",
                        category = FindingCategory.INTEGRITY
                    )
                )
            } catch (_: PackageManager.NameNotFoundException) {
            }
        }

        // 9. Xposed / Dynamic Hooking Framework Probe
        if (isXposedFrameworkActive()) {
            rootFindings.add(
                Finding(
                    title = "Dynamic Hooking Framework (Xposed / LSPosed)",
                    description = "XposedBridge class loaded in memory; bytecode instrumentation active.",
                    severity = Severity.CRITICAL,
                    recommendation = "Remove LSPosed/EdXposed runtime to prevent runtime memory manipulation.",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 10. SELinux enforcement state
        val selinuxMode = querySELinuxMode()
        if (selinuxMode != "Enforcing") {
            generalFindings.add(
                Finding(
                    title = "SELinux Permissive or Disabled",
                    description = "SELinux is operating in mode '$selinuxMode' instead of Enforcing.",
                    severity = Severity.CRITICAL,
                    recommendation = "Enable SELinux Enforcing mode to maintain mandatory access controls.",
                    actionType = ActionType.OPEN_SECURITY_SETTINGS,
                    actionLabel = "Open Security",
                    category = FindingCategory.INTEGRITY
                )
            )
        } else {
            generalFindings.add(
                Finding(
                    title = "SELinux Enforcing Active",
                    description = "Mandatory Access Control (MAC) is active and strictly confining application domains.",
                    severity = Severity.SECURE,
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 11. USB Debugging & ADB
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
                    recommendation = "Disable USB Debugging in Developer Options when not actively testing.",
                    actionType = ActionType.OPEN_DEVELOPER_OPTIONS,
                    actionLabel = "Open Dev Options",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 12. Wireless ADB
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
                    recommendation = "Disable Wireless Debugging to prevent remote lateral movement.",
                    actionType = ActionType.OPEN_DEVELOPER_OPTIONS,
                    actionLabel = "Open Dev Options",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 13. Keyguard / Screen Lock security
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val isDeviceLocked = keyguardManager?.isDeviceSecure ?: false
        if (!isDeviceLocked) {
            generalFindings.add(
                Finding(
                    title = "No Secure Screen Lock Configured",
                    description = "Device does not require a PIN, Password, or Biometric to unlock.",
                    severity = Severity.CRITICAL,
                    recommendation = "Set a secure device lock in Settings to encrypt keystore credentials.",
                    actionType = ActionType.OPEN_SECURITY_SETTINGS,
                    actionLabel = "Setup Screen Lock",
                    category = FindingCategory.INTEGRITY
                )
            )
        } else {
            generalFindings.add(
                Finding(
                    title = "Secure Screen Lock Configured",
                    description = "Device requires PIN, pattern, password, or biometric credential to unlock.",
                    severity = Severity.SECURE,
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        // 14. Biometric Status & Enrollment
        val (biometricStatus, biometricFinding) = evaluateBiometrics(context)
        if (biometricFinding != null) {
            generalFindings.add(biometricFinding)
        }

        // 15. Hardware Keystore & StrongBox Probe
        val hasStrongBox = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val isHardwareBacked = probeKeystoreHardwareBacked()

        if (hasStrongBox) {
            generalFindings.add(
                Finding(
                    title = "StrongBox Keymaster HSM Supported",
                    description = "Dedicated discrete hardware secure element (StrongBox) is present on device.",
                    severity = Severity.SECURE,
                    category = FindingCategory.INTEGRITY
                )
            )
        } else {
            generalFindings.add(
                Finding(
                    title = "Dedicated StrongBox HSM Not Available",
                    description = "Device hardware lacks a separate discrete secure element (keys reside in TEE).",
                    severity = Severity.INFO,
                    recommendation = "Keys are backed by standard processor TEE rather than dedicated HSM.",
                    category = FindingCategory.INTEGRITY
                )
            )
        }

        if (isHardwareBacked) {
            generalFindings.add(
                Finding(
                    title = "Hardware-Backed Keymaster TEE Active",
                    description = "Cryptographic probe key verified inside secure hardware enclave (TEE/TrustZone).",
                    severity = Severity.SECURE,
                    category = FindingCategory.INTEGRITY
                )
            )
        } else {
            generalFindings.add(
                Finding(
                    title = "Keystore Emulated in Software",
                    description = "Cryptographic key generation is not backed by hardware enclave.",
                    severity = Severity.WARNING,
                    recommendation = "Cryptographic operations lack tamper-resistant hardware boundary.",
                    category = FindingCategory.INTEGRITY
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
            hasHardwareKeystore = isHardwareBacked,
            isKeystoreHardwareBacked = isHardwareBacked,
            biometricStatus = biometricStatus,
            isTestKeysBuild = buildTags.contains("test-keys"),
            isSystemDebuggable = isDebuggableProp,
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

    private fun checkSuspiciousMounts(): String? {
        val mountPaths = listOf("/proc/self/mounts", "/proc/mounts")
        for (path in mountPaths) {
            try {
                val file = File(path)
                if (file.exists() && file.canRead()) {
                    BufferedReader(FileReader(file)).use { reader ->
                        var line = reader.readLine()
                        while (line != null) {
                            val lower = line.lowercase()
                            if (lower.contains("magisk") || lower.contains("core/mirror") || lower.contains("/sbin/.magisk")) {
                                return "Magisk mount point identified: ${line.take(80)}"
                            }
                            if (lower.contains("ksud") || lower.contains("/data/adb/ksu")) {
                                return "KernelSU mount identified: ${line.take(80)}"
                            }
                            line = reader.readLine()
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
        return null
    }

    private fun checkKernelVersionString(): String? {
        try {
            val file = File("/proc/version")
            if (file.exists() && file.canRead()) {
                val content = file.readText().lowercase()
                if (content.contains("kernelsu") || content.contains("ksu-")) {
                    return "Kernel version string contains KernelSU signature"
                }
                if (content.contains("apatch")) {
                    return "Kernel version string contains APatch signature"
                }
            }
        } catch (_: Exception) {
        }
        return null
    }

    private fun isSystemPartitionWritable(): Boolean {
        val testDirs = listOf("/system", "/vendor")
        for (dir in testDirs) {
            try {
                val testFile = File(dir, "droidsentinel_rw_probe_${System.currentTimeMillis()}.tmp")
                if (testFile.createNewFile()) {
                    testFile.delete()
                    return true
                }
            } catch (_: Exception) {
            }
        }
        return false
    }

    private fun isXposedFrameworkActive(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        } catch (_: ClassNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun querySELinuxMode(): String {
        // 1. Try getenforce command
        try {
            val process = Runtime.getRuntime().exec("/system/bin/getenforce")
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                val line = reader.readLine()?.trim()
                process.destroy()
                if (!line.isNullOrEmpty()) return line
            }
        } catch (_: Exception) {
        }

        // 2. Try reading /sys/fs/selinux/enforce (1 = Enforcing, 0 = Permissive)
        try {
            val enforceFile = File("/sys/fs/selinux/enforce")
            if (enforceFile.exists() && enforceFile.canRead()) {
                val value = enforceFile.readText().trim()
                if (value == "1") return "Enforcing"
                if (value == "0") return "Permissive"
            }
        } catch (_: Exception) {
        }

        // 3. Fallback to system property
        val prop = getSystemProperty("ro.boot.selinux")
        if (prop.equals("permissive", ignoreCase = true)) {
            return "Permissive"
        }

        return "Enforcing"
    }

    private fun getSystemProperty(key: String): String {
        return try {
            val spClass = Class.forName("android.os.SystemProperties")
            val getMethod: Method = spClass.getMethod("get", String::class.java, String::class.java)
            getMethod.invoke(null, key, "") as? String ?: ""
        } catch (_: Exception) {
            try {
                val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
                BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                    val line = reader.readLine()?.trim()
                    process.destroy()
                    line ?: ""
                }
            } catch (_: Exception) {
                ""
            }
        }
    }

    private fun evaluateBiometrics(context: Context): Pair<String, Finding?> {
        val biometricManager = context.getSystemService(Context.BIOMETRIC_SERVICE) as? BiometricManager
            ?: return "Service Unavailable" to null

        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL

        return when (biometricManager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                "Enrolled & Active" to Finding(
                    title = "Biometric Authentication Enrolled",
                    description = "Strong biometric credentials (fingerprint/face) are active and verified.",
                    severity = Severity.SECURE,
                    category = FindingCategory.INTEGRITY
                )
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                "No Credentials Enrolled" to Finding(
                    title = "No Biometric Credentials Enrolled",
                    description = "Device supports biometrics but user has not enrolled biometric credentials.",
                    severity = Severity.WARNING,
                    recommendation = "Enroll biometric authentication in Settings for hardware-bound authorization.",
                    actionType = ActionType.OPEN_BIOMETRIC_ENROLL,
                    actionLabel = "Enroll Biometrics",
                    category = FindingCategory.INTEGRITY
                )
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                "Hardware Not Available" to Finding(
                    title = "No Biometric Hardware Sensor",
                    description = "Device hardware does not contain a biometric sensor.",
                    severity = Severity.INFO,
                    category = FindingCategory.INTEGRITY
                )
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                "Hardware Busy/Unavailable" to Finding(
                    title = "Biometric Sensor Unavailable",
                    description = "Biometric hardware is temporarily unavailable or compromised.",
                    severity = Severity.WARNING,
                    category = FindingCategory.INTEGRITY
                )
            }
            else -> "Unknown State" to null
        }
    }

    private fun probeKeystoreHardwareBacked(): Boolean {
        val alias = "droidsentinel_hw_probe_${System.currentTimeMillis()}"
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            val secretKey = keyGenerator.generateKey()

            val factory = SecretKeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
            val isHw = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }

            // Cleanup
            keyStore.deleteEntry(alias)
            isHw
        } catch (_: Exception) {
            false
        }
    }
}
