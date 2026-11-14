package com.fullstopsolution.droidsentinel.auditor

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.AppAuditResult
import com.fullstopsolution.droidsentinel.model.AppThreatInfo
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.FindingCategory
import com.fullstopsolution.droidsentinel.model.Severity

object AppThreatAuditor {

    val TRUSTED_STORE_INSTALLERS = setOf(
        "com.android.vending",               // Google Play
        "com.sec.android.app.samsungapps",   // Samsung Galaxy Store
        "com.amazon.venezia",               // Amazon Appstore
        "org.fdroid.fdroid",                // F-Droid Official
        "org.fdroid.fdroid.privileged",
        "com.xiaomi.mipicks",               // Xiaomi GetApps
        "com.huawei.appmarket",             // Huawei AppGallery
        "com.heytap.market",                // Oppo App Market
        "com.vivo.appstore"                 // Vivo App Store
    )

    private val SUSPICIOUS_UPDATE_KEYWORDS = listOf(
        "system update", "software update", "android update",
        "firmware update", "security patch", "google update",
        "chrome update", "play update", "samsung update",
        "device update", "play protect update", "oneui update"
    )

    fun audit(
        context: Context,
        isCancelled: (() -> Boolean)? = null,
        onProgress: ((scanned: Int, total: Int, currentPkg: String) -> Unit)? = null
    ): AppAuditResult {
        val pm = context.packageManager
        val myPackage = context.packageName

        // Discover boot-completed receivers
        val bootPackages = queryBootReceivers(pm)

        val flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_META_DATA or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS

        val packages: List<PackageInfo> = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(flags)
            }
        } catch (_: Exception) {
            emptyList()
        }

        val allThreatApps = mutableListOf<AppThreatInfo>()
        val generalFindings = mutableListOf<Finding>()
        val totalCount = packages.size

        var index = 0
        for (pkg in packages) {
            if (isCancelled?.invoke() == true) break

            index++
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            // Report real-time scanning progress
            onProgress?.invoke(index, totalCount, pkg.packageName)

            // Skip ourselves and system packages for third-party posture audits
            if (isSystem || pkg.packageName == myPackage) continue

            val appLabel = try {
                appInfo.loadLabel(pm).toString()
            } catch (_: Exception) {
                pkg.packageName
            }

            val installer = getInstaller(pm, pkg.packageName)
            val isSideloaded = installer == null || installer !in TRUSTED_STORE_INSTALLERS
            val isDebuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val usesCleartextTraffic = (appInfo.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0
            val isBootCompleted = bootPackages.contains(pkg.packageName)

            val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
            val dangerousPerms = permissions.filter { isDangerousPermission(it) }

            // Count unprotected exported components, excluding the primary user launcher activity
            val launchActivityName = try {
                pm.getLaunchIntentForPackage(pkg.packageName)?.component?.className
            } catch (_: Exception) {
                null
            }
            val exportedCount = countUnprotectedExportedComponents(pkg, launchActivityName)

            val appRiskFindings = mutableListOf<Finding>()
            var riskScore = 0

            // 1. Sideload signal
            if (isSideloaded) {
                riskScore += 25
                appRiskFindings.add(
                    Finding(
                        title = "Sideloaded App",
                        description = "App was not installed from official store (installer: ${installer ?: "Manual/Direct Sideload"}).",
                        severity = Severity.WARNING,
                        recommendation = "Verify publisher legitimacy before granting sensitive permissions.",
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 2. Debuggable production release
            if (isDebuggable) {
                riskScore += 35
                appRiskFindings.add(
                    Finding(
                        title = "Debuggable Production App",
                        description = "Compiled with android:debuggable='true', permitting JDWP debugger attachment and memory extraction.",
                        severity = Severity.CRITICAL,
                        recommendation = "Uninstall or replace with hardened release build.",
                        actionType = ActionType.UNINSTALL_APP,
                        actionPayload = pkg.packageName,
                        actionLabel = "Uninstall",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 3. Update-impersonation heuristics
            val lowerLabel = appLabel.lowercase()
            for (kw in SUSPICIOUS_UPDATE_KEYWORDS) {
                if (lowerLabel.contains(kw) &&
                    !pkg.packageName.startsWith("com.google.") &&
                    !pkg.packageName.startsWith("com.sec.") &&
                    !pkg.packageName.startsWith("com.samsung.")
                ) {
                    riskScore += 45
                    appRiskFindings.add(
                        Finding(
                            title = "Update Impersonation Vector",
                            description = "App label '$appLabel' mimics a system update service ($kw).",
                            severity = Severity.CRITICAL,
                            recommendation = "High likelihood of social engineering malware. Uninstall immediately.",
                            actionType = ActionType.UNINSTALL_APP,
                            actionPayload = pkg.packageName,
                            actionLabel = "Uninstall",
                            category = FindingCategory.APPS
                        )
                    )
                    break
                }
            }

            // 4. Cleartext Traffic Allowed
            if (usesCleartextTraffic) {
                riskScore += 15
                appRiskFindings.add(
                    Finding(
                        title = "Cleartext HTTP Traffic Permitted",
                        description = "App permits unencrypted HTTP network communication susceptible to MITM sniffing.",
                        severity = Severity.WARNING,
                        recommendation = "Enforce HTTPS TLS-only network security config.",
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 5. Unprotected Exported IPC Components (excluding legitimate launcher activity)
            if (exportedCount > 0) {
                riskScore += (exportedCount * 5).coerceAtMost(20)
                appRiskFindings.add(
                    Finding(
                        title = "$exportedCount Unprotected Exported Component(s)",
                        description = "App exposes $exportedCount non-launcher activities, services, receivers, or providers without required permissions.",
                        severity = Severity.WARNING,
                        recommendation = "Third-party malware on the device can invoke these components directly.",
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 6. Permission Clustering: Overlay / Tapjacking
            val hasOverlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
            if (hasOverlay) {
                riskScore += 20
                appRiskFindings.add(
                    Finding(
                        title = "Screen Overlay Capability",
                        description = "Can draw over other applications (Tapjacking & credential spoofing risk).",
                        severity = Severity.WARNING,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Manage Permissions",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 7. Permission Clustering: Accessibility Abuse
            val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
            if (hasAccessibility) {
                riskScore += 30
                appRiskFindings.add(
                    Finding(
                        title = "Accessibility Service Hook",
                        description = "Declares accessibility binding capable of reading keystrokes and screen content.",
                        severity = Severity.CRITICAL,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Review Hook",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 8. Malware Profile: Device Takeover Trojan (Overlay + Accessibility)
            if (hasOverlay && hasAccessibility) {
                riskScore += 40
                appRiskFindings.add(
                    Finding(
                        title = "Device Takeover Trojan Cluster",
                        description = "App combines Screen Overlay and Accessibility Hook (profile of banking trojans such as SharkBot/TeaBot).",
                        severity = Severity.CRITICAL,
                        recommendation = "Extremely high threat level. Review or uninstall immediately.",
                        actionType = ActionType.UNINSTALL_APP,
                        actionPayload = pkg.packageName,
                        actionLabel = "Uninstall",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 9. Permission Clustering: OTP / SMS + Internet
            val hasSms = permissions.any { it.contains("SMS") }
            val hasInternet = permissions.contains("android.permission.INTERNET")
            if (hasSms && hasInternet) {
                riskScore += 30
                appRiskFindings.add(
                    Finding(
                        title = "SMS Interception & Internet Access",
                        description = "App holds both SMS read/receive permissions and outbound internet access (OTP stealer profile).",
                        severity = Severity.CRITICAL,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 10. Permission Clustering: Audio/Camera + Internet
            val hasAudio = permissions.contains("android.permission.RECORD_AUDIO")
            val hasCamera = permissions.contains("android.permission.CAMERA")
            if (hasAudio && hasInternet && isSideloaded) {
                riskScore += 25
                appRiskFindings.add(
                    Finding(
                        title = "Audio Surveillance Vector",
                        description = "Sideloaded app holds microphone recording and internet transmission permissions.",
                        severity = Severity.WARNING,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }
            if (hasCamera && hasInternet && isSideloaded) {
                riskScore += 25
                appRiskFindings.add(
                    Finding(
                        title = "Camera Surveillance Vector",
                        description = "Sideloaded app holds camera capture and internet transmission permissions.",
                        severity = Severity.WARNING,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 11. Stalkerware Profile: Background Location + Fine Location + Internet
            val hasFineLocation = permissions.contains("android.permission.ACCESS_FINE_LOCATION")
            val hasBackgroundLocation = permissions.contains("android.permission.ACCESS_BACKGROUND_LOCATION")
            if (hasFineLocation && hasBackgroundLocation && hasInternet && isSideloaded) {
                riskScore += 30
                appRiskFindings.add(
                    Finding(
                        title = "Stalkerware / Tracking Vector",
                        description = "Sideloaded app tracks precise user location continuously in background with outbound network access.",
                        severity = Severity.WARNING,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Manage Location",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 12. Contact & Call Harvester Profile: Contacts + Call Log + Internet
            val hasContacts = permissions.any { it.contains("CONTACTS") }
            val hasCallLog = permissions.any { it.contains("CALL_LOG") }
            if (hasContacts && hasCallLog && hasInternet) {
                riskScore += 25
                appRiskFindings.add(
                    Finding(
                        title = "Contacts & Call Harvester Profile",
                        description = "App holds both contact list and telephone call history permissions with outbound network transmission.",
                        severity = Severity.WARNING,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 13. Dropper: Request Install Packages
            if (permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
                riskScore += 20
                appRiskFindings.add(
                    Finding(
                        title = "Application Dropper / Package Installer",
                        description = "Holds permission to request installation of secondary APK packages.",
                        severity = Severity.WARNING,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            }

            // 14. Low Target SDK
            if (appInfo.targetSdkVersion < 31) {
                riskScore += 20
                appRiskFindings.add(
                    Finding(
                        title = "Obsolete Target SDK (${appInfo.targetSdkVersion})",
                        description = "Targets legacy Android runtime, evading modern runtime permissions and background start limits.",
                        severity = Severity.CRITICAL,
                        actionType = ActionType.OPEN_APP_SETTINGS,
                        actionPayload = pkg.packageName,
                        actionLabel = "Inspect App",
                        category = FindingCategory.APPS
                    )
                )
            } else if (appInfo.targetSdkVersion < 34) {
                riskScore += 10
                appRiskFindings.add(
                    Finding(
                        title = "Target SDK Below Android 14 (${appInfo.targetSdkVersion})",
                        description = "Targets older Android SDK below Android 14 security baseline.",
                        severity = Severity.INFO,
                        category = FindingCategory.APPS
                    )
                )
            }

            // 15. Boot Persistence
            if (isBootCompleted) {
                riskScore += 10
            }

            val appThreat = AppThreatInfo(
                appName = appLabel,
                packageName = pkg.packageName,
                versionName = pkg.versionName ?: "1.0",
                targetSdk = appInfo.targetSdkVersion,
                installerPackage = installer,
                isSideloaded = isSideloaded,
                isDebuggable = isDebuggable,
                isBootCompleted = isBootCompleted,
                usesCleartextTraffic = usesCleartextTraffic,
                exportedComponentsCount = exportedCount,
                dangerousPermissions = dangerousPerms,
                riskFindings = appRiskFindings,
                riskScore = riskScore
            )

            allThreatApps.add(appThreat)
        }

        val sideloaded = allThreatApps.filter { it.isSideloaded }
        val highRisk = allThreatApps.filter { it.riskScore >= 40 }
        val autorun = allThreatApps.filter { it.isBootCompleted }
        val cleartext = allThreatApps.filter { it.usesCleartextTraffic }

        if (highRisk.isNotEmpty()) {
            generalFindings.add(
                Finding(
                    title = "${highRisk.size} High-Risk Application(s) Identified",
                    description = "Detected apps with dangerous permission clusters, update impersonation, or debuggable binaries.",
                    severity = Severity.CRITICAL,
                    recommendation = "Review the Apps tab to revoke permissions or uninstall suspicious software.",
                    actionType = ActionType.OPEN_PLAY_PROTECT,
                    actionLabel = "Play Protect",
                    category = FindingCategory.APPS
                )
            )
        }

        if (sideloaded.isNotEmpty()) {
            generalFindings.add(
                Finding(
                    title = "${sideloaded.size} Sideloaded Application(s)",
                    description = "Applications installed from non-official sources bypass automated store scanning.",
                    severity = Severity.WARNING,
                    recommendation = "Keep Google Play Protect and Knox scanning active.",
                    category = FindingCategory.APPS
                )
            )
        }

        if (cleartext.isNotEmpty()) {
            generalFindings.add(
                Finding(
                    title = "${cleartext.size} App(s) Allow Cleartext HTTP",
                    description = "Identified applications permitting unencrypted HTTP traffic.",
                    severity = Severity.INFO,
                    category = FindingCategory.APPS
                )
            )
        }

        return AppAuditResult(
            totalAppsScanned = allThreatApps.size,
            sideloadedApps = sideloaded,
            highRiskApps = highRisk,
            autorunApps = autorun,
            cleartextApps = cleartext,
            allApps = allThreatApps,
            findings = generalFindings
        )
    }

    private fun getInstaller(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun queryBootReceivers(pm: PackageManager): Set<String> {
        val bootIntent = Intent(Intent.ACTION_BOOT_COMPLETED)
        val receivers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryBroadcastReceivers(bootIntent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.queryBroadcastReceivers(bootIntent, 0)
        }
        return receivers.mapNotNull { it.activityInfo?.packageName }.toSet()
    }

    internal fun countUnprotectedExportedComponents(pkg: PackageInfo, launchActivityName: String? = null): Int {
        var count = 0
        pkg.activities?.forEach {
            // Exclude the legitimate user launcher activity
            val isLauncher = launchActivityName != null && it.name == launchActivityName
            if (!isLauncher && it.exported && it.permission.isNullOrEmpty()) count++
        }
        pkg.services?.forEach {
            if (it.exported && it.permission.isNullOrEmpty()) count++
        }
        pkg.receivers?.forEach {
            if (it.exported && it.permission.isNullOrEmpty()) count++
        }
        pkg.providers?.forEach {
            if (it.exported && it.readPermission.isNullOrEmpty() && it.writePermission.isNullOrEmpty()) count++
        }
        return count
    }

    internal fun isDangerousPermission(perm: String): Boolean {
        return perm.contains("SMS") ||
                perm.contains("CONTACTS") ||
                perm.contains("CAMERA") ||
                perm.contains("RECORD_AUDIO") ||
                perm.contains("ACCESS_FINE_LOCATION") ||
                perm.contains("ACCESS_BACKGROUND_LOCATION") ||
                perm.contains("SYSTEM_ALERT_WINDOW") ||
                perm.contains("BIND_ACCESSIBILITY_SERVICE") ||
                perm.contains("REQUEST_INSTALL_PACKAGES") ||
                perm.contains("READ_CALL_LOG") ||
                perm.contains("QUERY_ALL_PACKAGES") ||
                perm.contains("READ_PHONE_STATE") ||
                perm.contains("READ_PHONE_NUMBERS") ||
                perm.contains("CALL_PHONE") ||
                perm.contains("READ_CALENDAR") ||
                perm.contains("WRITE_CALENDAR")
    }
}
