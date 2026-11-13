package com.fullstopsolution.droidsentinel.auditor

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.fullstopsolution.droidsentinel.model.AppAuditResult
import com.fullstopsolution.droidsentinel.model.AppThreatInfo
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity

object AppThreatAuditor {

    private val TRUSTED_STORE_INSTALLERS = setOf(
        "com.android.vending",               // Google Play
        "com.sec.android.app.samsungapps",   // Samsung Galaxy Store
        "com.amazon.venezia",               // Amazon Appstore
        "org.fdroid.fdroid",                // F-Droid Official
        "org.fdroid.fdroid.privileged"
    )

    private val SUSPICIOUS_UPDATE_KEYWORDS = listOf(
        "system update", "software update", "android update",
        "firmware update", "security patch", "google update",
        "chrome update", "play update", "samsung update"
    )

    fun audit(context: Context): AppAuditResult {
        val pm = context.packageManager
        val myPackage = context.packageName

        // Discover boot-completed receivers
        val bootPackages = queryBootReceivers(pm)

        // Query enabled accessibility services in system settings
        val enabledAccessibilityServices = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        } catch (_: Exception) {
            ""
        }

        // Include GET_SERVICES so declared service permissions are visible
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_META_DATA or PackageManager.GET_SERVICES
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }

        val allThreatApps = mutableListOf<AppThreatInfo>()
        val generalFindings = mutableListOf<Finding>()

        for (pkg in packages) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            // Skip ourselves and system packages for sideload audits
            if (isSystem || pkg.packageName == myPackage) continue

            val appLabel = appInfo.loadLabel(pm).toString()
            val installer = getInstaller(pm, pkg.packageName)
            val isSideloaded = installer == null || installer !in TRUSTED_STORE_INSTALLERS
            val isDebuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val isBootCompleted = bootPackages.contains(pkg.packageName)

            val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
            val dangerousPerms = permissions.filter { isDangerousPermission(it) }.toMutableList()

            val appRiskFindings = mutableListOf<Finding>()
            var riskScore = 0

            // 1. Sideload signal
            if (isSideloaded) {
                riskScore += 25
                appRiskFindings.add(
                    Finding(
                        title = "Sideloaded App",
                        description = "App was not installed from Google Play or Galaxy Store (installer: ${installer ?: "Manual/Direct"}).",
                        severity = Severity.WARNING,
                        recommendation = "Verify publisher legitimacy before granting sensitive permissions."
                    )
                )
            }

            // 2. Debuggable release
            if (isDebuggable) {
                riskScore += 35
                appRiskFindings.add(
                    Finding(
                        title = "Debuggable Production App",
                        description = "App was compiled with android:debuggable='true', allowing JDWP debugger attachment and memory dumping.",
                        severity = Severity.CRITICAL,
                        recommendation = "Uninstall or replace with a hardened release build."
                    )
                )
            }

            // 3. Update-impersonation
            val lowerLabel = appLabel.lowercase()
            for (kw in SUSPICIOUS_UPDATE_KEYWORDS) {
                if (lowerLabel.contains(kw) && !pkg.packageName.startsWith("com.google.") && !pkg.packageName.startsWith("com.sec.")) {
                    riskScore += 45
                    appRiskFindings.add(
                        Finding(
                            title = "Update Impersonation Vector",
                            description = "App label '$appLabel' mimics a system update service.",
                            severity = Severity.CRITICAL,
                            recommendation = "High likelihood of social engineering malware. Review carefully."
                        )
                    )
                    break
                }
            }

            // 4. Permission Clustering: Overlay / Tapjacking
            if (permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
                riskScore += 20
                appRiskFindings.add(
                    Finding(
                        title = "Screen Overlay Capability",
                        description = "Can draw over other applications (Tapjacking / credential phishing risk).",
                        severity = Severity.WARNING
                    )
                )
            }

            // 5. Accessibility Service Hook: check declared <service android:permission>, requested permission, AND enabled system status
            val declaresAccessibilityService = pkg.services?.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" } == true
            val requestsAccessibilityPerm = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
            val isAccessibilityActive = enabledAccessibilityServices.contains(pkg.packageName)

            if (isAccessibilityActive) {
                riskScore += 45
                dangerousPerms.add("android.permission.BIND_ACCESSIBILITY_SERVICE (ACTIVE)")
                appRiskFindings.add(
                    Finding(
                        title = "Active Accessibility Service",
                        description = "This application has an active, enabled Accessibility Service in Android system settings, granting real-time screen inspection, key event logging, and automated touch actions.",
                        severity = Severity.CRITICAL,
                        recommendation = "Disable this accessibility service in Settings unless strictly necessary."
                    )
                )
            } else if (declaresAccessibilityService || requestsAccessibilityPerm) {
                riskScore += 30
                dangerousPerms.add("android.permission.BIND_ACCESSIBILITY_SERVICE (DECLARED)")
                appRiskFindings.add(
                    Finding(
                        title = "Accessibility Service Hook Declared",
                        description = "Declares an accessibility service (<service android:permission='android.permission.BIND_ACCESSIBILITY_SERVICE'>) capable of intercepting UI contents if activated by the user.",
                        severity = Severity.CRITICAL,
                        recommendation = "Ensure this app is not granted Accessibility permissions in Settings."
                    )
                )
            }

            // 6. Permission Clustering: OTP / SMS + Internet
            val hasSms = permissions.any { it.contains("SMS") }
            val hasInternet = permissions.contains("android.permission.INTERNET")
            if (hasSms && hasInternet) {
                riskScore += 30
                appRiskFindings.add(
                    Finding(
                        title = "SMS Interception & Internet Access",
                        description = "App holds both SMS read/receive permissions and outbound internet access (OTP stealer profile).",
                        severity = Severity.WARNING
                    )
                )
            }

            // 7. Dropper: Request Install Packages
            if (permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
                riskScore += 20
                appRiskFindings.add(
                    Finding(
                        title = "Application Dropper / Package Installer",
                        description = "App holds permission to request installation of secondary APK packages.",
                        severity = Severity.WARNING
                    )
                )
            }

            // 8. Low Target SDK
            if (appInfo.targetSdkVersion < 31) {
                riskScore += 15
                appRiskFindings.add(
                    Finding(
                        title = "Outdated Target SDK (${appInfo.targetSdkVersion})",
                        description = "Targets legacy Android runtime, bypassing modern permission restrictions.",
                        severity = Severity.WARNING
                    )
                )
            }

            // 9. Boot Persistence
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
                dangerousPermissions = dangerousPerms.distinct(),
                riskFindings = appRiskFindings,
                riskScore = riskScore
            )

            allThreatApps.add(appThreat)
        }

        val sideloaded = allThreatApps.filter { it.isSideloaded }
        val highRisk = allThreatApps.filter { it.riskScore >= 40 }
        val autorun = allThreatApps.filter { it.isBootCompleted }

        if (highRisk.isNotEmpty()) {
            generalFindings.add(
                Finding(
                    title = "${highRisk.size} High-Risk Application(s) Identified",
                    description = "Detected apps with dangerous permission clusters or impersonation heuristics.",
                    severity = Severity.CRITICAL,
                    recommendation = "Inspect the Apps tab and revoke unneeded permissions or remove untrusted software."
                )
            )
        }

        if (sideloaded.isNotEmpty()) {
            generalFindings.add(
                Finding(
                    title = "${sideloaded.size} Sideloaded Application(s)",
                    description = "Applications installed from non-official sources bypass automated store scanning.",
                    severity = Severity.INFO,
                    recommendation = "Keep Google Play Protect and Knox scanning active."
                )
            )
        }

        return AppAuditResult(
            totalAppsScanned = allThreatApps.size,
            sideloadedApps = sideloaded,
            highRiskApps = highRisk,
            autorunApps = autorun,
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

    private fun isDangerousPermission(perm: String): Boolean {
        return perm.contains("SMS") ||
                perm.contains("CONTACTS") ||
                perm.contains("CAMERA") ||
                perm.contains("RECORD_AUDIO") ||
                perm.contains("ACCESS_FINE_LOCATION") ||
                perm.contains("ACCESS_BACKGROUND_LOCATION") ||
                perm.contains("SYSTEM_ALERT_WINDOW") ||
                perm.contains("BIND_ACCESSIBILITY_SERVICE") ||
                perm.contains("REQUEST_INSTALL_PACKAGES")
    }
}
