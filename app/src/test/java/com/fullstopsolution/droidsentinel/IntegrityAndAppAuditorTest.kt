package com.fullstopsolution.droidsentinel

import android.content.pm.ActivityInfo
import android.content.pm.PackageInfo
import android.content.pm.ProviderInfo
import android.content.pm.ServiceInfo
import com.fullstopsolution.droidsentinel.auditor.AppThreatAuditor
import com.fullstopsolution.droidsentinel.auditor.IntegrityAuditor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityAndAppAuditorTest {

    @Test
    fun testLauncherActivityExcludedFromUnprotectedExportedCount() {
        val pkg = PackageInfo().apply {
            packageName = "com.example.normalapp"
            activities = arrayOf(
                ActivityInfo().apply {
                    name = "com.example.normalapp.MainActivity"
                    exported = true
                    permission = null
                }
            )
        }

        // When launcher activity name is provided, it must not be counted as an unprotected component
        val countWithLauncher = AppThreatAuditor.countUnprotectedExportedComponents(
            pkg = pkg,
            launchActivityName = "com.example.normalapp.MainActivity"
        )
        assertEquals("Launcher activity must not be counted as unprotected component", 0, countWithLauncher)

        // But an exported secondary activity with no permission MUST be counted
        val pkgWithLeakedActivity = PackageInfo().apply {
            packageName = "com.example.normalapp"
            activities = arrayOf(
                ActivityInfo().apply {
                    name = "com.example.normalapp.MainActivity"
                    exported = true
                    permission = null
                },
                ActivityInfo().apply {
                    name = "com.example.normalapp.InternalDebugActivity"
                    exported = true
                    permission = null
                }
            )
        }
        val countWithLeaked = AppThreatAuditor.countUnprotectedExportedComponents(
            pkg = pkgWithLeakedActivity,
            launchActivityName = "com.example.normalapp.MainActivity"
        )
        assertEquals("Unprotected non-launcher activity must be counted", 1, countWithLeaked)
    }

    @Test
    fun testUnprotectedServicesAndProvidersCounted() {
        val pkg = PackageInfo().apply {
            packageName = "com.example.vulnapp"
            services = arrayOf(
                ServiceInfo().apply {
                    name = "com.example.vulnapp.VulnerableService"
                    exported = true
                    permission = null
                }
            )
            providers = arrayOf(
                ProviderInfo().apply {
                    name = "com.example.vulnapp.LeakedProvider"
                    exported = true
                    readPermission = null
                    writePermission = null
                }
            )
        }

        val count = AppThreatAuditor.countUnprotectedExportedComponents(pkg, null)
        assertEquals("Exported service and provider without permissions must be counted", 2, count)
    }

    @Test
    fun testDangerousPermissionsIdentified() {
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.RECORD_AUDIO"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.CAMERA"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.ACCESS_FINE_LOCATION"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.ACCESS_BACKGROUND_LOCATION"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.SYSTEM_ALERT_WINDOW"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.BIND_ACCESSIBILITY_SERVICE"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.SEND_SMS"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.READ_PHONE_STATE"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.READ_CONTACTS"))
        assertTrue(AppThreatAuditor.isDangerousPermission("android.permission.READ_CALL_LOG"))

        assertFalse(AppThreatAuditor.isDangerousPermission("android.permission.INTERNET"))
        assertFalse(AppThreatAuditor.isDangerousPermission("android.permission.VIBRATE"))
    }

    @Test
    fun testTrustedStoreInstallersCoverage() {
        val stores = AppThreatAuditor.TRUSTED_STORE_INSTALLERS
        assertTrue(stores.contains("com.android.vending"))
        assertTrue(stores.contains("com.sec.android.app.samsungapps"))
        assertTrue(stores.contains("com.amazon.venezia"))
        assertTrue(stores.contains("org.fdroid.fdroid"))
        assertTrue(stores.contains("com.xiaomi.mipicks"))
        assertTrue(stores.contains("com.huawei.appmarket"))
        assertTrue(stores.contains("com.heytap.market"))
        assertTrue(stores.contains("com.vivo.appstore"))
    }

    @Test
    fun testKnownSuPathsCoverage() {
        val paths = IntegrityAuditor.KNOWN_SU_PATHS
        assertTrue(paths.contains("/system/bin/su"))
        assertTrue(paths.contains("/data/adb/ksu"))
        assertTrue(paths.contains("/data/adb/ksud"))
        assertTrue(paths.contains("/data/adb/ap"))
        assertTrue(paths.contains("/data/adb/magisk"))
        assertTrue(paths.contains("/system/bin/busybox"))
    }

    @Test
    fun testRootPackagesCoverage() {
        val packages = IntegrityAuditor.ROOT_PACKAGES
        assertTrue(packages.contains("com.topjohnwu.magisk"))
        assertTrue(packages.contains("me.weishu.kernelsu"))
        assertTrue(packages.contains("me.bmax.apatch"))
        assertTrue(packages.contains("org.lsposed.manager"))
        assertTrue(packages.contains("de.robv.android.xposed.installer"))
        assertTrue(packages.contains("com.amphoras.hidemyroot"))
    }
}
