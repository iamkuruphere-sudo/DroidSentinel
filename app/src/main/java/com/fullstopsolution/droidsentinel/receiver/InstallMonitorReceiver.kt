package com.fullstopsolution.droidsentinel.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import com.fullstopsolution.droidsentinel.MainActivity

class InstallMonitorReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return

        val pkgUri = intent.data ?: return
        val packageName = pkgUri.schemeSpecificPart ?: return
        if (packageName == context.packageName) return

        val pm = context.packageManager
        val pkgInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }
        } catch (_: Exception) {
            return
        }

        val appInfo = pkgInfo.applicationInfo ?: return
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        if (isSystem) return

        val appLabel = appInfo.loadLabel(pm).toString()
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }

        val trustedStores = setOf(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.amazon.venezia",
            "org.fdroid.fdroid",
            "org.fdroid.fdroid.privileged",
            "com.xiaomi.mipicks",
            "com.huawei.appmarket"
        )
        val isSideloaded = installer == null || installer !in trustedStores
        val permissions = pkgInfo.requestedPermissions?.toSet() ?: emptySet()
        val hasOverlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasSms = permissions.any { it.contains("SMS") }

        if (isSideloaded || hasOverlay || hasAccessibility || hasSms) {
            showThreatNotification(context, appLabel, packageName, isSideloaded, hasOverlay || hasAccessibility)
        }
    }

    private fun showThreatNotification(
        context: Context,
        appLabel: String,
        packageName: String,
        isSideloaded: Boolean,
        hasCriticalPerms: Boolean
    ) {
        val channelId = "droidsentinel_security_alerts"
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        val channel = NotificationChannel(
            channelId,
            "DroidSentinel Security Alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Real-time alerts for sideloaded or high-risk app installations"
            enableVibration(true)
        }
        nm.createNotificationChannel(channel)

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val riskDesc = when {
            hasCriticalPerms && isSideloaded -> "Sideloaded app with privileged Accessibility/Overlay access."
            isSideloaded -> "App was installed from an unverified external source."
            else -> "App holds sensitive permissions."
        }

        val notification = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Security Alert: $appLabel")
            .setContentText(riskDesc)
            .setStyle(NotificationCompat.BigTextStyle().bigText("Newly installed app '$appLabel' ($packageName) flagged by DroidSentinel.\n\n$riskDesc"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        nm.notify(packageName.hashCode(), notification)
    }
}
