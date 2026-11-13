package com.fullstopsolution.droidsentinel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.fullstopsolution.droidsentinel.auditor.AppThreatAuditor
import com.fullstopsolution.droidsentinel.auditor.IntegrityAuditor
import com.fullstopsolution.droidsentinel.auditor.NetworkAuditor
import com.fullstopsolution.droidsentinel.auditor.StorageInspector
import com.fullstopsolution.droidsentinel.export.EvidenceExporter
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity
import com.fullstopsolution.droidsentinel.ui.screens.AppsTab
import com.fullstopsolution.droidsentinel.ui.screens.DashboardScreen
import com.fullstopsolution.droidsentinel.ui.screens.IntegrityTab
import com.fullstopsolution.droidsentinel.ui.screens.NetworkTab
import com.fullstopsolution.droidsentinel.ui.screens.StorageTab
import com.fullstopsolution.droidsentinel.ui.theme.CyanAccent
import com.fullstopsolution.droidsentinel.ui.theme.CyberBorder
import com.fullstopsolution.droidsentinel.ui.theme.CyberCardElevated
import com.fullstopsolution.droidsentinel.ui.theme.CyberObsidian
import com.fullstopsolution.droidsentinel.ui.theme.DroidSentinelTheme
import com.fullstopsolution.droidsentinel.ui.theme.TextMuted
import com.fullstopsolution.droidsentinel.ui.theme.TextPrimary
import com.fullstopsolution.droidsentinel.ui.theme.TextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    private var assessmentState by mutableStateOf<CompleteSecurityAssessment?>(null)
    private var isScanningState by mutableStateOf(false)

    private val requestNotificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Request notification permission on Android 13+ for real-time install alerts
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Run initial scan automatically on launch
        runSecurityAudit()

        setContent {
            DroidSentinelTheme {
                MainScreen(
                    assessment = assessmentState,
                    isScanning = isScanningState,
                    onRunScan = { runSecurityAudit() },
                    onExportEvidence = {
                        assessmentState?.let { EvidenceExporter.shareEvidence(this, it) }
                    },
                    onRequestStoragePermission = { requestStorageAccess() }
                )
            }
        }
    }

    private fun runSecurityAudit() {
        if (isScanningState) return
        isScanningState = true

        lifecycleScope.launch(Dispatchers.Default) {
            val integrity = IntegrityAuditor.audit(this@MainActivity)
            val appAudit = AppThreatAuditor.audit(this@MainActivity)
            val storageAudit = StorageInspector.audit(this@MainActivity)
            val networkAudit = NetworkAuditor.audit(this@MainActivity)

            val allFindings = mutableListOf<Finding>()
            allFindings.addAll(integrity.findings)
            allFindings.addAll(appAudit.findings)
            allFindings.addAll(storageAudit.findings)
            allFindings.addAll(networkAudit.findings)

            // Calculate overall score (0-100)
            var score = 100
            if (integrity.isRooted) score -= 40
            if (integrity.selinuxMode != "Enforcing") score -= 25
            if (integrity.isAdbEnabled) score -= 10
            if (integrity.isAdbWifiEnabled) score -= 20
            if (!integrity.isDeviceLocked) score -= 15

            score -= (appAudit.highRiskApps.size * 15).coerceAtMost(30)
            score -= (storageAudit.threatsFound.size * 20).coerceAtMost(40)
            if (!networkAudit.isVpnActive && !networkAudit.isPrivateDnsActive) score -= 10

            score = score.coerceIn(0, 100)

            val status = when {
                score >= 80 -> Severity.SECURE
                score >= 50 -> Severity.WARNING
                else -> Severity.CRITICAL
            }

            val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            val currentAssessment = CompleteSecurityAssessment(
                timestamp = System.currentTimeMillis(),
                timestampIso = isoFormat.format(Date()),
                deviceModel = Build.MODEL,
                deviceManufacturer = Build.MANUFACTURER.replaceFirstChar { it.uppercase() },
                androidVersion = Build.VERSION.RELEASE,
                securityPatch = Build.VERSION.SECURITY_PATCH ?: "Unknown",
                overallScore = score,
                overallStatus = status,
                integrity = integrity,
                appAudit = appAudit,
                storageAudit = storageAudit,
                networkAudit = networkAudit,
                allFindings = allFindings
            )

            withContext(Dispatchers.Main) {
                assessmentState = currentAssessment
                isScanningState = false
            }
        }
    }

    private fun requestStorageAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val intent = Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:$packageName")
                )
                startActivity(intent)
            } catch (_: Exception) {
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                startActivity(intent)
            }
        }
    }
}

@Composable
fun MainScreen(
    assessment: CompleteSecurityAssessment?,
    isScanning: Boolean,
    onRunScan: () -> Unit,
    onExportEvidence: () -> Unit,
    onRequestStoragePermission: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabTitles = listOf("Dashboard", "Integrity", "Apps", "Storage", "Network")

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = CyberObsidian,
        bottomBar = {
            NavigationBar(
                containerColor = CyberCardElevated,
                tonalElevation = 0.dp
            ) {
                tabTitles.forEachIndexed { index, title ->
                    val isSelected = selectedTab == index
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { selectedTab = index },
                        icon = {
                            Text(
                                text = title.take(3).uppercase(),
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                fontSize = 11.sp
                            )
                        },
                        label = {
                            Text(
                                text = title,
                                fontSize = 10.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = CyanAccent,
                            selectedTextColor = CyanAccent,
                            indicatorColor = CyberBorder,
                            unselectedIconColor = TextMuted,
                            unselectedTextColor = TextSecondary
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(CyberObsidian)
        ) {
            when (selectedTab) {
                0 -> DashboardScreen(
                    assessment = assessment,
                    isScanning = isScanning,
                    onRunScan = onRunScan,
                    onExportEvidence = onExportEvidence,
                    onNavigateTab = { selectedTab = it }
                )
                1 -> IntegrityTab(assessment = assessment)
                2 -> AppsTab(assessment = assessment)
                3 -> StorageTab(
                    assessment = assessment,
                    onRequestStoragePermission = onRequestStoragePermission
                )
                4 -> NetworkTab(assessment = assessment)
            }
        }
    }
}
