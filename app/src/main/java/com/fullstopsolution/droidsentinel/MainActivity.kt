package com.fullstopsolution.droidsentinel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.vector.ImageVector
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
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.ScanProgress
import com.fullstopsolution.droidsentinel.model.ScanStage
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
import com.fullstopsolution.droidsentinel.ui.theme.StatusCritical
import com.fullstopsolution.droidsentinel.ui.theme.TextMuted
import com.fullstopsolution.droidsentinel.ui.theme.TextPrimary
import com.fullstopsolution.droidsentinel.ui.theme.TextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {

    private var assessmentState by mutableStateOf<CompleteSecurityAssessment?>(null)
    private var scanProgressState by mutableStateOf(ScanProgress())
    private var scanJob: Job? = null
    private var isScanPaused by mutableStateOf(false)

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
                    scanProgress = scanProgressState,
                    onRunScan = { runSecurityAudit() },
                    onCancelScan = { cancelSecurityAudit() },
                    onPauseResumeScan = { togglePauseAudit() },
                    onExportJson = {
                        assessmentState?.let { EvidenceExporter.shareEvidence(this, it) }
                    },
                    onExportMarkdown = {
                        assessmentState?.let { EvidenceExporter.shareMarkdownReport(this, it) }
                    },
                    onCopySummary = {
                        assessmentState?.let { EvidenceExporter.copySummaryToClipboard(this, it) }
                    },
                    onExecuteAction = { finding -> handleAction(finding) },
                    onRequestStoragePermission = { requestStorageAccess() }
                )
            }
        }
    }

    private fun runSecurityAudit() {
        if (scanJob?.isActive == true) return

        isScanPaused = false
        scanJob = lifecycleScope.launch(Dispatchers.Default) {
            try {
                // Stage 1: Integrity Audit (0% - 25%)
                updateProgress(ScanStage.INTEGRITY_AUDIT, 5, "Auditing Kernel, SELinux & Hardware Keystore...")
                checkPause()
                val integrity = IntegrityAuditor.audit(this@MainActivity)
                updateProgress(ScanStage.INTEGRITY_AUDIT, 25, "OS & Keystore baseline verified")
                checkPause()

                // Stage 2: Application Audit (25% - 65%)
                updateProgress(ScanStage.APPLICATION_AUDIT, 30, "Discovering installed applications...")
                checkPause()
                val appAudit = AppThreatAuditor.audit(this@MainActivity) { scanned, total, pkgName ->
                    if (total > 0) {
                        val pct = 30 + ((scanned.toFloat() / total.toFloat()) * 35).toInt()
                        updateProgress(
                            ScanStage.APPLICATION_AUDIT,
                            pct,
                            "Auditing packages ($scanned/$total): ${pkgName.takeLast(28)}"
                        )
                    }
                }
                checkPause()

                // Stage 3: Storage & Macro Inspection (65% - 85%)
                updateProgress(ScanStage.STORAGE_INSPECTION, 68, "Inspecting storage directory /Download...")
                checkPause()
                val storageAudit = StorageInspector.audit(this@MainActivity) { scanned, total, fileName ->
                    if (total > 0) {
                        val pct = 68 + ((scanned.toFloat() / total.toFloat()) * 17).toInt()
                        updateProgress(
                            ScanStage.STORAGE_INSPECTION,
                            pct,
                            "Inspecting file ($scanned/$total): ${fileName.take(24)}"
                        )
                    }
                }
                checkPause()

                // Stage 4: Network Posture Audit (85% - 95%)
                updateProgress(ScanStage.NETWORK_AUDIT, 88, "Evaluating VPN tunnel & Private DNS DoT...")
                checkPause()
                val networkAudit = NetworkAuditor.audit(this@MainActivity)
                updateProgress(ScanStage.NETWORK_AUDIT, 95, "Network interfaces evaluated")
                checkPause()

                // Stage 5: Finalizing Score & Evidence (95% - 100%)
                updateProgress(ScanStage.FINALIZING, 98, "Synthesizing posture assessment...")

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
                if (!integrity.hasHardwareKeystore) score -= 10

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
                    scanProgressState = ScanProgress(
                        isScanning = false,
                        isPaused = false,
                        stage = ScanStage.COMPLETED,
                        stageProgress = 1.0f,
                        percentage = 100,
                        detailText = "Audit completed (${currentAssessment.allFindings.size} findings)"
                    )
                }
            } catch (e: Exception) {
                if (!isActive) {
                    withContext(Dispatchers.Main) {
                        scanProgressState = ScanProgress(
                            isScanning = false,
                            isPaused = false,
                            stage = ScanStage.CANCELLED,
                            detailText = "Audit cancelled by user"
                        )
                    }
                }
            }
        }
    }

    private suspend fun checkPause() {
        while (isScanPaused) {
            delay(200)
        }
    }

    private fun cancelSecurityAudit() {
        scanJob?.cancel()
        scanJob = null
        scanProgressState = ScanProgress(
            isScanning = false,
            isPaused = false,
            stage = ScanStage.CANCELLED,
            detailText = "Audit cancelled"
        )
    }

    private fun togglePauseAudit() {
        isScanPaused = !isScanPaused
        scanProgressState = scanProgressState.copy(isPaused = isScanPaused)
    }

    private fun updateProgress(stage: ScanStage, percentage: Int, message: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            scanProgressState = ScanProgress(
                isScanning = true,
                isPaused = isScanPaused,
                stage = stage,
                percentage = percentage,
                detailText = message
            )
        }
    }

    private fun handleAction(finding: Finding) {
        try {
            when (finding.actionType) {
                ActionType.OPEN_DEVELOPER_OPTIONS -> {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
                }
                ActionType.OPEN_SECURITY_SETTINGS -> {
                    startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                }
                ActionType.OPEN_BIOMETRIC_ENROLL -> {
                    try {
                        startActivity(Intent(Settings.ACTION_BIOMETRIC_ENROLL))
                    } catch (_: Exception) {
                        startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                    }
                }
                ActionType.OPEN_WIRELESS_SETTINGS, ActionType.OPEN_PRIVATE_DNS_SETTINGS -> {
                    startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
                }
                ActionType.OPEN_APP_SETTINGS -> {
                    val pkg = finding.actionPayload ?: return
                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.parse("package:$pkg")
                    }
                    startActivity(intent)
                }
                ActionType.UNINSTALL_APP -> {
                    val pkg = finding.actionPayload ?: return
                    val intent = Intent(Intent.ACTION_DELETE).apply {
                        data = Uri.parse("package:$pkg")
                    }
                    startActivity(intent)
                }
                ActionType.MANAGE_STORAGE -> {
                    requestStorageAccess()
                }
                ActionType.OPEN_PLAY_PROTECT -> {
                    try {
                        val intent = Intent("com.google.android.gms.security.settings.PlayProtectSettings")
                        startActivity(intent)
                    } catch (_: Exception) {
                        startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                    }
                }
                ActionType.NONE -> {
                    Toast.makeText(this, finding.recommendation.ifEmpty { finding.title }, Toast.LENGTH_SHORT).show()
                }
            }
        } catch (_: Exception) {
            Toast.makeText(this, "Unable to launch system setting directly.", Toast.LENGTH_SHORT).show()
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

data class NavItem(
    val title: String,
    val icon: ImageVector,
    val badgeCount: Int = 0
)

@Composable
fun MainScreen(
    assessment: CompleteSecurityAssessment?,
    scanProgress: ScanProgress,
    onRunScan: () -> Unit,
    onCancelScan: () -> Unit,
    onPauseResumeScan: () -> Unit,
    onExportJson: () -> Unit,
    onExportMarkdown: () -> Unit,
    onCopySummary: () -> Unit,
    onExecuteAction: (Finding) -> Unit,
    onRequestStoragePermission: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }

    val navItems = listOf(
        NavItem("Dashboard", Icons.Default.Shield),
        NavItem("Integrity", Icons.Default.Security, if (assessment?.integrity?.isRooted == true) 1 else 0),
        NavItem("Apps", Icons.Default.Apps, assessment?.appAudit?.highRiskApps?.size ?: 0),
        NavItem("Storage", Icons.Default.Folder, assessment?.storageAudit?.threatsFound?.size ?: 0),
        NavItem("Network", Icons.Default.Wifi)
    )

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = CyberObsidian,
        bottomBar = {
            NavigationBar(
                containerColor = CyberCardElevated,
                tonalElevation = 0.dp
            ) {
                navItems.forEachIndexed { index, item ->
                    val isSelected = selectedTab == index
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { selectedTab = index },
                        icon = {
                            if (item.badgeCount > 0) {
                                BadgedBox(
                                    badge = {
                                        Badge(
                                            containerColor = StatusCritical,
                                            contentColor = TextPrimary
                                        ) {
                                            Text(
                                                text = "${item.badgeCount}",
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                    }
                                ) {
                                    Icon(
                                        imageVector = item.icon,
                                        contentDescription = item.title,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                            } else {
                                Icon(
                                    imageVector = item.icon,
                                    contentDescription = item.title,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        },
                        label = {
                            Text(
                                text = item.title,
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
                    scanProgress = scanProgress,
                    onRunScan = onRunScan,
                    onCancelScan = onCancelScan,
                    onPauseResumeScan = onPauseResumeScan,
                    onExportEvidenceJson = onExportJson,
                    onExportEvidenceMarkdown = onExportMarkdown,
                    onCopySummary = onCopySummary,
                    onExecuteAction = onExecuteAction,
                    onNavigateTab = { selectedTab = it }
                )
                1 -> IntegrityTab(
                    assessment = assessment,
                    onExecuteAction = onExecuteAction
                )
                2 -> AppsTab(
                    assessment = assessment,
                    onExecuteAction = onExecuteAction
                )
                3 -> StorageTab(
                    assessment = assessment,
                    onRequestStoragePermission = onRequestStoragePermission
                )
                4 -> NetworkTab(
                    assessment = assessment,
                    onExecuteAction = onExecuteAction
                )
            }
        }
    }
}
