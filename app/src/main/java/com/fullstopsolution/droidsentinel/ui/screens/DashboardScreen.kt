package com.fullstopsolution.droidsentinel.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.ScanProgress
import com.fullstopsolution.droidsentinel.model.Severity
import com.fullstopsolution.droidsentinel.ui.theme.CyanAccent
import com.fullstopsolution.droidsentinel.ui.theme.CyberBorder
import com.fullstopsolution.droidsentinel.ui.theme.CyberCard
import com.fullstopsolution.droidsentinel.ui.theme.CyberCardElevated
import com.fullstopsolution.droidsentinel.ui.theme.CyberGlowCyan
import com.fullstopsolution.droidsentinel.ui.theme.CyberObsidian
import com.fullstopsolution.droidsentinel.ui.theme.MintEmerald
import com.fullstopsolution.droidsentinel.ui.theme.StatusCritical
import com.fullstopsolution.droidsentinel.ui.theme.StatusInfo
import com.fullstopsolution.droidsentinel.ui.theme.StatusSecure
import com.fullstopsolution.droidsentinel.ui.theme.StatusWarning
import com.fullstopsolution.droidsentinel.ui.theme.TextMuted
import com.fullstopsolution.droidsentinel.ui.theme.TextPrimary
import com.fullstopsolution.droidsentinel.ui.theme.TextSecondary

@Composable
fun DashboardScreen(
    assessment: CompleteSecurityAssessment?,
    scanProgress: ScanProgress,
    onRunScan: () -> Unit,
    onCancelScan: () -> Unit,
    onPauseResumeScan: () -> Unit,
    onExportEvidenceJson: () -> Unit,
    onExportEvidenceMarkdown: () -> Unit,
    onCopySummary: () -> Unit,
    onExecuteAction: (Finding) -> Unit,
    onNavigateTab: (Int) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var severityFilter by remember { mutableStateOf("ALL") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // App Header
        item {
            Column {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(if (scanProgress.isScanning) CyanAccent else MintEmerald)
                    )
                    Text(
                        text = "DROIDSENTINEL",
                        color = CyanAccent,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 2.sp
                    )
                }
                Text(
                    text = "Endpoint Security Suite",
                    color = TextPrimary,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Zero-Cloud Client-Side Security Auditing • Fullstop Solution",
                    color = TextSecondary,
                    fontSize = 12.sp
                )
            }
        }

        // Real-Time Scan Progress & Cancel/Pause Panel (Visible while scanning)
        if (scanProgress.isScanning) {
            item {
                ScanProgressCard(
                    scanProgress = scanProgress,
                    onPauseResumeScan = onPauseResumeScan,
                    onCancelScan = onCancelScan
                )
            }
        }

        // Health Score & Primary Action Card
        item {
            SecurityScoreCard(
                assessment = assessment,
                scanProgress = scanProgress,
                onRunScan = onRunScan,
                onExportJson = onExportEvidenceJson,
                onExportMarkdown = onExportEvidenceMarkdown,
                onCopySummary = onCopySummary
            )
        }

        // Quick Category Posture Overview
        if (assessment != null) {
            item {
                Text(
                    text = "DEFENSE PILLARS",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 1.5.sp
                )
            }

            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        CategoryCard(
                            modifier = Modifier.weight(1f),
                            title = "OS Integrity",
                            statusText = if (assessment.integrity.isRooted) "COMPROMISED" else "ENFORCING",
                            statusColor = if (assessment.integrity.isRooted) StatusCritical else StatusSecure,
                            detail = if (assessment.integrity.isRooted) "Root binary detected" else "SELinux Enforcing • StrongBox: ${if (assessment.integrity.hasStrongBox) "Yes" else "TEE"}",
                            onClick = { onNavigateTab(1) }
                        )
                        CategoryCard(
                            modifier = Modifier.weight(1f),
                            title = "Apps & Sideloads",
                            statusText = "${assessment.appAudit.highRiskApps.size} High Risk",
                            statusColor = if (assessment.appAudit.highRiskApps.isNotEmpty()) StatusCritical else if (assessment.appAudit.sideloadedApps.isNotEmpty()) StatusWarning else StatusSecure,
                            detail = "${assessment.appAudit.sideloadedApps.size} sideloaded of ${assessment.appAudit.totalAppsScanned}",
                            onClick = { onNavigateTab(2) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        CategoryCard(
                            modifier = Modifier.weight(1f),
                            title = "Storage & Macros",
                            statusText = "${assessment.storageAudit.threatsFound.size} Threats",
                            statusColor = if (assessment.storageAudit.threatsFound.isNotEmpty()) StatusCritical else StatusSecure,
                            detail = "${assessment.storageAudit.filesScannedCount} files scanned in /Download",
                            onClick = { onNavigateTab(3) }
                        )
                        CategoryCard(
                            modifier = Modifier.weight(1f),
                            title = "Network Posture",
                            statusText = assessment.networkAudit.connectionType,
                            statusColor = if (assessment.networkAudit.isVpnActive) StatusSecure else StatusInfo,
                            detail = if (assessment.networkAudit.isPrivateDnsActive) "Private DNS DoT Active" else "No VPN / Plaintext DNS",
                            onClick = { onNavigateTab(4) }
                        )
                    }
                }
            }

            // Quick Remediation Action Center
            val actionableFindings = assessment.allFindings.filter { it.actionType != ActionType.NONE && (it.severity == Severity.CRITICAL || it.severity == Severity.WARNING) }
            if (actionableFindings.isNotEmpty()) {
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "QUICK REMEDIATION HUB",
                            color = CyanAccent,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = 1.5.sp
                        )

                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .border(1.dp, CyanAccent.copy(alpha = 0.4f), RoundedCornerShape(12.dp)),
                            color = CyberCardElevated
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Text(
                                    text = "Actionable Security Vulnerabilities (${actionableFindings.size})",
                                    color = TextPrimary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold
                                )

                                actionableFindings.take(3).forEach { finding ->
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                                            Text(
                                                text = finding.title,
                                                color = if (finding.severity == Severity.CRITICAL) StatusCritical else StatusWarning,
                                                fontSize = 12.sp,
                                                fontWeight = FontWeight.SemiBold
                                            )
                                            Text(
                                                text = finding.recommendation.ifEmpty { finding.description },
                                                color = TextSecondary,
                                                fontSize = 11.sp,
                                                maxLines = 1
                                            )
                                        }

                                        Button(
                                            onClick = { onExecuteAction(finding) },
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = CyanAccent,
                                                contentColor = CyberObsidian
                                            ),
                                            shape = RoundedCornerShape(6.dp),
                                            contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                                        ) {
                                            Text(
                                                text = finding.actionLabel ?: "Fix Now",
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Findings Search & Filter Header
            item {
                Spacer(modifier = Modifier.height(4.dp))
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "SECURITY FINDINGS (${assessment.allFindings.size})",
                        color = TextSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        fontFamily = FontFamily.Monospace,
                        letterSpacing = 1.5.sp
                    )

                    // Search Input
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Filter findings by keyword...", color = TextMuted, fontSize = 12.sp) },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = CyanAccent, modifier = Modifier.size(18.dp)) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyanAccent,
                            unfocusedBorderColor = CyberBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )

                    // Severity Filter Chips
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        FilterPill("ALL", severityFilter == "ALL") { severityFilter = "ALL" }
                        FilterPill("CRITICAL", severityFilter == "CRITICAL") { severityFilter = "CRITICAL" }
                        FilterPill("WARNING", severityFilter == "WARNING") { severityFilter = "WARNING" }
                        FilterPill("INFO", severityFilter == "INFO") { severityFilter = "INFO" }
                        FilterPill("SECURE", severityFilter == "SECURE") { severityFilter = "SECURE" }
                    }
                }
            }

            // Filtered Findings List
            val displayedFindings = assessment.allFindings.filter { finding ->
                val matchesSeverity = when (severityFilter) {
                    "CRITICAL" -> finding.severity == Severity.CRITICAL
                    "WARNING" -> finding.severity == Severity.WARNING
                    "INFO" -> finding.severity == Severity.INFO
                    "SECURE" -> finding.severity == Severity.SECURE
                    else -> true
                }
                val matchesQuery = searchQuery.isBlank() ||
                        finding.title.contains(searchQuery, ignoreCase = true) ||
                        finding.description.contains(searchQuery, ignoreCase = true) ||
                        finding.recommendation.contains(searchQuery, ignoreCase = true)

                matchesSeverity && matchesQuery
            }

            if (displayedFindings.isEmpty()) {
                item {
                    Text(
                        text = "No findings matching criteria.",
                        color = TextSecondary,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )
                }
            } else {
                items(displayedFindings) { finding ->
                    FindingItemCard(finding = finding, onExecuteAction = onExecuteAction)
                }
            }
        }
    }
}

@Composable
fun ScanProgressCard(
    scanProgress: ScanProgress,
    onPauseResumeScan: () -> Unit,
    onCancelScan: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .border(1.dp, CyanAccent, RoundedCornerShape(14.dp)),
        color = CyberCardElevated
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Default.Shield,
                        contentDescription = "Scanning",
                        tint = CyanAccent,
                        modifier = Modifier.size(18.dp)
                    )
                    Text(
                        text = if (scanProgress.isPaused) "AUDIT PAUSED" else "ACTIVE AUDIT IN PROGRESS",
                        color = if (scanProgress.isPaused) StatusWarning else CyanAccent,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Text(
                    text = "${scanProgress.percentage}%",
                    color = CyanAccent,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
            }

            LinearProgressIndicator(
                progress = { scanProgress.percentage / 100f },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp)),
                color = CyanAccent,
                trackColor = CyberBorder
            )

            Text(
                text = scanProgress.detailText,
                color = TextSecondary,
                fontSize = 12.sp,
                maxLines = 2
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onPauseResumeScan,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = if (scanProgress.isPaused) StatusSecure else StatusWarning)
                ) {
                    Icon(
                        imageVector = if (scanProgress.isPaused) Icons.Default.PlayArrow else Icons.Default.Pause,
                        contentDescription = "Pause/Resume",
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (scanProgress.isPaused) "Resume" else "Pause",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                OutlinedButton(
                    onClick = onCancelScan,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusCritical)
                ) {
                    Icon(
                        imageVector = Icons.Default.Cancel,
                        contentDescription = "Cancel",
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Cancel",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun SecurityScoreCard(
    assessment: CompleteSecurityAssessment?,
    scanProgress: ScanProgress,
    onRunScan: () -> Unit,
    onExportJson: () -> Unit,
    onExportMarkdown: () -> Unit,
    onCopySummary: () -> Unit
) {
    val score = assessment?.overallScore ?: 0
    val scoreColor = when {
        assessment == null -> TextMuted
        score >= 80 -> StatusSecure
        score >= 50 -> StatusWarning
        else -> StatusCritical
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .border(1.dp, CyberBorder, RoundedCornerShape(16.dp)),
        color = CyberCard
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                    Text(
                        text = if (assessment == null) "SECURITY AUDIT PENDING" else "SYSTEM POSTURE: ${assessment.overallStatus}",
                        color = scoreColor,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = if (assessment == null) "Initiate on-device baseline security audit" else "${assessment.deviceManufacturer} ${assessment.deviceModel}",
                        color = TextPrimary,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    if (assessment != null) {
                        Text(
                            text = "Android ${assessment.androidVersion} • Patch: ${assessment.securityPatch}",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                }

                // Interactive Animated Security Gauge
                AnimatedSecurityGauge(
                    score = score,
                    isScanning = scanProgress.isScanning,
                    statusColor = scoreColor,
                    modifier = Modifier.size(92.dp)
                )
            }

            // Primary Scan Button
            Button(
                onClick = onRunScan,
                enabled = !scanProgress.isScanning,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = CyanAccent,
                    contentColor = CyberObsidian
                )
            ) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Scan",
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (scanProgress.isScanning) "Auditing System Components..." else "Run Complete Security Audit",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }

            // Evidence Action Bar
            if (assessment != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onExportJson,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MintEmerald)
                    ) {
                        Icon(Icons.Default.Share, contentDescription = "JSON", modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(text = "JSON", fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                    }

                    OutlinedButton(
                        onClick = onExportMarkdown,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanAccent)
                    ) {
                        Icon(Icons.Default.Description, contentDescription = "Markdown", modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(text = "Report", fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                    }

                    OutlinedButton(
                        onClick = onCopySummary,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(8.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(text = "Copy", fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                    }
                }
            }
        }
    }
}

@Composable
fun AnimatedSecurityGauge(
    score: Int,
    isScanning: Boolean,
    statusColor: Color,
    modifier: Modifier = Modifier
) {
    val animatedProgress by animateFloatAsState(
        targetValue = score / 100f,
        animationSpec = tween(durationMillis = 1200, easing = FastOutSlowInEasing),
        label = "gaugeSweep"
    )

    val animatedScore by animateIntAsState(
        targetValue = score,
        animationSpec = tween(durationMillis = 1200, easing = FastOutSlowInEasing),
        label = "gaugeScore"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 0.9f,
        animationSpec = infiniteRepeatable(
            animation = tween(800),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )

    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val strokeWidth = 8.dp.toPx()
            val diameter = size.minDimension - strokeWidth
            val topLeft = Offset(strokeWidth / 2, strokeWidth / 2)
            val arcSize = Size(diameter, diameter)

            // Background Track Arc (260 degrees, start at 140)
            drawArc(
                color = CyberBorder,
                startAngle = 140f,
                sweepAngle = 260f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
            )

            // Animated Foreground Arc with gradient
            val gradientColors = if (score >= 80) {
                listOf(StatusSecure, CyanAccent)
            } else if (score >= 50) {
                listOf(StatusWarning, CyanAccent)
            } else {
                listOf(StatusCritical, StatusWarning)
            }

            if (animatedProgress > 0.005f) {
                drawArc(
                    brush = Brush.sweepGradient(
                        colors = gradientColors,
                        center = Offset(size.width / 2, size.height / 2)
                    ),
                    startAngle = 140f,
                    sweepAngle = 260f * animatedProgress,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                )
            }
        }

        // Center Content
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = if (isScanning) "--" else "$animatedScore",
                color = if (isScanning) CyanAccent.copy(alpha = pulseAlpha) else statusColor,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = "/100",
                color = TextSecondary,
                fontSize = 10.sp
            )
        }
    }
}

@Composable
fun FindingItemCard(
    finding: Finding,
    onExecuteAction: (Finding) -> Unit = {}
) {
    val (badgeBg, badgeColor) = when (finding.severity) {
        Severity.CRITICAL -> Color(0x33EF4444) to StatusCritical
        Severity.WARNING -> Color(0x33F59E0B) to StatusWarning
        Severity.INFO -> Color(0x3338BDF8) to StatusInfo
        Severity.SECURE -> Color(0x3310B981) to StatusSecure
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, CyberBorder, RoundedCornerShape(12.dp)),
        color = CyberCard
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = finding.title,
                    color = TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f)
                )
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(badgeBg)
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = finding.severity.name,
                        color = badgeColor,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Text(
                text = finding.description,
                color = TextSecondary,
                fontSize = 12.sp,
                lineHeight = 16.sp
            )

            if (finding.recommendation.isNotEmpty()) {
                Text(
                    text = "Remediation: ${finding.recommendation}",
                    color = MintEmerald,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(CyberCardElevated)
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                )
            }

            // Action Button
            if (finding.actionType != ActionType.NONE && finding.actionLabel != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    Button(
                        onClick = { onExecuteAction(finding) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyanAccent,
                            contentColor = CyberObsidian
                        ),
                        shape = RoundedCornerShape(6.dp),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = finding.actionLabel,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun CategoryCard(
    modifier: Modifier = Modifier,
    title: String,
    statusText: String,
    statusColor: Color,
    detail: String,
    onClick: () -> Unit
) {
    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
            .clickable { onClick() },
        color = CyberCard
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = title,
                color = TextSecondary,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = statusText,
                color = statusColor,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = detail,
                color = TextMuted,
                fontSize = 11.sp,
                maxLines = 2
            )
        }
    }
}


