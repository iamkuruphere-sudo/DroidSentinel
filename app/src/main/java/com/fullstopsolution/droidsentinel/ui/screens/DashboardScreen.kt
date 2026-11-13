package com.fullstopsolution.droidsentinel.ui.screens

import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.Severity
import com.fullstopsolution.droidsentinel.ui.theme.CyanAccent
import com.fullstopsolution.droidsentinel.ui.theme.CyberBorder
import com.fullstopsolution.droidsentinel.ui.theme.CyberCard
import com.fullstopsolution.droidsentinel.ui.theme.CyberCardElevated
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
    isScanning: Boolean,
    onRunScan: () -> Unit,
    onExportEvidence: () -> Unit,
    onNavigateTab: (Int) -> Unit
) {
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
                            .size(14.dp)
                            .clip(CircleShape)
                            .background(if (isScanning) CyanAccent else MintEmerald)
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

        // Health Score & Primary Action Card
        item {
            SecurityScoreCard(
                assessment = assessment,
                isScanning = isScanning,
                onRunScan = onRunScan,
                onExportEvidence = onExportEvidence
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
                            detail = if (assessment.integrity.isRooted) "Root binary detected" else "SELinux Enforcing, Stock Keys",
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

            // Findings List
            item {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "SECURITY FINDINGS (${assessment.allFindings.size})",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 1.5.sp
                )
            }

            items(assessment.allFindings) { finding ->
                FindingItemCard(finding = finding)
            }
        }
    }
}

@Composable
fun SecurityScoreCard(
    assessment: CompleteSecurityAssessment?,
    isScanning: Boolean,
    onRunScan: () -> Unit,
    onExportEvidence: () -> Unit
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
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (assessment == null) "SECURITY AUDIT PENDING" else "SYSTEM POSTURE: ${assessment.overallStatus}",
                        color = scoreColor,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = if (assessment == null) "Run an on-device audit to evaluate device posture" else "${assessment.deviceManufacturer} ${assessment.deviceModel}",
                        color = TextPrimary,
                        fontSize = 15.sp,
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

                // Circular Score Display
                Box(
                    modifier = Modifier
                        .size(76.dp)
                        .clip(CircleShape)
                        .background(CyberCardElevated)
                        .border(2.dp, scoreColor, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    if (isScanning) {
                        CircularProgressIndicator(
                            color = CyanAccent,
                            modifier = Modifier.size(36.dp),
                            strokeWidth = 3.dp
                        )
                    } else {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = if (assessment == null) "--" else "$score",
                                color = scoreColor,
                                fontSize = 24.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "/100",
                                color = TextSecondary,
                                fontSize = 10.sp
                            )
                        }
                    }
                }
            }

            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = onRunScan,
                    enabled = !isScanning,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CyanAccent,
                        contentColor = CyberObsidian
                    )
                ) {
                    Text(
                        text = if (isScanning) "Auditing System..." else "Run Full Audit",
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp
                    )
                }

                if (assessment != null) {
                    OutlinedButton(
                        onClick = onExportEvidence,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MintEmerald
                        )
                    ) {
                        Text(
                            text = "Export Evidence",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp
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

@Composable
fun FindingItemCard(finding: Finding) {
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
            verticalArrangement = Arrangement.spacedBy(6.dp)
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
                    text = "Action: ${finding.recommendation}",
                    color = MintEmerald,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(CyberCardElevated)
                        .padding(horizontal = 6.dp, vertical = 4.dp)
                )
            }
        }
    }
}
