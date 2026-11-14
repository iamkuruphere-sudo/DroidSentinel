package com.fullstopsolution.droidsentinel.ui.screens

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fullstopsolution.droidsentinel.auditor.NetworkAuditor
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.AppThreatInfo
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
fun IntegrityTab(
    assessment: CompleteSecurityAssessment?,
    onExecuteAction: (Finding) -> Unit = {}
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text(
                text = "OS INTEGRITY & HARDWARE POSTURE",
                color = CyanAccent,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.5.sp
            )
            Text(
                text = "Kernel & System Baseline Audit",
                color = TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }

        if (assessment == null) {
            item {
                Text("Run full audit on Dashboard to review system integrity.", color = TextSecondary)
            }
        } else {
            val integrity = assessment.integrity

            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    IntegrityRow("Root / Jailbreak Binary Status", if (integrity.isRooted) "COMPROMISED" else "CLEAN (No SU)", !integrity.isRooted)
                    IntegrityRow("SELinux Security Module", integrity.selinuxMode, integrity.selinuxMode == "Enforcing")
                    IntegrityRow("OS Build Certificate", if (integrity.isTestKeysBuild) "TEST-KEYS (Custom)" else "RELEASE-KEYS (Official)", !integrity.isTestKeysBuild)
                    IntegrityRow("USB Debugging (ADB)", if (integrity.isAdbEnabled) "ENABLED (Risk)" else "DISABLED (Safe)", !integrity.isAdbEnabled)
                    IntegrityRow("Wireless ADB over Wi-Fi", if (integrity.isAdbWifiEnabled) "ACTIVE (Critical)" else "DISABLED (Safe)", !integrity.isAdbWifiEnabled)
                    IntegrityRow("Device Screen Lock Keyguard", if (integrity.isDeviceLocked) "SECURE (PIN/Biometrics)" else "INSECURE (No Lock)", integrity.isDeviceLocked)
                    IntegrityRow("Hardware Keystore (TEE)", if (integrity.isKeystoreHardwareBacked) "HARDWARE-BACKED" else "SOFTWARE EMULATED", integrity.isKeystoreHardwareBacked)
                    IntegrityRow("Dedicated StrongBox HSM", if (integrity.hasStrongBox) "SUPPORTED" else "NOT PRESENT (TEE)", true)
                    IntegrityRow("Biometric Authentication", integrity.biometricStatus, integrity.biometricStatus.contains("Enrolled"))
                }
            }

            item {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "AUDIT SIGNALS & PLATFORM LIMITATIONS",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 1.sp
                )
            }

            items(integrity.findings) { finding ->
                FindingItemCard(finding = finding, onExecuteAction = onExecuteAction)
            }

            item {
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .border(1.dp, CyberBorder, RoundedCornerShape(10.dp)),
                    color = CyberCardElevated
                ) {
                    Text(
                        text = "Zero-Cloud Sandbox Architecture: Standard user-space apps are restricted by the Android Linux sandbox from reading raw storage blocks or unconfined kernel logs. Hardware Knox/Verified Boot verification requires stock firmware with Google Play Protect enabled.",
                        color = TextMuted,
                        fontSize = 11.sp,
                        lineHeight = 15.sp,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun AppsTab(
    assessment: CompleteSecurityAssessment?,
    onExecuteAction: (Finding) -> Unit = {}
) {
    var selectedFilter by remember { mutableStateOf("ALL") }
    var appSearchQuery by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text(
                text = "APPLICATION THREAT INVENTORY",
                color = CyanAccent,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.5.sp
            )
            Text(
                text = "Sideload & Permission Cluster Audit",
                color = TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }

        if (assessment == null) {
            item {
                Text("Run full audit on Dashboard to inspect installed applications.", color = TextSecondary)
            }
        } else {
            val appAudit = assessment.appAudit

            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    // App Search Box
                    OutlinedTextField(
                        value = appSearchQuery,
                        onValueChange = { appSearchQuery = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Search by name or package...", color = TextMuted, fontSize = 12.sp) },
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

                    // Filter Pills
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        FilterPill("ALL (${appAudit.totalAppsScanned})", selectedFilter == "ALL") { selectedFilter = "ALL" }
                        FilterPill("HIGH RISK (${appAudit.highRiskApps.size})", selectedFilter == "HIGH_RISK") { selectedFilter = "HIGH_RISK" }
                        FilterPill("SIDELOAD (${appAudit.sideloadedApps.size})", selectedFilter == "SIDELOAD") { selectedFilter = "SIDELOAD" }
                        FilterPill("CLEARTEXT (${appAudit.cleartextApps.size})", selectedFilter == "CLEARTEXT") { selectedFilter = "CLEARTEXT" }
                        FilterPill("AUTORUN (${appAudit.autorunApps.size})", selectedFilter == "AUTORUN") { selectedFilter = "AUTORUN" }
                    }
                }
            }

            val baseList = when (selectedFilter) {
                "HIGH_RISK" -> appAudit.highRiskApps
                "SIDELOAD" -> appAudit.sideloadedApps
                "CLEARTEXT" -> appAudit.cleartextApps
                "AUTORUN" -> appAudit.autorunApps
                else -> appAudit.allApps.ifEmpty { appAudit.sideloadedApps + appAudit.highRiskApps + appAudit.cleartextApps }
            }.distinctBy { it.packageName }

            val filteredList = baseList.filter { app ->
                appSearchQuery.isBlank() ||
                        app.appName.contains(appSearchQuery, ignoreCase = true) ||
                        app.packageName.contains(appSearchQuery, ignoreCase = true)
            }

            if (filteredList.isEmpty()) {
                item {
                    Text(
                        text = "No applications matching this filter query.",
                        color = TextSecondary,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )
                }
            } else {
                items(filteredList) { app ->
                    AppDetailCard(app = app, onExecuteAction = onExecuteAction)
                }
            }
        }
    }
}

@Composable
fun StorageTab(
    assessment: CompleteSecurityAssessment?,
    onRequestStoragePermission: () -> Unit,
    onExecuteAction: (Finding) -> Unit = {}
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text(
                text = "STORAGE & PAYLOAD INSPECTION",
                color = CyanAccent,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.5.sp
            )
            Text(
                text = "VBA Macro & Script Vectors",
                color = TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }

        if (assessment == null) {
            item {
                Text("Run full audit on Dashboard to inspect storage directories.", color = TextSecondary)
            }
        } else {
            val storage = assessment.storageAudit

            if (!storage.isStorageAccessGranted) {
                item {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .border(1.dp, StatusWarning.copy(alpha = 0.5f), RoundedCornerShape(12.dp)),
                        color = CyberCard
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Text(
                                text = "Deep File Inspection Restricted",
                                color = StatusWarning,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "Grant All Files Access to inspect user downloads for embedded VBA macros in Office files (.docm, .xlsm), autorun scripts (.vbs, .bat), and deceptive update APK payloads.",
                                color = TextSecondary,
                                fontSize = 12.sp
                            )
                            Button(
                                onClick = onRequestStoragePermission,
                                colors = ButtonDefaults.buttonColors(containerColor = CyanAccent, contentColor = CyberObsidian),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text("Grant Deep File Access", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                item {
                    Text(
                        text = "Scanned ${storage.filesScannedCount} files in Download storage directory.",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )
                }

                if (storage.threatsFound.isEmpty()) {
                    item {
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .border(1.dp, CyberBorder, RoundedCornerShape(12.dp)),
                            color = CyberCard
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("No Threat Payloads Identified", color = StatusSecure, fontWeight = FontWeight.Bold)
                                Text("All scanned Office documents and files are free of embedded macro binaries and deceptive extension payloads.", color = TextSecondary, fontSize = 12.sp)
                            }
                        }
                    }
                } else {
                    items(storage.threatsFound) { threat ->
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .border(1.dp, CyberBorder, RoundedCornerShape(12.dp)),
                            color = CyberCard
                        ) {
                            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(threat.fileName, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(Color(0x33EF4444))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(threat.threatType, color = StatusCritical, fontWeight = FontWeight.Bold, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                    }
                                }
                                Text(threat.details, color = TextSecondary, fontSize = 12.sp)
                                if (threat.sha256Hash != null) {
                                    Text("SHA-256: ${threat.sha256Hash}", color = CyanAccent, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                                }
                                Text("Path: ${threat.filePath}", color = TextMuted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.End
                                ) {
                                    OutlinedButton(
                                        onClick = {
                                            onExecuteAction(
                                                Finding(
                                                    title = "Delete File: ${threat.fileName}",
                                                    description = threat.details,
                                                    severity = Severity.CRITICAL,
                                                    actionType = ActionType.DELETE_FILE,
                                                    actionPayload = threat.filePath,
                                                    actionLabel = "Delete File"
                                                )
                                            )
                                        },
                                        shape = RoundedCornerShape(6.dp),
                                        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusCritical)
                                    ) {
                                        Icon(Icons.Default.Delete, contentDescription = "Delete", modifier = Modifier.size(12.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Delete Threat", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun NetworkTab(
    assessment: CompleteSecurityAssessment?,
    onExecuteAction: (Finding) -> Unit = {}
) {
    var testUrl by remember { mutableStateOf("") }
    var urlFindings by remember { mutableStateOf<List<Finding>?>(null) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text(
                text = "NETWORK DEFENSE & LINK AUDIT",
                color = CyanAccent,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.5.sp
            )
            Text(
                text = "Connection Security & Phishing Defense",
                color = TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }

        // Active Connection Posture
        if (assessment != null) {
            val net = assessment.networkAudit
            item {
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .border(1.dp, CyberBorder, RoundedCornerShape(12.dp)),
                    color = CyberCard
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Active Interface Posture", color = TextPrimary, fontWeight = FontWeight.Bold)
                        IntegrityRow("Transport Type", net.connectionType, true)
                        IntegrityRow("VPN Encryption Tunnel", if (net.isVpnActive) "PROTECTED (VPN Active)" else "DIRECT (No VPN)", net.isVpnActive)
                        IntegrityRow("Private DNS (DoT)", if (net.isPrivateDnsActive) "ENCRYPTED (${net.privateDnsServer ?: "Auto"})" else "PLAINTEXT / OFF", net.isPrivateDnsActive)
                        IntegrityRow("Captive Portal Interception", if (net.isCaptivePortal) "DETECTED (Risk)" else "NONE", !net.isCaptivePortal)

                        if (!net.isPrivateDnsActive) {
                            Button(
                                onClick = {
                                    onExecuteAction(
                                        Finding(
                                            title = "Enable Private DNS",
                                            description = "",
                                            severity = Severity.WARNING,
                                            actionType = ActionType.OPEN_PRIVATE_DNS_SETTINGS
                                        )
                                    )
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = CyanAccent, contentColor = CyberObsidian),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text("Configure Private DNS in Settings", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // Interactive URL Phishing Scanner
        item {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .border(1.dp, CyberBorder, RoundedCornerShape(12.dp)),
                color = CyberCard
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("Interactive Phishing & Link Analyzer", color = TextPrimary, fontWeight = FontWeight.Bold)
                    Text("Test any URL against 10 on-device phishing heuristics (Punycode, '@' redirects, cleartext HTTP, hex IPs, brand spoofing).", color = TextSecondary, fontSize = 12.sp)

                    OutlinedTextField(
                        value = testUrl,
                        onValueChange = { testUrl = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("https://example.com/login", color = TextMuted) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyanAccent,
                            unfocusedBorderColor = CyberBorder,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )

                    // Preset Test Buttons
                    Text("Quick Preset Tests:", color = TextMuted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        PresetPill("Punycode") {
                            testUrl = "https://xn--pple-43d.com/login"
                            urlFindings = NetworkAuditor.analyzeUrl(testUrl)
                        }
                        PresetPill("@ Redirect") {
                            testUrl = "https://bank.com@phish-login.xyz/auth"
                            urlFindings = NetworkAuditor.analyzeUrl(testUrl)
                        }
                        PresetPill("Brand Spoof") {
                            testUrl = "https://paypal.com.verify-user.xyz/signin"
                            urlFindings = NetworkAuditor.analyzeUrl(testUrl)
                        }
                        PresetPill("Raw IP") {
                            testUrl = "http://192.168.1.1/admin"
                            urlFindings = NetworkAuditor.analyzeUrl(testUrl)
                        }
                    }

                    Button(
                        onClick = { urlFindings = NetworkAuditor.analyzeUrl(testUrl) },
                        enabled = testUrl.isNotBlank(),
                        colors = ButtonDefaults.buttonColors(containerColor = CyanAccent, contentColor = CyberObsidian),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Analyze Link Integrity", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        if (urlFindings != null) {
            item {
                Text("LINK HEURISTIC VERDICT", color = TextSecondary, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
            items(urlFindings!!) { f ->
                FindingItemCard(finding = f, onExecuteAction = onExecuteAction)
            }
        }
    }
}

@Composable
fun PresetPill(text: String, onClick: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(6.dp),
        color = CyberCardElevated,
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberBorder),
        modifier = androidx.compose.ui.Modifier.clickable { onClick() }
    ) {
        Text(
            text = text,
            color = CyanAccent,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}

@Composable
fun IntegrityRow(label: String, value: String, isOk: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = TextSecondary, fontSize = 12.sp)
        Text(
            value,
            color = if (isOk) StatusSecure else StatusCritical,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun FilterPill(text: String, isSelected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = isSelected,
        onClick = onClick,
        label = { Text(text, fontSize = 10.sp, fontWeight = FontWeight.Bold) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = CyanAccent,
            selectedLabelColor = CyberObsidian,
            containerColor = CyberCardElevated,
            labelColor = TextSecondary
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true,
            selected = isSelected,
            borderColor = if (isSelected) CyanAccent else CyberBorder
        )
    )
}

@Composable
fun AppDetailCard(
    app: AppThreatInfo,
    onExecuteAction: (Finding) -> Unit = {}
) {
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
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(app.appName, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (app.riskScore >= 40) Color(0x33EF4444) else Color(0x33F59E0B))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text("RISK ${app.riskScore}", color = if (app.riskScore >= 40) StatusCritical else StatusWarning, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }

            Text(app.packageName, color = TextMuted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            Text("Installer: ${app.installerPackage ?: "Direct Sideload"} • Target SDK: ${app.targetSdk}", color = TextSecondary, fontSize = 11.sp)

            // Tags row
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (app.isSideloaded) {
                    SmallTag("SIDELOAD", StatusWarning)
                }
                if (app.usesCleartextTraffic) {
                    SmallTag("CLEARTEXT HTTP", StatusCritical)
                }
                if (app.isBootCompleted) {
                    SmallTag("AUTORUN", StatusInfo)
                }
                if (app.exportedComponentsCount > 0) {
                    SmallTag("EXPORTED IPC: ${app.exportedComponentsCount}", StatusWarning)
                }
            }

            if (app.dangerousPermissions.isNotEmpty()) {
                Text("Permissions: ${app.dangerousPermissions.joinToString(", ") { it.substringAfterLast(".") }}", color = TextMuted, fontSize = 10.sp)
            }

            // Quick Actions: App Info & Uninstall
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                OutlinedButton(
                    onClick = {
                        onExecuteAction(
                            Finding(
                                title = "App Info",
                                description = "",
                                severity = Severity.INFO,
                                actionType = ActionType.OPEN_APP_SETTINGS,
                                actionPayload = app.packageName
                            )
                        )
                    },
                    shape = RoundedCornerShape(6.dp),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanAccent)
                ) {
                    Icon(Icons.Default.Info, contentDescription = "Info", modifier = Modifier.size(12.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("App Info", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.width(8.dp))

                OutlinedButton(
                    onClick = {
                        onExecuteAction(
                            Finding(
                                title = "Uninstall App",
                                description = "",
                                severity = Severity.CRITICAL,
                                actionType = ActionType.UNINSTALL_APP,
                                actionPayload = app.packageName
                            )
                        )
                    },
                    shape = RoundedCornerShape(6.dp),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusCritical)
                ) {
                    Icon(Icons.Default.Delete, contentDescription = "Uninstall", modifier = Modifier.size(12.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Uninstall", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun SmallTag(text: String, color: Color) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(4.dp))
            .background(color.copy(alpha = 0.15f))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(text, color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
    }
}
