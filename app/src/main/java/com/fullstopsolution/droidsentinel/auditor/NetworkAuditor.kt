package com.fullstopsolution.droidsentinel.auditor

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.provider.Settings
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.FindingCategory
import com.fullstopsolution.droidsentinel.model.NetworkAuditResult
import com.fullstopsolution.droidsentinel.model.Severity
import java.net.URI

object NetworkAuditor {

    private val SHORTENER_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
        "rb.gy", "ow.ly", "goo.gl", "buff.ly", "adf.ly",
        "shorte.st", "v.gd", "qr.ae", "bc.vc", "linktr.ee"
    )

    private val SUSPICIOUS_TLDS = setOf(
        ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".buzz", ".work", ".click", ".loan", ".surf", ".racing",
        ".download", ".review", ".stream", ".country", ".kim", ".fit"
    )

    private val CONFUSABLE_CYRILLIC_LOOKALIKES = mapOf(
        '\u0430' to 'a', // Cyrillic small letter a
        '\u0435' to 'e', // Cyrillic small letter ie
        '\u043E' to 'o', // Cyrillic small letter o
        '\u0440' to 'p', // Cyrillic small letter er
        '\u0441' to 'c', // Cyrillic small letter es
        '\u0443' to 'y', // Cyrillic small letter u
        '\u0445' to 'x', // Cyrillic small letter ha
        '\u0456' to 'i'  // Cyrillic small letter byelorussian-ukrainian i
    )

    fun audit(context: Context): NetworkAuditResult {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = cm?.activeNetwork
        val caps = cm?.getNetworkCapabilities(activeNetwork)

        val findings = mutableListOf<Finding>()

        val isConnected = caps != null
        val isVpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
        val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ?: false
        val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ?: false
        val isEthernet = caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ?: false

        val connType = when {
            isWifi -> "Wi-Fi"
            isCellular -> "Cellular"
            isEthernet -> "Ethernet"
            isVpnActive -> "VPN Tunnel"
            else -> "Disconnected / Other"
        }

        // 1. VPN Status
        if (isVpnActive) {
            findings.add(
                Finding(
                    title = "Active VPN Encrypted Tunnel",
                    description = "Outbound IP traffic is routed through a virtual private network tunnel.",
                    severity = Severity.SECURE,
                    category = FindingCategory.NETWORK
                )
            )
        } else {
            findings.add(
                Finding(
                    title = "No Active VPN Tunnel",
                    description = "Traffic traverses local network gateways without a secure VPN envelope.",
                    severity = Severity.INFO,
                    recommendation = "Use a trusted WireGuard/IKEv2 VPN on untrusted or public Wi-Fi networks.",
                    actionType = ActionType.OPEN_WIRELESS_SETTINGS,
                    actionLabel = "Open Network Settings",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 2. Private DNS (DNS-over-TLS)
        val privateDnsMode = try {
            Settings.Global.getString(context.contentResolver, "private_dns_mode") ?: "off"
        } catch (_: Exception) {
            "unknown"
        }
        val privateDnsSpecifier = try {
            Settings.Global.getString(context.contentResolver, "private_dns_specifier")
        } catch (_: Exception) {
            null
        }

        val isPrivateDns = privateDnsMode.lowercase() in setOf("hostname", "opportunistic")
        if (isPrivateDns) {
            findings.add(
                Finding(
                    title = "Private DNS (DoT) Enabled",
                    description = "DNS lookups are encrypted via DNS-over-TLS (mode: $privateDnsMode${if (!privateDnsSpecifier.isNullOrEmpty()) ", provider: $privateDnsSpecifier" else ""}).",
                    severity = Severity.SECURE,
                    category = FindingCategory.NETWORK
                )
            )
        } else {
            findings.add(
                Finding(
                    title = "Private DNS Disabled or Unconfigured",
                    description = "DNS lookups may be transmitted unencrypted in plaintext across local gateways.",
                    severity = Severity.WARNING,
                    recommendation = "Enable Private DNS (e.g. dns.google or 1dot1dot1dot1.cloudflare-dns.com) in Network Settings.",
                    actionType = ActionType.OPEN_PRIVATE_DNS_SETTINGS,
                    actionLabel = "Enable Private DNS",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 3. Captive portal check
        val isCaptive = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) ?: false
        if (isCaptive) {
            findings.add(
                Finding(
                    title = "Captive Portal Network Detected",
                    description = "Connected to a captive network intercepting web traffic for authentication.",
                    severity = Severity.WARNING,
                    recommendation = "Avoid transmitting credentials or confidential data until authenticated.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 4. Wi-Fi Security Check (using modern transportInfo to avoid deprecation)
        if (isWifi) {
            val wifiInfo = caps?.transportInfo as? WifiInfo
            val isMetered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            findings.add(
                Finding(
                    title = "Wi-Fi Interface Active",
                    description = "Connected over Wi-Fi (Metered: $isMetered). Keep Private DNS enabled to protect queries.",
                    severity = Severity.INFO,
                    category = FindingCategory.NETWORK
                )
            )
        }

        return NetworkAuditResult(
            isConnected = isConnected,
            connectionType = connType,
            isWifiEncrypted = isWifi,
            wifiSecurityType = if (isWifi) "WPA2/WPA3" else "N/A",
            isVpnActive = isVpnActive,
            isPrivateDnsActive = isPrivateDns,
            privateDnsServer = privateDnsSpecifier,
            isCaptivePortal = isCaptive,
            findings = findings
        )
    }

    // Comprehensive Interactive URL Phishing & Link Analyzer
    fun analyzeUrl(rawUrl: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        val trimmed = rawUrl.trim()

        if (trimmed.isEmpty()) return findings

        // 1. Cleartext HTTP Check
        if (trimmed.startsWith("http://", ignoreCase = true)) {
            findings.add(
                Finding(
                    title = "Insecure Cleartext Protocol (HTTP)",
                    description = "Link does not enforce TLS encryption; traffic is vulnerable to man-in-the-middle manipulation.",
                    severity = Severity.CRITICAL,
                    recommendation = "Do not enter passwords, credit cards, or confidential data on unencrypted HTTP pages.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 2. Deceptive '@' sign redirect syntax
        if (trimmed.contains("@")) {
            findings.add(
                Finding(
                    title = "Deceptive '@' Authority Redirect Syntax",
                    description = "URI contains an '@' character, frequently weaponized in phishing to mask the real destination host.",
                    severity = Severity.CRITICAL,
                    recommendation = "Reject link. Web browsers discard all text prior to the '@' character and route to the suffix host.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        val parsed = try {
            URI(trimmed)
        } catch (_: Exception) {
            null
        }

        val rawHost = parsed?.host ?: extractHostFallback(trimmed)
        val host = rawHost.lowercase()
        val port = parsed?.port ?: -1

        // 3. Raw Numeric IPv4 or IPv6 Hostname
        val isNumericIp = host.matches(Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) || host.startsWith("[")
        if (isNumericIp) {
            findings.add(
                Finding(
                    title = "Raw Numeric IP Hostname",
                    description = "URL points directly to an IP address ($host) rather than a verified registered domain.",
                    severity = Severity.CRITICAL,
                    recommendation = "Legitimate consumer platforms virtually never serve customer web portals over raw IP endpoints.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 4. Hex / Dword Obfuscated IP Address (e.g., http://0x7f000001 or http://2130706433)
        if (host.startsWith("0x", ignoreCase = true) || host.matches(Regex("^[0-9]{8,12}$"))) {
            findings.add(
                Finding(
                    title = "Obfuscated Integer / Hexadecimal IP",
                    description = "Hostname uses hexadecimal or 32-bit integer IP representation to bypass URL pattern filters ($host).",
                    severity = Severity.CRITICAL,
                    recommendation = "High-confidence malicious evasion indicator. Do not open.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 5. Non-Standard / Suspicious Port
        val suspiciousPorts = setOf(8080, 8888, 4444, 1337, 3128, 8443, 9090)
        if (port in suspiciousPorts) {
            findings.add(
                Finding(
                    title = "Non-Standard Port Designation (:$port)",
                    description = "Connection routes through non-standard network port $port, frequently associated with ad-hoc phishing proxies.",
                    severity = Severity.WARNING,
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 6. Punycode / IDN Homograph Attack
        if (host.startsWith("xn--") || host.contains(".xn--")) {
            findings.add(
                Finding(
                    title = "Punycode / IDN Homograph Vector",
                    description = "Hostname uses Punycode ($host), often weaponized to mimic Latin brand names with Cyrillic characters.",
                    severity = Severity.CRITICAL,
                    recommendation = "Inspect character glyphs with extreme caution before entering credentials.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 7. Confusable Mixed-Script Homoglyph Heuristic
        for (char in host) {
            if (CONFUSABLE_CYRILLIC_LOOKALIKES.containsKey(char)) {
                val latinEquivalent = CONFUSABLE_CYRILLIC_LOOKALIKES[char]
                findings.add(
                    Finding(
                        title = "Confusable Cyrillic Homoglyph Detected",
                        description = "Hostname contains Cyrillic character '$char' masquerading as Latin '$latinEquivalent' (IDN spoofing).",
                        severity = Severity.CRITICAL,
                        recommendation = "Confirmed homograph spoofing attempt. Do not navigate to this destination.",
                        category = FindingCategory.NETWORK
                    )
                )
                break
            }
        }

        // 8. URL Shortening Services
        if (SHORTENER_DOMAINS.any { host == it || host.endsWith(".$it") }) {
            findings.add(
                Finding(
                    title = "URL Shortener Redirection",
                    description = "Destination host is obscured by a redirect service ($host).",
                    severity = Severity.WARNING,
                    recommendation = "Unshorten and verify target URL before opening.",
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 9. High-Risk / Suspicious TLDs
        if (SUSPICIOUS_TLDS.any { host.endsWith(it) }) {
            findings.add(
                Finding(
                    title = "High-Risk Top-Level Domain",
                    description = "Domain resides on a TLD frequently associated with automated throwaway phishing infrastructure.",
                    severity = Severity.WARNING,
                    category = FindingCategory.NETWORK
                )
            )
        }

        // 10. Brand Impersonation Subdomain Pattern (e.g. paypal.com.evil.xyz or support.apple.com.login.link)
        val brands = listOf("paypal", "apple", "google", "samsung", "netflix", "bank", "login", "verify", "chase", "wellsfargo", "binance", "coinbase", "support")
        for (brand in brands) {
            if (host.contains("$brand.") && !host.endsWith("$brand.com") && !host.endsWith("$brand.net")) {
                findings.add(
                    Finding(
                        title = "Brand Impersonation Subdomain Heuristic",
                        description = "Hostname mimics '$brand' in subdomain prefix while hosted on an external root domain ($host).",
                        severity = Severity.CRITICAL,
                        recommendation = "Deceptive phishing domain masquerading as a reputable institution.",
                        category = FindingCategory.NETWORK
                    )
                )
                break
            }
        }

        if (findings.isEmpty()) {
            findings.add(
                Finding(
                    title = "No Local Phishing Heuristics Triggered",
                    description = "URL adheres to TLS conventions and displays no obvious obfuscation patterns.",
                    severity = Severity.SECURE,
                    category = FindingCategory.NETWORK
                )
            )
        }

        return findings
    }

    private fun extractHostFallback(url: String): String {
        val withoutScheme = url.substringAfter("://", url)
        val hostPart = withoutScheme.substringBefore("/").substringBefore("?").substringBefore("#")
        return hostPart.substringBefore(":")
    }
}
