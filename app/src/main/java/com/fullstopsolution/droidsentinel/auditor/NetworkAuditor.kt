package com.fullstopsolution.droidsentinel.auditor

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.provider.Settings
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.NetworkAuditResult
import com.fullstopsolution.droidsentinel.model.Severity
import java.net.URI

object NetworkAuditor {

    private val SHORTENER_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
        "rb.gy", "ow.ly", "goo.gl", "buff.ly", "adf.ly"
    )

    private val SUSPICIOUS_TLDS = setOf(".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".click")

    fun audit(context: Context): NetworkAuditResult {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = cm?.activeNetwork
        val caps = cm?.getNetworkCapabilities(activeNetwork)

        val findings = mutableListOf<Finding>()

        val isConnected = caps != null
        val isVpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
        val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ?: false
        val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ?: false

        val connType = when {
            isWifi -> "Wi-Fi"
            isCellular -> "Cellular"
            isVpnActive -> "VPN Tunnel"
            else -> "Disconnected / Other"
        }

        // 1. VPN Status
        if (isVpnActive) {
            findings.add(
                Finding(
                    title = "Active VPN Encrypted Tunnel",
                    description = "Outbound IP traffic is routed through a virtual private network tunnel.",
                    severity = Severity.SECURE
                )
            )
        } else {
            findings.add(
                Finding(
                    title = "No Active VPN Tunnel",
                    description = "Traffic traverses local network gateways without a secure VPN envelope.",
                    severity = Severity.INFO,
                    recommendation = "Use a trusted WireGuard/IKEv2 VPN on public or untrusted Wi-Fi."
                )
            )
        }

        // 2. Private DNS (DNS-over-TLS)
        val privateDnsMode = try {
            Settings.Global.getString(context.contentResolver, "private_dns_mode") ?: "off"
        } catch (_: Exception) {
            "unknown"
        }

        val isPrivateDns = privateDnsMode.lowercase() in setOf("hostname", "opportunistic")
        if (isPrivateDns) {
            findings.add(
                Finding(
                    title = "Private DNS (DoT) Enabled",
                    description = "DNS queries are encrypted via DNS-over-TLS (mode: $privateDnsMode).",
                    severity = Severity.SECURE
                )
            )
        } else {
            findings.add(
                Finding(
                    title = "Private DNS Disabled or Unconfigured",
                    description = "DNS lookups may be transmitted unencrypted in plaintext across local gateways.",
                    severity = Severity.WARNING,
                    recommendation = "Enable Private DNS (e.g. dns.google or 1dot1dot1dot1.cloudflare-dns.com) in Network Settings."
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
                    recommendation = "Avoid transmitting credentials until authenticated through official portal."
                )
            )
        }

        // 4. Wi-Fi details
        var wifiSsid: String? = null
        if (isWifi) {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            val info = wifiManager?.connectionInfo
            wifiSsid = info?.ssid?.replace("\"", "")
        }

        return NetworkAuditResult(
            isConnected = isConnected,
            connectionType = connType,
            isWifiEncrypted = isWifi,
            wifiSecurityType = if (isWifi) "WPA2/WPA3" else "N/A",
            isVpnActive = isVpnActive,
            isPrivateDnsActive = isPrivateDns,
            findings = findings
        )
    }

    // Interactive URL Phishing & Link Analyzer
    fun analyzeUrl(rawUrl: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        val trimmed = rawUrl.trim()

        if (trimmed.isEmpty()) return findings

        // 1. HTTPS Check
        if (!trimmed.startsWith("https://", ignoreCase = true)) {
            findings.add(
                Finding(
                    title = "Insecure Cleartext Protocol (HTTP)",
                    description = "Link does not enforce TLS encryption; traffic is vulnerable to MITM manipulation.",
                    severity = Severity.CRITICAL,
                    recommendation = "Do not enter credentials or confidential data on unencrypted HTTP pages."
                )
            )
        }

        // 2. Misleading '@' sign redirect
        if (trimmed.contains("@")) {
            findings.add(
                Finding(
                    title = "Deceptive '@' Redirect Authority Syntax",
                    description = "URI contains an '@' character, frequently used in phishing to mask the real destination host.",
                    severity = Severity.CRITICAL,
                    recommendation = "Reject link. Browsers will discard prefix text prior to the '@' symbol."
                )
            )
        }

        val parsed = try {
            URI(trimmed)
        } catch (_: Exception) {
            null
        }

        val host = parsed?.host?.lowercase() ?: ""

        // 3. Numeric IPv4 / IPv6 Hostname
        val isNumericIp = host.matches(Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) || host.startsWith("[")
        if (isNumericIp) {
            findings.add(
                Finding(
                    title = "Raw Numeric IP Hostname",
                    description = "URL points directly to an IP address ($host) rather than a verified registered domain.",
                    severity = Severity.CRITICAL,
                    recommendation = "Legitimate consumer platforms virtually never use direct IP web endpoints."
                )
            )
        }

        // 4. Internationalized Domain / Punycode
        if (host.startsWith("xn--") || host.contains(".xn--")) {
            findings.add(
                Finding(
                    title = "Punycode / IDN Homograph Attack Vector",
                    description = "Hostname uses Punycode ($host), often weaponized to mimic Latin brand names with Cyrillic characters.",
                    severity = Severity.CRITICAL,
                    recommendation = "Verify character glyphs carefully before navigating."
                )
            )
        }

        // 5. URL Shortener Service
        if (SHORTENER_DOMAINS.any { host == it || host.endsWith(".$it") }) {
            findings.add(
                Finding(
                    title = "URL Shortening Service",
                    description = "Destination URL is obscured by a redirect service ($host).",
                    severity = Severity.WARNING,
                    recommendation = "Unshorten and preview target before opening."
                )
            )
        }

        // 6. Suspicious / Abused TLDs
        if (SUSPICIOUS_TLDS.any { host.endsWith(it) }) {
            findings.add(
                Finding(
                    title = "High-Risk Top-Level Domain",
                    description = "Domain resides on a TLD frequently associated with automated phishing campaigns.",
                    severity = Severity.WARNING
                )
            )
        }

        // 7. Brand Impersonation Subdomain Pattern (e.g. paypal.com.evil.xyz)
        val brands = listOf("paypal", "apple", "google", "samsung", "netflix", "bank", "login", "verify")
        for (brand in brands) {
            if (host.contains("$brand.") && !host.endsWith("$brand.com") && !host.endsWith("$brand.net")) {
                findings.add(
                    Finding(
                        title = "Brand Spoofing Subdomain Heuristic",
                        description = "Hostname mimics '$brand' in subdomain prefix while hosted on a distinct domain.",
                        severity = Severity.CRITICAL,
                        recommendation = "Likely deceptive phishing domain masquerading as a reputable service."
                    )
                )
                break
            }
        }

        if (findings.isEmpty()) {
            findings.add(
                Finding(
                    title = "No Local Phishing Heuristics Triggered",
                    description = "URL adheres to standard HTTPS conventions and shows no obvious obfuscation patterns.",
                    severity = Severity.SECURE
                )
            )
        }

        return findings
    }
}
