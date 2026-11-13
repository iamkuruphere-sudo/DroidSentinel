package com.fullstopsolution.droidsentinel.auditor

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.provider.Settings
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.NetworkAuditResult
import com.fullstopsolution.droidsentinel.model.Severity
import java.net.IDN
import java.net.URI

internal data class PrivateDnsAssessment(
    val requiresDnsOverTls: Boolean,
    val finding: Finding
)

internal fun assessPrivateDnsMode(mode: String): PrivateDnsAssessment {
    val finding = when {
        mode.equals("hostname", ignoreCase = true) -> Finding(
            title = "Strict Private DNS Configured",
            description = "DNS-over-TLS is required by the configured Private DNS provider; DNS resolution may fail rather than fall back to plaintext.",
            severity = Severity.SECURE
        )
        mode.equals("opportunistic", ignoreCase = true) -> Finding(
            title = "Opportunistic Private DNS",
            description = "DNS-over-TLS is attempted when available, but Android may fall back to unencrypted DNS.",
            severity = Severity.WARNING,
            recommendation = "Configure a Private DNS provider hostname to require DNS-over-TLS."
        )
        else -> Finding(
            title = "Private DNS Disabled or Unconfigured",
            description = "DNS lookups may be transmitted unencrypted in plaintext across local gateways.",
            severity = Severity.WARNING,
            recommendation = "Enable Private DNS (e.g. dns.google or 1dot1dot1dot1.cloudflare-dns.com) in Network Settings."
        )
    }
    return PrivateDnsAssessment(
        requiresDnsOverTls = mode.equals("hostname", ignoreCase = true),
        finding = finding
    )
}

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

        val privateDnsAssessment = assessPrivateDnsMode(privateDnsMode)
        findings.add(privateDnsAssessment.finding)

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
            isPrivateDnsActive = privateDnsAssessment.requiresDnsOverTls,
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

        val rawHost = parsed?.host ?: parsed?.rawAuthority?.let(::hostFromAuthority)
        val host = rawHost?.let(::toAsciiHostname)?.lowercase()

        if (host == null) {
            findings.add(
                Finding(
                    title = "Unable to Verify URL Hostname",
                    description = "The URL hostname could not be parsed or normalized safely.",
                    severity = Severity.WARNING,
                    recommendation = "Do not open the link until its destination can be verified."
                )
            )
        }

        val normalizedHost = host.orEmpty()

        // 3. Numeric IPv4 / IPv6 Hostname
        val isNumericIp = normalizedHost.matches(Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) || normalizedHost.startsWith("[")
        if (isNumericIp) {
            findings.add(
                Finding(
                    title = "Raw Numeric IP Hostname",
                    description = "URL points directly to an IP address ($normalizedHost) rather than a verified registered domain.",
                    severity = Severity.CRITICAL,
                    recommendation = "Legitimate consumer platforms virtually never use direct IP web endpoints."
                )
            )
        }

        // 4. Internationalized Domain / Punycode
        if (normalizedHost.startsWith("xn--") || normalizedHost.contains(".xn--")) {
            findings.add(
                Finding(
                    title = "Punycode / IDN Homograph Attack Vector",
                    description = "Hostname uses Punycode ($normalizedHost), often weaponized to mimic Latin brand names with Cyrillic characters.",
                    severity = Severity.CRITICAL,
                    recommendation = "Verify character glyphs carefully before navigating."
                )
            )
        }

        // 5. URL Shortener Service
        if (SHORTENER_DOMAINS.any { normalizedHost == it || normalizedHost.endsWith(".$it") }) {
            findings.add(
                Finding(
                    title = "URL Shortening Service",
                    description = "Destination URL is obscured by a redirect service ($normalizedHost).",
                    severity = Severity.WARNING,
                    recommendation = "Unshorten and preview target before opening."
                )
            )
        }

        // 6. Suspicious / Abused TLDs
        if (SUSPICIOUS_TLDS.any { normalizedHost.endsWith(it) }) {
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
            if (normalizedHost.contains("$brand.") && !normalizedHost.endsWith("$brand.com") && !normalizedHost.endsWith("$brand.net")) {
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

    private fun hostFromAuthority(authority: String): String? {
        val withoutUserInfo = authority.substringAfterLast('@')
        if (withoutUserInfo.startsWith("[")) {
            return withoutUserInfo.substringBefore(']') + "]"
        }
        val portSeparator = withoutUserInfo.lastIndexOf(':')
        return if (portSeparator >= 0 && withoutUserInfo.substring(portSeparator + 1).all(Char::isDigit)) {
            withoutUserInfo.substring(0, portSeparator)
        } else {
            withoutUserInfo
        }.takeIf { it.isNotBlank() }
    }

    private fun toAsciiHostname(host: String): String? = try {
        if (host.startsWith("[") && host.endsWith("]")) host
        else IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES)
    } catch (_: IllegalArgumentException) {
        null
    }
}
