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

        // 2. Private DNS (DNS-over-TLS) - Differentiate Strict vs. Opportunistic modes
        val rawPrivateDnsMode = try {
            Settings.Global.getString(context.contentResolver, "private_dns_mode") ?: "off"
        } catch (_: Exception) {
            "unknown"
        }

        val (isPrivateDnsActive, dnsDisplayMode) = when (rawPrivateDnsMode.lowercase()) {
            "hostname" -> {
                findings.add(
                    Finding(
                        title = "Strict Private DNS (DoT) Active",
                        description = "DNS queries are strictly encrypted via DNS-over-TLS to a designated provider and will not fall back to plaintext.",
                        severity = Severity.SECURE
                    )
                )
                true to "Strict DoT"
            }
            "opportunistic" -> {
                findings.add(
                    Finding(
                        title = "Opportunistic Private DNS (Automatic Mode)",
                        description = "Private DNS is set to Automatic. Android attempts DNS-over-TLS on port 853, but will silently fall back to unencrypted plaintext DNS if port 853 is blocked by local firewalls or captive portals.",
                        severity = Severity.WARNING,
                        recommendation = "Specify a designated Private DNS provider hostname in Android Settings to prevent unencrypted plaintext fallback."
                    )
                )
                true to "Opportunistic (Fallback Risk)"
            }
            else -> {
                findings.add(
                    Finding(
                        title = "Private DNS Disabled or Unconfigured",
                        description = "DNS lookups are transmitted unencrypted in plaintext across local gateways and ISPs.",
                        severity = Severity.WARNING,
                        recommendation = "Enable Private DNS in Android Network Settings to encrypt DNS queries."
                    )
                )
                false to "Disabled / Plaintext"
            }
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
            @Suppress("DEPRECATION")
            val info = wifiManager?.connectionInfo
            wifiSsid = info?.ssid?.replace("\"", "")
        }

        return NetworkAuditResult(
            isConnected = isConnected,
            connectionType = connType,
            isWifiEncrypted = isWifi,
            wifiSecurityType = if (isWifi) "WPA2/WPA3" else "N/A",
            isVpnActive = isVpnActive,
            isPrivateDnsActive = isPrivateDnsActive,
            privateDnsMode = dnsDisplayMode,
            findings = findings
        )
    }

    // Interactive URL Phishing & Link Analyzer
    fun analyzeUrl(rawUrl: String): List<Finding> {
        val findings = mutableListOf<Finding>()
        val trimmed = rawUrl.trim()

        if (trimmed.isEmpty()) return findings

        // 1. Protocol Check
        val lowerUrl = trimmed.lowercase()
        val isHttps = lowerUrl.startsWith("https://")
        val isHttp = lowerUrl.startsWith("http://")

        if (!isHttps) {
            findings.add(
                Finding(
                    title = if (isHttp) "Insecure Cleartext Protocol (HTTP)" else "Missing Secure Protocol Scheme",
                    description = if (isHttp) "Link does not enforce TLS encryption; traffic is vulnerable to MITM manipulation." else "Link lacks https:// scheme.",
                    severity = Severity.CRITICAL,
                    recommendation = "Do not enter credentials or confidential data on unencrypted HTTP pages."
                )
            )
        }

        // 2. Deceptive '@' Authority Redirect
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

        // 3. Robust Host Extraction (including raw Unicode hosts)
        // Extract authority part via regex to prevent URI(rawUrl) failure on raw Unicode characters
        val hostMatch = Regex("""^(?:https?://)?([^/?#]+)""", RegexOption.IGNORE_CASE).find(trimmed)
        val rawAuthority = hostMatch?.groupValues?.get(1)?.trim() ?: ""
        val hostPart = rawAuthority.substringAfterLast("@").substringBefore(":")

        if (hostPart.isEmpty()) {
            findings.add(
                Finding(
                    title = "Malformed Destination Host",
                    description = "The URL does not contain a parseable destination hostname.",
                    severity = Severity.CRITICAL,
                    recommendation = "Do not follow malformed links."
                )
            )
            return findings
        }

        // 4. Unicode & Punycode (IDN Homograph) Detection
        val hasNonAscii = hostPart.any { it.code > 127 }
        val asciiHost = try {
            IDN.toASCII(hostPart, IDN.ALLOW_UNASSIGNED).lowercase()
        } catch (_: Exception) {
            hostPart.lowercase()
        }

        val isPunycode = asciiHost.startsWith("xn--") || asciiHost.contains(".xn--")
        if (hasNonAscii || isPunycode) {
            findings.add(
                Finding(
                    title = "Punycode / IDN Homograph Attack Vector",
                    description = "Hostname contains internationalized Unicode characters or Punycode encoding ($hostPart -> $asciiHost), often weaponized to mimic legitimate brand names with look-alike glyphs (e.g. Cyrillic vs Latin).",
                    severity = Severity.CRITICAL,
                    recommendation = "Reject or scrutinize characters closely. Attackers register look-alike domains to deceive users."
                )
            )
        }

        // 5. Numeric IPv4 / IPv6 Hostname
        val isNumericIp = asciiHost.matches(Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) || asciiHost.startsWith("[")
        if (isNumericIp) {
            findings.add(
                Finding(
                    title = "Raw Numeric IP Hostname",
                    description = "URL points directly to an IP address ($asciiHost) rather than a verified registered domain.",
                    severity = Severity.CRITICAL,
                    recommendation = "Legitimate consumer platforms virtually never use direct IP web endpoints."
                )
            )
        }

        // 6. URL Shortener Service
        if (SHORTENER_DOMAINS.any { asciiHost == it || asciiHost.endsWith(".$it") }) {
            findings.add(
                Finding(
                    title = "URL Shortening Service",
                    description = "Destination URL is obscured by a redirect service ($asciiHost).",
                    severity = Severity.WARNING,
                    recommendation = "Unshorten and preview target before opening."
                )
            )
        }

        // 7. Suspicious / Abused TLDs
        if (SUSPICIOUS_TLDS.any { asciiHost.endsWith(it) }) {
            findings.add(
                Finding(
                    title = "High-Risk Top-Level Domain",
                    description = "Domain resides on a TLD ($asciiHost) frequently associated with automated phishing campaigns.",
                    severity = Severity.WARNING
                )
            )
        }

        // 8. Brand Impersonation Subdomain Pattern (e.g. paypal.com.evil.xyz)
        val brands = listOf("paypal", "apple", "google", "samsung", "netflix", "microsoft", "amazon", "bank", "login", "verify")
        for (brand in brands) {
            if (asciiHost.contains("$brand.") && !asciiHost.endsWith("$brand.com") && !asciiHost.endsWith("$brand.net") && !asciiHost.endsWith("$brand.org")) {
                findings.add(
                    Finding(
                        title = "Brand Spoofing Subdomain Heuristic",
                        description = "Hostname mimics '$brand' in subdomain prefix while hosted on a distinct domain ($asciiHost).",
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
