# DroidSentinel

**Part of the [Fullstop Solution](https://www.fullstopsolution.in) precision software ecosystem.**

An enterprise-grade, point-in-time, read-only Android mobile endpoint security auditing and evidence collection app. Built natively in Kotlin with Jetpack Compose & Material 3.

DroidSentinel is the Android mobile companion to [MacSentinel](https://github.com/iamkuruphere-sudo/MacSentinel). It evaluates on-device security posture, firmware integrity, root/exploit indicators, sideloaded applications, dangerous permission clusters, storage threats (VBA macros & rogue update APKs), network posture, and phishing vectors without transmitting telemetry or customer data to third-party cloud servers.

---

## ⬇️ Official Downloads & Release Assets

| Resource | Value / Link |
| :--- | :--- |
| **Release APK** | `DroidSentinel-release.apk` (v1.0.0) |
| **Package ID** | `com.fullstopsolution.droidsentinel` |
| **Target SDK** | Android 17 (API 37) / Min SDK: Android 13 (API 33) |
| **Signing Fingerprint (SHA-256)** | `40:83:42:03:B8:15:A4:3E:70:78:2F:E1:6D:10:BC:DD:84:28:C3:C4:A8:7A:54:83:4D:42:97:B3:91:22:99:30` |
| **APK Binary Checksum (SHA-256)** | `a9cb7d7da8c4b4858bfdb6440ed4389abf35bde1d36788eff94b2df59d419634` |
| **GitHub Releases** | [DroidSentinel Releases](https://github.com/iamkuruphere-sudo/DroidSentinel/releases) |
| **Official Ecosystem** | [Fullstop Solution Mobile & Desktop Suites](https://www.fullstopsolution.in) |

---

## Checks Included

### 1. OS & Firmware Integrity Posture
* **Multi-Vector Root Detection**: Scans 14 known superuser execution paths (`/sbin/su`, `/system/bin/su`, `/data/adb/ksu`, `/data/adb/magisk`, etc.), checks `su` binary execution in local environment, audits Magisk/KernelSU/APatch package presence and mount namespace isolation.
* **SELinux Enforcement**: Queries kernel status to ensure SELinux is operating in mandatory `Enforcing` mode rather than `Permissive` or `Disabled`.
* **Build Integrity**: Analyzes OS build signature tags for developer or custom ROM `test-keys`.
* **Debug Interfaces**: Audits USB Debugging (`ADB_ENABLED`) and Wireless ADB state.
* **Hardware Keystore & StrongBox**: Validates cryptographic binding to discrete hardware secure elements (StrongBox HSM / TEE).
* **Keyguard Security**: Verifies screen lock authentication (Biometrics, PIN, Password).

### 2. Application & Sideload Auditing
* **Sideload Origin Tracking**: Differentiates official store installs (Google Play, Samsung Galaxy Store, F-Droid) from unverified sideloads (web browsers, file managers, local droppers).
* **High-Risk Permission Clustering**:
  * Screen Overlay / Tapjacking: `SYSTEM_ALERT_WINDOW`
  * Keystroke & Content Scraping: `BIND_ACCESSIBILITY_SERVICE`
  * OTP / SMS Exfiltration Pattern: `READ_SMS` / `RECEIVE_SMS` + `INTERNET`
  * Dropper / Secondary Payload Execution: `REQUEST_INSTALL_PACKAGES`
* **Social Engineering Detection**: Identifies rogue packages masquerading as system or carrier updates (`system update`, `security patch`, `oneui update`).
* **Debuggable Production Apps**: Detects third-party apps compiled with `android:debuggable="true"`.
* **Target SDK Deprecation**: Flags applications targeting obsolete Android runtimes to evade modern runtime permission constraints.

### 3. Storage & Download Threat Inspection
* **OpenXML Macro Analysis**: Performs ZIP inspection of Word, Excel, and PowerPoint documents (`.docm`, `.xlsm`, `.pptm`, etc.) to isolate weaponized `vbaProject.bin` or `vbaData.xml` macros.
* **Script & Autorun Vectors**: Flags dangerous executable scripts (`.vbs`, `.bat`, `.cmd`, `.ps1`, `autorun.inf`).
* **Deceptive Double Extensions**: Detects masquerading payloads (`.pdf.apk`, `.jpg.apk`).
* **Unverified Standalone APKs**: Inspects downloaded installation packages for archive integrity and package names.

### 4. Network & Link Phishing Defense
* **Transport Encryption**: Audits Wi-Fi encryption status (WPA2/WPA3), active VPN tunnels (`TRANSPORT_VPN`), and captive portal interception.
* **Private DNS (DNS-over-TLS)**: Detects whether device DNS queries are protected against ISP/LAN eavesdropping.
* **Interactive Phishing Heuristic Engine**:
  * Insecure HTTP cleartext warnings.
  * Deceptive `@` redirect syntax detection (`https://bank.com@phish.xyz`).
  * Raw numeric IPv4/IPv6 hostname detection.
  * Punycode / IDN homograph attack vectors (`xn--`).
  * URL shortener expansion flags (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
  * Brand spoofing subdomain analysis (`paypal.com.account-verify.xyz`).

### 5. Real-Time Sideload Monitoring
* Background `InstallMonitorReceiver` dynamically alerts the user when a newly installed application holds privileged overlay or accessibility permissions or arrives from an unverified sideload origin.

### 6. Standardized JSON Evidence Export
* Exports a complete point-in-time security audit report adhering to Fullstop Solution evidence standards, allowing developers and security auditors to export findings via the Android Sharesheet or ingest into SIEM / compliance pipelines.

---

## Technical Architecture

```
com.fullstopsolution.droidsentinel/
├── MainActivity.kt                      # Edge-to-edge Compose host & coroutine lifecycle
├── auditor/
│   ├── IntegrityAuditor.kt             # Kernel, Root, SELinux & Keystore checks
│   ├── AppThreatAuditor.kt             # Package inventory, sideload & permission clusters
│   ├── StorageInspector.kt             # Scoped storage, VBA macro & script inspection
│   └── NetworkAuditor.kt               # VPN, Private DNS & link phishing heuristic engine
├── receiver/
│   └── InstallMonitorReceiver.kt       # Real-time package installation security broadcast
├── export/
│   └── EvidenceExporter.kt             # Fullstop Solution standard JSON evidence generation
├── model/
│   └── SecurityModels.kt               # Structured findings, severity & assessment schema
└── ui/
    ├── screens/
    │   ├── DashboardScreen.kt          # Health gauge (0-100), quick stats & findings
    │   └── DetailTabs.kt               # Categorized Integrity, Apps, Storage & Network tabs
    └── theme/                          # Cyber Obsidian & Electric Cyan Material 3 Theme
```

---

## Building from Source

### Prerequisites
* JDK 17+ or OpenJDK 25 (e.g. bundled in Android Studio)
* Android SDK Platform 37 & Build-Tools 36.0.0+

### Build Commands
```bash
# Clone the repository
git clone https://github.com/iamkuruphere-sudo/DroidSentinel.git
cd DroidSentinel

# Build debug APK
./gradlew assembleDebug

# Build and sign release APK
./gradlew assembleRelease
```

The signed release APK will be generated at:
`app/build/outputs/apk/release/app-release.apk`

---

## Boundaries & Limitations

* Standard Android user-space security apps operate within the Linux application sandbox (`UID`). They cannot inspect the private sandboxed data directories of other apps or read raw hardware partitions.
* DroidSentinel collects evidence, not verdicts. Legitimate enterprise or developer software may utilize ADB debugging, sideloading, or background services.
* For hardware Knox attestation and verified boot flags, ensure Samsung Knox and Google Play Protect remain enabled.

---

## 🔒 Zero Telemetry Guarantee

100% on-device client execution. DroidSentinel contains zero analytics SDKs, zero advertising identifiers, zero tracking beacons, and zero outbound network transmission. All evidence reports remain strictly local until explicitly exported by the user.

© 2026 [Fullstop Solution](https://www.fullstopsolution.in). All rights reserved.
