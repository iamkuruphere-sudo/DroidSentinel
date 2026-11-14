package com.fullstopsolution.droidsentinel.auditor

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import com.fullstopsolution.droidsentinel.model.ActionType
import com.fullstopsolution.droidsentinel.model.Finding
import com.fullstopsolution.droidsentinel.model.FindingCategory
import com.fullstopsolution.droidsentinel.model.Severity
import com.fullstopsolution.droidsentinel.model.StorageAuditResult
import com.fullstopsolution.droidsentinel.model.StorageThreatInfo
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

object StorageInspector {

    private val SUSPICIOUS_SCRIPTS = setOf(
        "autorun.inf", ".bat", ".cmd", ".vbs", ".ps1", ".vbe", ".jse", ".sh", ".dex"
    )
    private val OFFICE_EXTENSIONS = setOf(
        ".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".dotm", ".xltm"
    )

    fun audit(
        context: Context,
        onProgress: ((scanned: Int, total: Int, currentFile: String) -> Unit)? = null
    ): StorageAuditResult {
        val hasAccess = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }

        val threats = mutableListOf<StorageThreatInfo>()
        val findings = mutableListOf<Finding>()
        var count = 0

        if (!hasAccess) {
            findings.add(
                Finding(
                    title = "Scoped Storage Active",
                    description = "Full filesystem access to /Download is restricted by the Android Linux sandbox.",
                    severity = Severity.INFO,
                    recommendation = "Grant All Files Access to perform deep inspection of downloads.",
                    actionType = ActionType.MANAGE_STORAGE,
                    actionLabel = "Grant File Access",
                    category = FindingCategory.STORAGE
                )
            )
            return StorageAuditResult(0, emptyList(), false, findings)
        }

        val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (downloadDir != null && downloadDir.exists() && downloadDir.isDirectory) {
            val files = downloadDir.listFiles() ?: emptyArray()
            val totalFiles = files.size
            count = totalFiles

            var scannedIndex = 0
            for (file in files) {
                scannedIndex++
                onProgress?.invoke(scannedIndex, totalFiles, file.name)

                if (!file.isFile) continue

                val lower = file.name.lowercase()

                // 1. Deceptive double extensions
                if (lower.contains(".pdf.apk") ||
                    lower.contains(".doc.apk") ||
                    lower.contains(".jpg.apk") ||
                    lower.contains(".docx.apk") ||
                    lower.contains(".png.apk")
                ) {
                    val hash = computeSha256(file)
                    threats.add(
                        StorageThreatInfo(
                            fileName = file.name,
                            filePath = file.absolutePath,
                            fileSize = file.length(),
                            threatType = "DECEPTIVE_EXTENSION",
                            details = "Payload employs deceptive double extension (.pdf.apk / .jpg.apk) to conceal executable binary. SHA-256: ${hash.take(16)}...",
                            severity = Severity.CRITICAL,
                            sha256Hash = hash
                        )
                    )
                    continue
                }

                // 2. Scripts / Autorun
                if (SUSPICIOUS_SCRIPTS.any { lower == it || lower.endsWith(it) }) {
                    val hash = computeSha256(file)
                    threats.add(
                        StorageThreatInfo(
                            fileName = file.name,
                            filePath = file.absolutePath,
                            fileSize = file.length(),
                            threatType = "AUTORUN_SCRIPT",
                            details = "Executable script or autorun configuration detected in user storage. SHA-256: ${hash.take(16)}...",
                            severity = Severity.WARNING,
                            sha256Hash = hash
                        )
                    )
                    continue
                }

                // 3. Office documents with embedded VBA macros
                if (OFFICE_EXTENSIONS.any { lower.endsWith(it) }) {
                    if (containsVbaMacro(file)) {
                        val hash = computeSha256(file)
                        threats.add(
                            StorageThreatInfo(
                                fileName = file.name,
                                filePath = file.absolutePath,
                                fileSize = file.length(),
                                threatType = "EMBEDDED_VBA_MACRO",
                                details = "Embedded VBA macro binary (vbaProject.bin) detected inside document archive. SHA-256: ${hash.take(16)}...",
                                severity = Severity.CRITICAL,
                                sha256Hash = hash
                            )
                        )
                    }
                    continue
                }

                // 4. Downloaded APK payload
                if (lower.endsWith(".apk")) {
                    val threat = inspectApkFile(context, file)
                    if (threat != null) {
                        threats.add(threat)
                    }
                }
            }
        }

        if (threats.isNotEmpty()) {
            findings.add(
                Finding(
                    title = "${threats.size} Threat Vector(s) Found in Downloads",
                    description = "Detected embedded macros, scripts, or unverified update APK payloads.",
                    severity = Severity.CRITICAL,
                    recommendation = "Review and delete suspicious downloads from the Storage tab.",
                    category = FindingCategory.STORAGE
                )
            )
        } else {
            findings.add(
                Finding(
                    title = "Storage Directory Clean",
                    description = "Scanned $count files in /Download. No embedded macros or rogue update APKs identified.",
                    severity = Severity.SECURE,
                    category = FindingCategory.STORAGE
                )
            )
        }

        return StorageAuditResult(
            filesScannedCount = count,
            threatsFound = threats,
            isStorageAccessGranted = true,
            findings = findings
        )
    }

    private fun containsVbaMacro(file: File): Boolean {
        return try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                var entryCount = 0
                while (entries.hasMoreElements() && entryCount < 1000) {
                    val entry = entries.nextElement()
                    entryCount++
                    val name = entry.name.lowercase()
                    if (name.endsWith("vbaproject.bin") ||
                        name.endsWith("vbadata.xml") ||
                        name.contains("word/vbaproject.bin") ||
                        name.contains("xl/vbaproject.bin") ||
                        name.contains("ppt/vbaproject.bin")
                    ) {
                        return true
                    }
                }
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun inspectApkFile(context: Context, file: File): StorageThreatInfo? {
        val lower = file.name.lowercase()
        val isUpdateImpersonator = lower.contains("update") ||
                lower.contains("patch") ||
                lower.contains("firmware")

        val archiveInfo = try {
            context.packageManager.getPackageArchiveInfo(file.absolutePath, PackageManager.GET_META_DATA)
        } catch (_: Exception) {
            null
        }

        val pkgName = archiveInfo?.packageName ?: "Corrupt/Unparseable"
        val severity = if (isUpdateImpersonator) Severity.CRITICAL else Severity.WARNING
        val hash = computeSha256(file)

        return StorageThreatInfo(
            fileName = file.name,
            filePath = file.absolutePath,
            fileSize = file.length(),
            threatType = if (isUpdateImpersonator) "FAKE_UPDATE_APK" else "UNVERIFIED_APK_PAYLOAD",
            details = "Package: $pkgName. Unverified standalone APK in user downloads. Sideloading this APK bypasses Play Protect verification. SHA-256: ${hash.take(16)}...",
            severity = severity,
            sha256Hash = hash
        )
    }

    private fun computeSha256(file: File): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(8192)
            FileInputStream(file).use { fis ->
                var bytesRead = fis.read(buffer)
                while (bytesRead != -1) {
                    digest.update(buffer, 0, bytesRead)
                    bytesRead = fis.read(buffer)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            "unknown_hash"
        }
    }
}
