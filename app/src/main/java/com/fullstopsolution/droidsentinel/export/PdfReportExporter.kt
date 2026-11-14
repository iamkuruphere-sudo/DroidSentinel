package com.fullstopsolution.droidsentinel.export

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import androidx.core.content.FileProvider
import com.fullstopsolution.droidsentinel.model.CompleteSecurityAssessment
import java.io.File

object PdfReportExporter {
    fun exportToPdf(context: Context, assessment: CompleteSecurityAssessment): File {
        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val reportFile = File(reportsDir, "DroidSentinel-Report-${assessment.timestamp}.pdf")
        val document = PdfDocument()
        try {
            val writer = ReportWriter(document)
            writer.heading("DroidSentinel Security Report", 22f, ACCENT)
            writer.paragraph("Generated ${assessment.timestampIso}", 10f, MUTED)
            writer.paragraph(
                "${assessment.deviceManufacturer} ${assessment.deviceModel} | Android ${assessment.androidVersion} | Patch ${assessment.securityPatch}",
                11f,
                BODY
            )
            writer.section("Overall posture")
            writer.paragraph("Score: ${assessment.overallScore}/100 | Status: ${assessment.overallStatus}", 14f, BODY, bold = true)

            writer.section("Audit summary")
            writer.paragraph(
                "Integrity: ${if (assessment.integrity.isRooted) "root indicators detected" else "no root indicators"}; SELinux ${assessment.integrity.selinuxMode}; USB debugging ${if (assessment.integrity.isAdbEnabled) "on" else "off"}.",
                11f,
                BODY
            )
            writer.paragraph(
                "Applications: ${assessment.appAudit.totalAppsScanned} scanned, ${assessment.appAudit.highRiskApps.size} high risk, ${assessment.appAudit.sideloadedApps.size} sideloaded.",
                11f,
                BODY
            )
            writer.paragraph(
                "Storage: ${assessment.storageAudit.filesScannedCount} files scanned, ${assessment.storageAudit.threatsFound.size} threats found.",
                11f,
                BODY
            )
            writer.paragraph(
                "Network: ${assessment.networkAudit.connectionType}; VPN ${if (assessment.networkAudit.isVpnActive) "active" else "inactive"}; strict Private DNS ${if (assessment.networkAudit.isPrivateDnsActive) "configured" else "not configured"}",
                11f,
                BODY
            )

            if (assessment.appAudit.highRiskApps.isNotEmpty()) {
                writer.section("High-risk applications")
                assessment.appAudit.highRiskApps.forEach { app ->
                    writer.paragraph("${app.appName} (${app.packageName}) | risk ${app.riskScore}", 11f, BODY, bold = true)
                    app.riskFindings.forEach { finding ->
                        writer.paragraph("${finding.severity}: ${finding.title}", 10f, MUTED, indent = 14f)
                    }
                }
            }

            if (assessment.storageAudit.threatsFound.isNotEmpty()) {
                writer.section("Storage threats")
                assessment.storageAudit.threatsFound.forEach { threat ->
                    writer.paragraph("${threat.severity}: ${threat.fileName} | ${threat.threatType}", 11f, BODY)
                    writer.paragraph(threat.details, 10f, MUTED, indent = 14f)
                }
            }

            writer.section("Security findings (${assessment.allFindings.size})")
            assessment.allFindings.forEach { finding ->
                writer.paragraph("${finding.severity}: ${finding.title}", 11f, BODY, bold = true)
                writer.paragraph(finding.description, 10f, MUTED, indent = 14f)
                if (finding.recommendation.isNotBlank()) {
                    writer.paragraph("Recommendation: ${finding.recommendation}", 10f, ACCENT_DARK, indent = 14f)
                }
            }
            writer.paragraph("Generated locally by DroidSentinel. This report is shared only when you choose a destination.", 9f, MUTED)
            writer.finish()
            reportFile.outputStream().use(document::writeTo)
        } finally {
            document.close()
        }
        return reportFile
    }

    fun sharePdfReport(context: Context, file: File, assessment: CompleteSecurityAssessment) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/pdf"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "DroidSentinel Security Report")
            putExtra(Intent.EXTRA_TEXT, "On-device security audit report generated ${assessment.timestampIso}.")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share security report").apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        })
    }

    private class ReportWriter(private val document: PdfDocument) {
        private var pageNumber = 0
        private var page: PdfDocument.Page? = null
        private var cursorY = TOP
        private val canvas get() = requireNotNull(page).canvas

        init {
            startPage()
        }

        fun heading(text: String, size: Float, color: Int) {
            paragraph(text, size, color, bold = true, gap = 8f)
        }

        fun section(text: String) {
            paragraph(text, 14f, ACCENT, bold = true, gap = 5f)
        }

        fun paragraph(text: String, size: Float, color: Int, bold: Boolean = false, indent: Float = 0f, gap: Float = 7f) {
            val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                this.color = color
                textSize = size
                typeface = Typeface.create("sans-serif", if (bold) Typeface.BOLD else Typeface.NORMAL)
            }
            val availableWidth = PAGE_WIDTH - MARGIN * 2 - indent
            val lines = wrapText(text, paint, availableWidth)
            val lineHeight = size * 1.35f
            lines.forEach { line ->
                ensureSpace(lineHeight)
                canvas.drawText(line, MARGIN + indent, cursorY, paint)
                cursorY += lineHeight
            }
            cursorY += gap
        }

        fun finish() {
            finishPage()
        }

        private fun wrapText(text: String, paint: Paint, maxWidth: Float): List<String> {
            val lines = mutableListOf<String>()
            var line = ""
            fun addLongWord(word: String) {
                var chunk = ""
                word.forEach { character ->
                    val next = chunk + character
                    if (chunk.isNotEmpty() && paint.measureText(next) > maxWidth) {
                        lines.add(chunk)
                        chunk = character.toString()
                    } else {
                        chunk = next
                    }
                }
                line = chunk
            }

            text.split(Regex("\\s+")).forEach { word ->
                val candidate = if (line.isEmpty()) word else "$line $word"
                if (paint.measureText(candidate) <= maxWidth) {
                    line = candidate
                } else {
                    if (line.isNotEmpty()) {
                        lines.add(line)
                        line = ""
                    }
                    addLongWord(word)
                }
            }
            if (line.isNotEmpty()) lines.add(line)
            return lines
        }

        private fun ensureSpace(lineHeight: Float) {
            if (cursorY + lineHeight > PAGE_HEIGHT - BOTTOM) {
                finishPage()
                startPage()
            }
        }

        private fun startPage() {
            pageNumber++
            val pageInfo = PdfDocument.PageInfo.Builder(PAGE_WIDTH.toInt(), PAGE_HEIGHT.toInt(), pageNumber).create()
            page = document.startPage(pageInfo)
            cursorY = TOP
            val headerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = ACCENT
                textSize = 9f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            }
            canvas.drawText("DROIDSENTINEL  |  SECURITY AUDIT", MARGIN, 30f, headerPaint)
            canvas.drawLine(MARGIN, 40f, PAGE_WIDTH - MARGIN, 40f, Paint().apply {
                color = RULE
                strokeWidth = 1f
            })
        }

        private fun finishPage() {
            val footerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = MUTED
                textSize = 9f
                textAlign = Paint.Align.RIGHT
            }
            canvas.drawText("Page $pageNumber", PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 24f, footerPaint)
            document.finishPage(requireNotNull(page))
            page = null
        }
    }

    private const val PAGE_WIDTH = 595f
    private const val PAGE_HEIGHT = 842f
    private const val MARGIN = 42f
    private const val TOP = 64f
    private const val BOTTOM = 48f
    private val ACCENT = Color.rgb(0, 100, 120)
    private val ACCENT_DARK = Color.rgb(0, 90, 90)
    private val BODY = Color.rgb(25, 35, 48)
    private val MUTED = Color.rgb(75, 88, 104)
    private val RULE = Color.rgb(210, 220, 228)
}
