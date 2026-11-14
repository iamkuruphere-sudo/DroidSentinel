package com.fullstopsolution.droidsentinel

import com.fullstopsolution.droidsentinel.auditor.StorageInspector
import com.fullstopsolution.droidsentinel.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class StorageInspectorTest {

    @Test
    fun testDeceptiveDoubleExtensionDetection() {
        assertTrue(StorageInspector.isDeceptiveExtension("urgent_invoice.pdf.apk"))
        assertTrue(StorageInspector.isDeceptiveExtension("photo.jpg.apk"))
        assertTrue(StorageInspector.isDeceptiveExtension("contract.doc.apk"))
        assertTrue(StorageInspector.isDeceptiveExtension("statement.docx.apk"))
        assertTrue(StorageInspector.isDeceptiveExtension("budget.xlsx.apk"))
        assertFalse(StorageInspector.isDeceptiveExtension("legitimate_app.apk"))
        assertFalse(StorageInspector.isDeceptiveExtension("document.pdf"))
    }

    @Test
    fun testSuspiciousScriptDetection() {
        assertTrue(StorageInspector.isSuspiciousScript("autorun.inf"))
        assertTrue(StorageInspector.isSuspiciousScript("payload.vbs"))
        assertTrue(StorageInspector.isSuspiciousScript("setup.bat"))
        assertTrue(StorageInspector.isSuspiciousScript("install.ps1"))
        assertTrue(StorageInspector.isSuspiciousScript("dropper.dex"))
        assertFalse(StorageInspector.isSuspiciousScript("readme.txt"))
        assertFalse(StorageInspector.isSuspiciousScript("notes.md"))
    }

    @Test
    fun testVbaMacroZipDetection() {
        // Create a temporary zip with a vbaProject.bin inside
        val tempZip = File.createTempFile("macro_test_", ".xlsm")
        tempZip.deleteOnExit()

        ZipOutputStream(FileOutputStream(tempZip)).use { zos ->
            zos.putNextEntry(ZipEntry("xl/vbaProject.bin"))
            zos.write(byteArrayOf(0x01, 0x02, 0x03))
            zos.closeEntry()
            zos.putNextEntry(ZipEntry("[Content_Types].xml"))
            zos.write("<xml></xml>".toByteArray())
            zos.closeEntry()
        }

        assertTrue("Should detect embedded VBA macro project in zip archive", StorageInspector.containsVbaMacro(tempZip))

        // Create a clean zip without macro
        val cleanZip = File.createTempFile("clean_test_", ".xlsx")
        cleanZip.deleteOnExit()

        ZipOutputStream(FileOutputStream(cleanZip)).use { zos ->
            zos.putNextEntry(ZipEntry("xl/workbook.xml"))
            zos.write("<xml></xml>".toByteArray())
            zos.closeEntry()
        }

        assertFalse("Clean document must not trigger macro detection", StorageInspector.containsVbaMacro(cleanZip))
    }

    @Test
    fun testAuditDirectoryEndToEndWithActualFiles() {
        val tempDir = File.createTempFile("droidsentinel_test_dir_", "").apply {
            delete()
            mkdirs()
        }
        tempDir.deleteOnExit()

        try {
            // 1. Clean file
            val cleanFile = File(tempDir, "readme.txt")
            cleanFile.writeText("Clean document")

            // 2. Deceptive double extension
            val deceptiveFile = File(tempDir, "invoice.pdf.apk")
            deceptiveFile.writeBytes(byteArrayOf(0x50, 0x4B, 0x03, 0x04))

            // 3. Suspicious script
            val scriptFile = File(tempDir, "autorun.inf")
            scriptFile.writeText("[autorun]\nopen=malware.exe")

            // 4. Macro file
            val macroFile = File(tempDir, "financials.xlsm")
            ZipOutputStream(FileOutputStream(macroFile)).use { zos ->
                zos.putNextEntry(ZipEntry("xl/vbaProject.bin"))
                zos.write("VBA MACRO PAYLOAD".toByteArray())
                zos.closeEntry()
            }

            val result = StorageInspector.auditDirectory(context = null, directory = tempDir)

            assertEquals(4, result.filesScannedCount)
            assertEquals(3, result.threatsFound.size)

            val threatTypes = result.threatsFound.map { it.threatType }.toSet()
            assertTrue(threatTypes.contains("DECEPTIVE_EXTENSION"))
            assertTrue(threatTypes.contains("AUTORUN_SCRIPT"))
            assertTrue(threatTypes.contains("EMBEDDED_VBA_MACRO"))

            result.threatsFound.forEach { threat ->
                assertNotNull("SHA-256 hash must be computed", threat.sha256Hash)
                assertEquals(64, threat.sha256Hash!!.length)
            }

            assertTrue("Must contain a critical finding", result.findings.any { it.severity == Severity.CRITICAL })
        } finally {
            tempDir.deleteRecursively()
        }
    }
}
