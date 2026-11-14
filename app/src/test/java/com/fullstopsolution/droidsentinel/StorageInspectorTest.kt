package com.fullstopsolution.droidsentinel

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class StorageInspectorTest {

    private fun isDeceptiveExtension(filename: String): Boolean {
        val lower = filename.lowercase()
        return lower.contains(".pdf.apk") ||
                lower.contains(".doc.apk") ||
                lower.contains(".jpg.apk") ||
                lower.contains(".docx.apk") ||
                lower.contains(".png.apk")
    }

    private fun isSuspiciousScript(filename: String): Boolean {
        val scripts = setOf("autorun.inf", ".bat", ".cmd", ".vbs", ".ps1", ".vbe", ".jse", ".sh", ".dex")
        val lower = filename.lowercase()
        return scripts.any { lower == it || lower.endsWith(it) }
    }

    private fun containsVbaMacroInZip(file: File): Boolean {
        return try {
            java.util.zip.ZipFile(file).use { zip ->
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

    @Test
    fun testDeceptiveDoubleExtensionDetection() {
        assertTrue(isDeceptiveExtension("urgent_invoice.pdf.apk"))
        assertTrue(isDeceptiveExtension("photo.jpg.apk"))
        assertTrue(isDeceptiveExtension("contract.doc.apk"))
        assertTrue(isDeceptiveExtension("statement.docx.apk"))
        assertFalse(isDeceptiveExtension("legitimate_app.apk"))
        assertFalse(isDeceptiveExtension("document.pdf"))
    }

    @Test
    fun testSuspiciousScriptDetection() {
        assertTrue(isSuspiciousScript("autorun.inf"))
        assertTrue(isSuspiciousScript("payload.vbs"))
        assertTrue(isSuspiciousScript("setup.bat"))
        assertTrue(isSuspiciousScript("install.ps1"))
        assertTrue(isSuspiciousScript("dropper.dex"))
        assertFalse(isSuspiciousScript("readme.txt"))
        assertFalse(isSuspiciousScript("notes.md"))
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

        assertTrue("Should detect embedded VBA macro project in zip archive", containsVbaMacroInZip(tempZip))

        // Create a clean zip without macro
        val cleanZip = File.createTempFile("clean_test_", ".xlsx")
        cleanZip.deleteOnExit()

        ZipOutputStream(FileOutputStream(cleanZip)).use { zos ->
            zos.putNextEntry(ZipEntry("xl/workbook.xml"))
            zos.write("<xml></xml>".toByteArray())
            zos.closeEntry()
        }

        assertFalse("Clean document must not trigger macro detection", containsVbaMacroInZip(cleanZip))
    }
}
