package com.fullstopsolution.droidsentinel.auditor

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessibilityServiceDetectorTest {
    @Test
    fun detectsAccessibilityPermissionDeclaredByService() {
        assertTrue(
            AccessibilityServiceDetector.declaresAccessibilityBinding(
                listOf(null, "android.permission.BIND_ACCESSIBILITY_SERVICE")
            )
        )
    }

    @Test
    fun ignoresUnrelatedOrMissingServicePermissions() {
        assertFalse(AccessibilityServiceDetector.declaresAccessibilityBinding(listOf(null, "other.permission")))
        assertFalse(AccessibilityServiceDetector.declaresAccessibilityBinding(null))
    }
}
