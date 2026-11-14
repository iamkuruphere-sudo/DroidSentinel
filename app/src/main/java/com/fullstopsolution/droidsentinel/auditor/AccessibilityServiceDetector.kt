package com.fullstopsolution.droidsentinel.auditor

internal object AccessibilityServiceDetector {
    private const val ACCESSIBILITY_BIND_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"

    fun declaresAccessibilityBinding(servicePermissions: Iterable<String?>?): Boolean =
        servicePermissions?.any { it == ACCESSIBILITY_BIND_PERMISSION } == true
}
