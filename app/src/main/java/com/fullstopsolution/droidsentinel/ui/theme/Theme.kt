package com.fullstopsolution.droidsentinel.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = CyanAccent,
    onPrimary = CyberObsidian,
    primaryContainer = CyberCardElevated,
    onPrimaryContainer = CyanAccent,
    secondary = MintEmerald,
    onSecondary = CyberObsidian,
    background = CyberObsidian,
    onBackground = TextPrimary,
    surface = CyberCard,
    onSurface = TextPrimary,
    surfaceVariant = CyberCardElevated,
    onSurfaceVariant = TextSecondary,
    outline = CyberBorder,
    error = StatusCritical,
    onError = TextPrimary
)

@Composable
fun DroidSentinelTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography,
        content = content
    )
}
