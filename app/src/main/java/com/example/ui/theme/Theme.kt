package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val RedXDarkColorScheme = darkColorScheme(
    primary = ElectricRed,
    onPrimary = TextPrimary,
    primaryContainer = ElectricRedDark,
    onPrimaryContainer = TextPrimary,
    secondary = NeonCyan,
    onSecondary = CyberBlack,
    secondaryContainer = CyberPanelElevated,
    onSecondaryContainer = NeonCyan,
    tertiary = CyberBlue,
    onTertiary = TextPrimary,
    background = CyberBlack,
    onBackground = TextPrimary,
    surface = CyberPanel,
    onSurface = TextPrimary,
    surfaceVariant = CyberPanelElevated,
    onSurfaceVariant = TextSecondary,
    outline = CyberPanelBorder,
    outlineVariant = CyberPanelBorder.copy(alpha = 0.5f),
    error = ElectricRed,
    onError = TextPrimary
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true,
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = RedXDarkColorScheme,
        typography = RedXTypography,
        content = content
    )
}
