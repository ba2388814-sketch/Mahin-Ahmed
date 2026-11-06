package com.example.core.model

data class BuildHistoryItem(
    val id: String,
    val timestamp: Long,
    val originalApkName: String,
    val packageName: String,
    val appName: String,
    val originalSize: Long,
    val protectedSize: Long,
    val profile: ProtectionProfile,
    val appliedModules: List<String>,
    val skippedModules: List<String>,
    val status: BuildStatus,
    val outputPath: String,
    val backupPath: String = "",
    val signatureFingerprint: String,
    val buildDurationMs: Long,
    val compatibilityState: CompatibilityStatus,
    val errorMessage: String? = null,
    val originalAppPreserved: Boolean = true,
    val functionalityVerified: Boolean = true,
    val protectionStatusVerified: Boolean = true,
    val signatureStatusVerified: Boolean = true,
    val compatibilityPassed: Boolean = true,
    val crashTestPassed: Boolean = true,
    val integrityCheckPassed: Boolean = true,

    // 10 Security Dashboard Status Indicators
    // Values: PROTECTED, PARTIALLY PROTECTED, FAILED, NOT SUPPORTED
    val multiDexProtectionStatus: String = "PROTECTED",
    val dexObfuscationStatus: String = "PROTECTED",
    val resourceProtectionStatus: String = "PROTECTED",
    val manifestIntegrityStatus: String = "PROTECTED",
    val assetIntegrityStatus: String = "PROTECTED",
    val nativeLibIntegrityStatus: String = "PROTECTED",
    val apkSignatureStatus: String = "PROTECTED",
    val runtimeTamperStatus: String = "PROTECTED",
    val repackagingDetectionStatus: String = "PROTECTED",
    val finalApkIntegrityStatus: String = "PROTECTED",

    // Legacy compatibility fields
    val dexProtectionStatus: String = multiDexProtectionStatus,
    val codeObfuscationStatus: String = dexObfuscationStatus,
    val resourceShrinkingStatus: String = resourceProtectionStatus,

    // Quantitative metrics
    val allDexFiles: List<String> = emptyList(),
    val dexFilesProtected: Int = 1,
    val resourcesHardenedCount: Int = 0,
    val nativeLibsCount: Int = 0,
    val assetsProtectedCount: Int = 0,
    val debugSymbolsStrippedCount: Int = 0,
    val sensitiveStringsProtectedCount: Int = 0
)

enum class BuildStatus {
    SUCCESS,
    FAILED,
    IN_PROGRESS
}

data class ProtectionStepProgress(
    val stepIndex: Int,
    val stepName: String,
    val description: String,
    val progress: Float, // 0f to 1f
    val isCompleted: Boolean = false,
    val error: String? = null
)
