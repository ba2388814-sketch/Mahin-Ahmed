package com.example.core.model

enum class CompatibilityStatus(val label: String) {
    COMPATIBLE("COMPATIBLE"),
    COMPATIBLE_WITH_WARNINGS("COMPATIBLE WITH WARNINGS"),
    UNSUPPORTED("UNSUPPORTED")
}

data class CompatibilityReport(
    val status: CompatibilityStatus,
    val score: Int, // 0 - 100
    val checks: List<CompatibilityCheckItem>,
    val autoAppliedRules: List<String>,
    val skippedModules: List<SkippedModuleReason>,
    val summary: String
)

data class CompatibilityCheckItem(
    val title: String,
    val category: String,
    val isPassed: Boolean,
    val severity: RiskSeverity,
    val message: String
)

enum class RiskSeverity {
    NONE,
    INFO,
    WARNING,
    CRITICAL
}

data class SkippedModuleReason(
    val module: SecurityModule,
    val reason: String
)
