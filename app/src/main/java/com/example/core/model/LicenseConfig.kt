package com.example.core.model

data class GeneratedLicense(
    val licenseKey: String,
    val targetPackage: String,
    val developerId: String,
    val licenseType: LicenseType,
    val issuedTimestamp: Long,
    val expiryTimestamp: Long,
    val maxDeviceCount: Int,
    val isRevoked: Boolean,
    val serverEndpoint: String,
    val signatureToken: String
)

enum class LicenseType(val label: String) {
    PERPETUAL("Perpetual Enterprise"),
    ANNUAL_SUBSCRIPTION("Annual Subscription (365d)"),
    MONTHLY_SUBSCRIPTION("Monthly Subscription (30d)"),
    TRIAL_7_DAYS("Evaluation Trial (7d)"),
    NODE_LOCKED("Node-Locked Device ID")
}
