package com.example.core.model

data class DeveloperKeystore(
    val alias: String,
    val keyName: String,
    val algorithm: String = "RSA 2048-bit",
    val signatureScheme: String = "v1 (JAR) + v2 (Full APK)",
    val commonName: String,
    val organization: String,
    val country: String,
    val validityYears: Int,
    val creationDate: Long,
    val sha1Fingerprint: String,
    val sha256Fingerprint: String,
    val isDefault: Boolean = false
)
