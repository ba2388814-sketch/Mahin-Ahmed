package com.example.core.model

data class ApkAnalysisResult(
    val fileName: String,
    val filePath: String,
    val fileSize: Long,
    val packageName: String,
    val appName: String,
    val versionCode: Long,
    val versionName: String,
    val minSdkVersion: Int,
    val targetSdkVersion: Int,
    val isDebuggable: Boolean,
    val allowsBackup: Boolean,
    val dexFiles: List<DexInfo>,
    val nativeLibs: List<NativeLibInfo>,
    val permissions: List<PermissionItem>,
    val activities: List<String>,
    val services: List<String>,
    val receivers: List<String>,
    val providers: List<String>,
    val signatureInfo: SignatureInfo?,
    val existingProtection: ExistingProtectionInfo,
    val resourceSummary: ResourceSummary,
    val totalClasses: Int,
    val totalMethods: Int,
    val totalFields: Int,
    val totalStrings: Int,
    val architectures: List<String>,
    val reflectionCount: Int,
    val jniMethodCount: Int,
    val sensitiveStringCandidates: List<String>
)

data class DexInfo(
    val fileName: String,
    val size: Long,
    val version: String,
    val checksum: Long,
    val sha1: String,
    val classCount: Int,
    val methodCount: Int,
    val fieldCount: Int,
    val stringCount: Int,
    val timestamp: Long = 0L,
    val formattedTimestamp: String = "",
    val formattedSize: String = ""
)

data class NativeLibInfo(
    val abi: String,
    val libName: String,
    val size: Long,
    val isElf: Boolean,
    val is64Bit: Boolean,
    val isStripped: Boolean
)

data class PermissionItem(
    val name: String,
    val protectionLevel: String, // Normal, Dangerous, Signature
    val description: String,
    val isSensitive: Boolean
)

data class SignatureInfo(
    val hasV1Scheme: Boolean,
    val hasV2Scheme: Boolean,
    val hasV3Scheme: Boolean,
    val signerSubject: String,
    val signerIssuer: String,
    val serialNumber: String,
    val validFrom: String,
    val validTo: String,
    val signatureAlgorithm: String,
    val sha1Fingerprint: String,
    val sha256Fingerprint: String
)

data class ExistingProtectionInfo(
    val isAlreadyProtected: Boolean,
    val detectedTools: List<String>,
    val details: String
)

data class ResourceSummary(
    val totalEntries: Int,
    val hasResourcesArsc: Boolean,
    val assetCount: Int,
    val drawableCount: Int,
    val layoutCount: Int
)
