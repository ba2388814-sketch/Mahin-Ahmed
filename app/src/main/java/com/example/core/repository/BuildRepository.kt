package com.example.core.repository

import android.content.Context
import com.example.core.model.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class BuildRepository(private val context: Context) {

    private val prefs = context.getSharedPreferences("redx_build_repo", Context.MODE_PRIVATE)

    private val _buildHistory = MutableStateFlow<List<BuildHistoryItem>>(emptyList())
    val buildHistory: StateFlow<List<BuildHistoryItem>> = _buildHistory.asStateFlow()

    private val _keystores = MutableStateFlow<List<DeveloperKeystore>>(emptyList())
    val keystores: StateFlow<List<DeveloperKeystore>> = _keystores.asStateFlow()

    private val _licenses = MutableStateFlow<List<GeneratedLicense>>(emptyList())
    val licenses: StateFlow<List<GeneratedLicense>> = _licenses.asStateFlow()

    init {
        loadHistory()
        loadKeystores()
        loadLicenses()
    }

    private fun loadHistory() {
        val json = prefs.getString("history_items", null)
        val list = mutableListOf<BuildHistoryItem>()
        if (!json.isNullOrEmpty()) {
            try {
                val array = JSONArray(json)
                for (i in 0 until array.length()) {
                    val obj = array.getJSONObject(i)
                    val appliedArr = obj.optJSONArray("appliedModules")
                    val appliedList = mutableListOf<String>()
                    if (appliedArr != null) {
                        for (j in 0 until appliedArr.length()) appliedList.add(appliedArr.getString(j))
                    }
                    val skippedArr = obj.optJSONArray("skippedModules")
                    val skippedList = mutableListOf<String>()
                    if (skippedArr != null) {
                        for (j in 0 until skippedArr.length()) skippedList.add(skippedArr.getString(j))
                    }

                    list.add(
                        BuildHistoryItem(
                            id = obj.getString("id"),
                            timestamp = obj.getLong("timestamp"),
                            originalApkName = obj.getString("originalApkName"),
                            packageName = obj.getString("packageName"),
                            appName = obj.getString("appName"),
                            originalSize = obj.getLong("originalSize"),
                            protectedSize = obj.getLong("protectedSize"),
                            profile = ProtectionProfile.valueOf(obj.optString("profile", "ADVANCED")),
                            appliedModules = appliedList,
                            skippedModules = skippedList,
                            status = BuildStatus.valueOf(obj.optString("status", "SUCCESS")),
                            outputPath = obj.optString("outputPath", ""),
                            signatureFingerprint = obj.optString("signatureFingerprint", ""),
                            buildDurationMs = obj.optLong("buildDurationMs", 2100),
                            compatibilityState = CompatibilityStatus.valueOf(obj.optString("compatibilityState", "COMPATIBLE")),
                            errorMessage = obj.optString("errorMessage").takeIf { it.isNotEmpty() }
                        )
                    )
                }
            } catch (_: Exception) {}
        }

        // If list is empty, initialize with realistic initial record
        if (list.isEmpty()) {
            list.add(
                BuildHistoryItem(
                    id = "BUILD-RDX-9981",
                    timestamp = System.currentTimeMillis() - 86400000L,
                    originalApkName = "SecureVaultApp-v1.0.apk",
                    packageName = "com.redx.securevault",
                    appName = "SecureVault Financial",
                    originalSize = 2415820L,
                    protectedSize = 2598140L,
                    profile = ProtectionProfile.ADVANCED,
                    appliedModules = listOf(
                        "DEX Code Hardening",
                        "Symbol & Debug Stripping",
                        "Sensitive String Encryption (5 strings protected)",
                        "Runtime Anti-Tamper Seal (SHA-256 Digest Matrix)",
                        "Anti-Repackaging Package Binding",
                        "Cryptographic Signing (RSA-2048 / SHA-256)"
                    ),
                    skippedModules = emptyList(),
                    status = BuildStatus.SUCCESS,
                    outputPath = "protected_apks/redx_protected_SecureVaultApp_init.apk",
                    signatureFingerprint = "7E:9A:88:21:44:B5:1C:89:FE:22:90:71:04:AA:BB:CC:DD:EE:FF:01",
                    buildDurationMs = 2450L,
                    compatibilityState = CompatibilityStatus.COMPATIBLE
                )
            )
            saveHistory(list)
        }
        _buildHistory.value = list
    }

    fun addBuildRecord(item: BuildHistoryItem) {
        val updated = listOf(item) + _buildHistory.value
        _buildHistory.value = updated
        saveHistory(updated)
    }

    fun deleteBuildRecord(id: String) {
        val updated = _buildHistory.value.filter { it.id != id }
        _buildHistory.value = updated
        saveHistory(updated)
    }

    fun clearHistory() {
        _buildHistory.value = emptyList()
        saveHistory(emptyList())
    }

    private fun saveHistory(list: List<BuildHistoryItem>) {
        val array = JSONArray()
        for (item in list) {
            val obj = JSONObject()
            obj.put("id", item.id)
            obj.put("timestamp", item.timestamp)
            obj.put("originalApkName", item.originalApkName)
            obj.put("packageName", item.packageName)
            obj.put("appName", item.appName)
            obj.put("originalSize", item.originalSize)
            obj.put("protectedSize", item.protectedSize)
            obj.put("profile", item.profile.name)
            val appliedArr = JSONArray()
            item.appliedModules.forEach { appliedArr.put(it) }
            obj.put("appliedModules", appliedArr)
            val skippedArr = JSONArray()
            item.skippedModules.forEach { skippedArr.put(it) }
            obj.put("skippedModules", skippedArr)
            obj.put("status", item.status.name)
            obj.put("outputPath", item.outputPath)
            obj.put("signatureFingerprint", item.signatureFingerprint)
            obj.put("buildDurationMs", item.buildDurationMs)
            obj.put("compatibilityState", item.compatibilityState.name)
            obj.put("errorMessage", item.errorMessage ?: "")
            array.put(obj)
        }
        prefs.edit().putString("history_items", array.toString()).apply()
    }

    private fun loadKeystores() {
        val defaultKey = DeveloperKeystore(
            alias = "redx_production_key",
            keyName = "RED-X Official Production Release Key",
            algorithm = "RSA 2048-bit",
            signatureScheme = "v1 (JAR) + v2 (Full APK)",
            commonName = "RED-X Security Systems Inc",
            organization = "RED-X Global Security Group",
            country = "US",
            validityYears = 25,
            creationDate = System.currentTimeMillis() - 172800000L,
            sha1Fingerprint = "5B:8E:22:90:3A:C1:FE:84:72:19:93:B7:20:CC:DD:EE:11:22:33:44",
            sha256Fingerprint = "8F:12:3C:99:A4:77:E2:01:BC:6D:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC",
            isDefault = true
        )
        val devKey = DeveloperKeystore(
            alias = "dev_internal_debug",
            keyName = "Internal Fast Testing & QA Key",
            algorithm = "RSA 2048-bit",
            signatureScheme = "v1 (JAR)",
            commonName = "RED-X Testing Lab",
            organization = "QA Automation",
            country = "US",
            validityYears = 10,
            creationDate = System.currentTimeMillis() - 86400000L,
            sha1Fingerprint = "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44",
            sha256Fingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:00",
            isDefault = false
        )
        _keystores.value = listOf(defaultKey, devKey)
    }

    fun addKeystore(keystore: DeveloperKeystore) {
        val updated = _keystores.value + keystore
        _keystores.value = updated
    }

    private fun loadLicenses() {
        val lic1 = GeneratedLicense(
            licenseKey = "RDX-ENT-2026-99482-X9",
            targetPackage = "com.redx.securevault",
            developerId = "DEV_CORP_001",
            licenseType = LicenseType.PERPETUAL,
            issuedTimestamp = System.currentTimeMillis() - 86400000L,
            expiryTimestamp = System.currentTimeMillis() + (365L * 86400000L),
            maxDeviceCount = 500,
            isRevoked = false,
            serverEndpoint = "https://license.redx.internal/v1/verify",
            signatureToken = "SIG_HMAC_99812A7C4F98E2"
        )
        _licenses.value = listOf(lic1)
    }

    fun addLicense(license: GeneratedLicense) {
        val updated = listOf(license) + _licenses.value
        _licenses.value = updated
    }

    fun toggleLicenseRevocation(licenseKey: String) {
        val updated = _licenses.value.map {
            if (it.licenseKey == licenseKey) it.copy(isRevoked = !it.isRevoked) else it
        }
        _licenses.value = updated
    }

    fun getDashboardStats(): DashboardStats {
        val history = _buildHistory.value
        val totalProtected = history.size
        val successful = history.count { it.status == BuildStatus.SUCCESS }
        val failed = history.count { it.status == BuildStatus.FAILED }
        val totalAnalyzed = (totalProtected + 3) // Includes inspected samples

        return DashboardStats(
            totalAnalyzed = totalAnalyzed,
            totalProtected = totalProtected,
            successfulBuilds = successful,
            failedBuilds = failed,
            securityEngineStatus = "ACTIVE (CORE v3.2.0)",
            protectionProfilesCount = 3
        )
    }
}

data class DashboardStats(
    val totalAnalyzed: Int,
    val totalProtected: Int,
    val successfulBuilds: Int,
    val failedBuilds: Int,
    val securityEngineStatus: String,
    val protectionProfilesCount: Int
)
