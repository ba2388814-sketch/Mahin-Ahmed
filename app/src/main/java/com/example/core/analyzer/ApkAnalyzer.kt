package com.example.core.analyzer

import android.content.Context
import android.net.Uri
import com.example.core.model.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.zip.ZipInputStream

class ApkAnalyzer(private val context: Context) {

    fun analyzeFile(file: File): ApkAnalysisResult {
        return file.inputStream().use { analyzeStream(it, file.name, file.absolutePath, file.length()) }
    }

    fun analyzeUri(uri: Uri, fileName: String): ApkAnalysisResult {
        val stream = context.contentResolver.openInputStream(uri)
            ?: throw IllegalStateException("Cannot open input stream for $uri")
        val tempFile = File(context.cacheDir, "temp_scan_${System.currentTimeMillis()}.apk")
        tempFile.outputStream().use { out -> stream.copyTo(out) }
        val result = tempFile.inputStream().use {
            analyzeStream(it, fileName, tempFile.absolutePath, tempFile.length())
        }
        return result
    }

    fun analyzeStream(inputStream: InputStream, fileName: String, filePath: String, fileSize: Long): ApkAnalysisResult {
        var manifestBytes: ByteArray? = null
        val dexList = mutableListOf<Triple<String, ByteArray, Long>>()
        val nativeLibs = mutableListOf<NativeLibInfo>()
        var certBytes: ByteArray? = null
        var totalZipEntries = 0
        var hasResourcesArsc = false
        var assetCount = 0
        var drawableCount = 0
        var layoutCount = 0

        val zip = ZipInputStream(inputStream)
        var entry = zip.nextEntry

        while (entry != null) {
            totalZipEntries++
            val name = entry.name

            when {
                name == "AndroidManifest.xml" -> {
                    manifestBytes = readEntryBytes(zip)
                }
                name.startsWith("classes") && name.endsWith(".dex") -> {
                    val bytes = readEntryBytes(zip)
                    val time = if (entry.time > 0L) entry.time else System.currentTimeMillis()
                    dexList.add(Triple(name, bytes, time))
                }
                name.startsWith("lib/") && name.endsWith(".so") -> {
                    val parts = name.split("/")
                    if (parts.size >= 3) {
                        val abi = parts[1]
                        val libName = parts[2]
                        val bytes = readEntryBytes(zip)
                        val libInfo = ElfParser.parse(abi, libName, bytes)
                        nativeLibs.add(libInfo)
                    }
                }
                name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")) -> {
                    certBytes = readEntryBytes(zip)
                }
                name == "resources.arsc" -> {
                    hasResourcesArsc = true
                }
                name.startsWith("assets/") -> {
                    assetCount++
                }
                name.startsWith("res/drawable") || name.startsWith("res/mipmap") -> {
                    drawableCount++
                }
                name.startsWith("res/layout") -> {
                    layoutCount++
                }
            }
            zip.closeEntry()
            entry = zip.nextEntry
        }

        // Parse Manifest
        val manifestData = manifestBytes?.let { AxmlParser(it).parse() } ?: AxmlParser.ManifestData(
            packageName = "com.sample.app",
            appName = fileName.substringBeforeLast('.'),
            versionCode = 1L,
            versionName = "1.0",
            minSdkVersion = 21,
            targetSdkVersion = 34,
            isDebuggable = false,
            allowsBackup = true,
            permissions = emptyList(),
            activities = listOf("com.sample.app.MainActivity"),
            services = emptyList(),
            receivers = emptyList(),
            providers = emptyList()
        )

        // Parse DEX files
        val dexInfos = mutableListOf<DexInfo>()
        var totalClasses = 0
        var totalMethods = 0
        var totalFields = 0
        var totalStrings = 0
        var totalReflection = 0
        var totalJni = 0
        val allSensitiveStrings = mutableListOf<String>()
        val allPackers = mutableListOf<String>()

        for ((dexName, bytes, time) in dexList) {
            val dexResult = DexParser(dexName, bytes, time).parse()
            dexInfos.add(dexResult.info)
            totalClasses += dexResult.info.classCount
            totalMethods += dexResult.info.methodCount
            totalFields += dexResult.info.fieldCount
            totalStrings += dexResult.info.stringCount
            totalReflection += dexResult.reflectionIndicators
            totalJni += dexResult.jniIndicators
            allSensitiveStrings.addAll(dexResult.sensitiveStrings)
            allPackers.addAll(dexResult.detectedPackers)
        }

        // Parse signature
        val sigInfo = certBytes?.let { CertParser.parse(it) } ?: SignatureInfo(
            hasV1Scheme = false,
            hasV2Scheme = false,
            hasV3Scheme = false,
            signerSubject = "Unsigned APK / Debug",
            signerIssuer = "None",
            serialNumber = "00",
            validFrom = "N/A",
            validTo = "N/A",
            signatureAlgorithm = "None",
            sha1Fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
            sha256Fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        )

        // Classify permissions
        val permissionItems = manifestData.permissions.map { permName ->
            val simple = permName.substringAfterLast('.')
            val isSensitive = simple.contains("CAMERA") ||
                    simple.contains("LOCATION") ||
                    simple.contains("RECORD_AUDIO") ||
                    simple.contains("READ_CONTACTS") ||
                    simple.contains("SMS") ||
                    simple.contains("STORAGE")
            PermissionItem(
                name = permName,
                protectionLevel = if (isSensitive) "Dangerous (Runtime)" else "Normal",
                description = getPermissionDescription(simple),
                isSensitive = isSensitive
            )
        }

        val architectures = nativeLibs.map { it.abi }.distinct().ifEmpty { listOf("Universal (No Native Code)") }

        val existingProtection = ExistingProtectionInfo(
            isAlreadyProtected = allPackers.isNotEmpty(),
            detectedTools = allPackers.distinct(),
            details = if (allPackers.isNotEmpty()) "Detected existing hardening: ${allPackers.joinToString(", ")}" else "No third-party packer detected."
        )

        var resolvedPackage = manifestData.packageName
        if (resolvedPackage.isBlank() || resolvedPackage == "com.app.unknown" || resolvedPackage == "com.sample.app") {
            // Attempt to derive package name from classes in primary DEX
            val primaryDex = dexList.find { it.first == "classes.dex" } ?: dexList.firstOrNull()
            if (primaryDex != null) {
                val dexText = String(primaryDex.second, Charsets.ISO_8859_1)
                val classRegex = Regex("""L([a-zA-Z]{2,10}/[a-zA-Z0-9_]{2,20}/[a-zA-Z0-9_]{2,25})/[a-zA-Z0-9_]+;""")
                val match = classRegex.find(dexText)
                if (match != null) {
                    val rawPkg = match.groupValues[1].replace('/', '.')
                    if (!rawPkg.startsWith("android.") && !rawPkg.startsWith("androidx.") && !rawPkg.startsWith("kotlin.")) {
                        resolvedPackage = rawPkg
                    }
                }
            }
        }

        return ApkAnalysisResult(
            fileName = fileName,
            filePath = filePath,
            fileSize = fileSize,
            packageName = resolvedPackage,
            appName = manifestData.appName,
            versionCode = manifestData.versionCode,
            versionName = manifestData.versionName,
            minSdkVersion = manifestData.minSdkVersion,
            targetSdkVersion = manifestData.targetSdkVersion,
            isDebuggable = manifestData.isDebuggable,
            allowsBackup = manifestData.allowsBackup,
            dexFiles = dexInfos,
            nativeLibs = nativeLibs,
            permissions = permissionItems,
            activities = manifestData.activities,
            services = manifestData.services,
            receivers = manifestData.receivers,
            providers = manifestData.providers,
            signatureInfo = sigInfo,
            existingProtection = existingProtection,
            resourceSummary = ResourceSummary(
                totalEntries = totalZipEntries,
                hasResourcesArsc = hasResourcesArsc,
                assetCount = assetCount,
                drawableCount = drawableCount,
                layoutCount = layoutCount
            ),
            totalClasses = totalClasses,
            totalMethods = totalMethods,
            totalFields = totalFields,
            totalStrings = totalStrings,
            architectures = architectures,
            reflectionCount = totalReflection,
            jniMethodCount = totalJni,
            sensitiveStringCandidates = allSensitiveStrings.distinct().take(15)
        )
    }

    private fun readEntryBytes(zip: ZipInputStream): ByteArray {
        val bos = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var len: Int
        while (zip.read(buffer).also { len = it } > 0) {
            bos.write(buffer, 0, len)
        }
        return bos.toByteArray()
    }

    private fun getPermissionDescription(simple: String): String {
        return when {
            simple.contains("INTERNET") -> "Allows open network sockets and internet API communication"
            simple.contains("CAMERA") -> "Direct camera sensor capture and video recording"
            simple.contains("LOCATION") -> "GPS satellite and cellular geolocation access"
            simple.contains("RECORD_AUDIO") -> "Audio microphone capture and recording"
            simple.contains("ACCESS_NETWORK_STATE") -> "Checks active Wi-Fi and mobile connectivity state"
            simple.contains("WAKE_LOCK") -> "Prevents CPU from sleeping during background tasks"
            simple.contains("VIBRATE") -> "Haptic feedback device control"
            simple.contains("POST_NOTIFICATIONS") -> "System status bar notification delivery"
            else -> "Standard Android platform capability"
        }
    }
}
