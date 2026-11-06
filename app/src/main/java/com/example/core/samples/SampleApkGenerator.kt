package com.example.core.samples

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SampleApkGenerator(private val context: Context) {

    fun ensureSampleApks(): List<File> {
        val samplesDir = File(context.filesDir, "sample_apks")
        if (!samplesDir.exists()) samplesDir.mkdirs()

        val sampleSpecs = listOf(
            Triple("SecureVaultApp-v1.0.apk", "SecureVaultApp-v1.0.apk", "com.redx.securevault"),
            Triple("CryptoWallet-v2.1.apk", "CryptoWallet-v2.1.apk", "com.redx.cryptowallet"),
            Triple("EnterprisePortal-v4.0.apk", "EnterprisePortal-v4.0.apk", "com.redx.enterpriseportal")
        )

        val result = mutableListOf<File>()

        for ((targetName, assetName, pkg) in sampleSpecs) {
            val targetFile = File(samplesDir, targetName)
            var loaded = false
            try {
                if (targetFile.exists() && targetFile.length() > 8000) {
                    loaded = true
                } else {
                    context.assets.open("samples/$assetName").use { input ->
                        FileOutputStream(targetFile).use { output ->
                            input.copyTo(output)
                        }
                    }
                    loaded = targetFile.length() > 8000
                }
            } catch (_: Exception) {}

            if (!loaded || !targetFile.exists() || targetFile.length() < 1024) {
                createSampleApk(
                    outputFile = targetFile,
                    packageName = pkg,
                    appName = targetName.removeSuffix(".apk"),
                    versionCode = 100,
                    versionName = "1.0.0",
                    minSdk = 24,
                    targetSdk = 34,
                    permissions = listOf("android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"),
                    nativeLibs = emptyList(),
                    sensitiveStrings = listOf("https://api.$pkg.internal/v1")
                )
            }
            result.add(targetFile)
        }

        return result
    }

    private fun createSampleApk(
        outputFile: File,
        packageName: String,
        appName: String,
        versionCode: Long,
        versionName: String,
        minSdk: Int,
        targetSdk: Int,
        permissions: List<String>,
        nativeLibs: List<String>,
        sensitiveStrings: List<String>
    ) {
        val manifestBytes = buildMinimalBinaryManifest(packageName, appName, versionCode, versionName, minSdk, targetSdk, permissions)
        val dexBytes = buildSampleDex(packageName, sensitiveStrings)

        val entriesMap = mutableMapOf<String, ByteArray>()
        entriesMap["AndroidManifest.xml"] = manifestBytes
        entriesMap["classes.dex"] = dexBytes
        if (appName.contains("Enterprise", ignoreCase = true)) {
            val secondaryDexBytes = buildSampleDex("$packageName.module2", listOf("https://vault.internal.corp/key"))
            entriesMap["classes2.dex"] = secondaryDexBytes
        }
        for (libPath in nativeLibs) {
            entriesMap["lib/$libPath"] = buildSampleElf(libPath.contains("64"))
        }
        entriesMap["resources.arsc"] = ByteArray(256) { 0x00 }
        val configJson = """{"app":"$appName","package":"$packageName","version":"$versionName","environment":"production"}"""
        entriesMap["assets/app_config.json"] = configJson.toByteArray(Charsets.UTF_8)
        entriesMap["res/drawable/ic_app_logo.xml"] = "<vector/>".toByteArray(Charsets.UTF_8)

        // Generate genuine cryptographic signature
        try {
            val signer = com.example.core.signer.ApkSigner(context)
            val sigResult = signer.signApkEntries(entriesMap)
            entriesMap["META-INF/MANIFEST.MF"] = sigResult.manifestMfBytes
            entriesMap["META-INF/CERT.SF"] = sigResult.certSfBytes
            entriesMap["META-INF/CERT.RSA"] = sigResult.certRsaBytes
        } catch (_: Exception) {}

        val zos = ZipOutputStream(FileOutputStream(outputFile))
        for ((name, bytes) in entriesMap) {
            addZipEntry(zos, name, bytes)
        }

        zos.close()
    }

    private fun addZipEntry(zos: ZipOutputStream, name: String, data: ByteArray) {
        val entry = ZipEntry(name)
        entry.time = System.currentTimeMillis()
        zos.putNextEntry(entry)
        zos.write(data)
        zos.closeEntry()
    }

    private fun buildSampleDex(packageName: String, sensitiveStrings: List<String>): ByteArray {
        val stringList = mutableListOf(
            "L$packageName/MainActivity;",
            "L$packageName/SecurityService;",
            "Ljava/lang/Object;",
            "Ljava/lang/String;",
            "onCreate",
            "initSecurity",
            "verifyLicense",
            "validateToken"
        )
        stringList.addAll(sensitiveStrings)

        val baos = ByteArrayOutputStream()
        // 112-byte DEX header
        val header = ByteBuffer.allocate(112).order(ByteOrder.LITTLE_ENDIAN)
        header.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII)) // 8 bytes magic
        header.putInt(0) // Checksum placeholder
        header.put(ByteArray(20)) // SHA-1 placeholder
        header.putInt(0) // file_size placeholder
        header.putInt(112) // header_size
        header.putInt(0x12345678) // endian_tag
        header.putInt(0) // link_size
        header.putInt(0) // link_off
        header.putInt(0) // map_off

        header.putInt(stringList.size) // string_ids_size
        header.putInt(112) // string_ids_off

        header.putInt(8) // type_ids_size
        header.putInt(112 + stringList.size * 4) // type_ids_off

        header.putInt(4) // proto_ids_size
        header.putInt(0)

        header.putInt(6) // field_ids_size
        header.putInt(0)

        header.putInt(14) // method_ids_size
        header.putInt(0)

        header.putInt(2) // class_defs_size
        header.putInt(0)

        header.putInt(1024) // data_size
        header.putInt(0)

        baos.write(header.array())

        // String IDs table (offsets into data section)
        val strOffsets = mutableListOf<Int>()
        var curOffset = 112 + (stringList.size * 4) + 64 // data section base
        for (s in stringList) {
            strOffsets.add(curOffset)
            curOffset += 1 + s.length + 1
        }

        val idsBuf = ByteBuffer.allocate(stringList.size * 4).order(ByteOrder.LITTLE_ENDIAN)
        for (off in strOffsets) idsBuf.putInt(off)
        baos.write(idsBuf.array())

        // String Data Section
        for (s in stringList) {
            baos.write(s.length and 0x7F) // ULEB128 len
            baos.write(s.toByteArray(Charsets.UTF_8))
            baos.write(0) // null terminator
        }

        // Pad to 1024 bytes
        while (baos.size() < 1024) baos.write(0)

        val dexBytes = baos.toByteArray()
        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)

        // Set file size
        buffer.putInt(32, dexBytes.size)

        // Calculate SHA-1 (over bytes 32 to end)
        val md = MessageDigest.getInstance("SHA-1")
        md.update(dexBytes, 32, dexBytes.size - 32)
        val sha1 = md.digest()
        System.arraycopy(sha1, 0, dexBytes, 12, 20)

        // Calculate Adler32 (over bytes 12 to end)
        val adler = Adler32()
        adler.update(dexBytes, 12, dexBytes.size - 12)
        buffer.putInt(8, adler.value.toInt())

        return dexBytes
    }

    private fun buildSampleElf(is64Bit: Boolean): ByteArray {
        val bytes = ByteArray(512)
        bytes[0] = 0x7F.toByte()
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = if (is64Bit) 2.toByte() else 1.toByte() // 64 or 32 bit
        bytes[5] = 1.toByte() // Little-endian
        bytes[6] = 1.toByte() // Version 1
        // Machine
        if (is64Bit) {
            bytes[18] = 0xB7.toByte() // AArch64
        } else {
            bytes[18] = 0x28.toByte() // ARM
        }
        return bytes
    }

    private fun buildMinimalBinaryManifest(
        packageName: String,
        appName: String,
        versionCode: Long,
        versionName: String,
        minSdk: Int,
        targetSdk: Int,
        permissions: List<String>
    ): ByteArray {
        // Build valid binary AXML structure
        val stringPool = mutableListOf(
            "manifest", "package", "versionCode", "versionName",
            "uses-sdk", "minSdkVersion", "targetSdkVersion",
            "application", "label", "debuggable", "allowBackup",
            "uses-permission", "name",
            "activity",
            packageName,
            appName,
            versionName,
            "$packageName.MainActivity"
        )
        stringPool.addAll(permissions)

        val baos = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        header.putShort(0x0003.toShort()) // RES_XML_TYPE
        header.putShort(8.toShort()) // header_size
        header.putInt(0) // total size placeholder
        baos.write(header.array())

        // String Pool Chunk
        val spBytes = buildStringPool(stringPool)
        baos.write(spBytes)

        // Start manifest element
        val elemBytes = buildStartElementChunk("manifest", mapOf("package" to packageName, "versionName" to versionName), stringPool)
        baos.write(elemBytes)

        // uses-permission elements
        for (perm in permissions) {
            val permBytes = buildStartElementChunk("uses-permission", mapOf("name" to perm), stringPool)
            baos.write(permBytes)
        }

        // application element
        val appBytes = buildStartElementChunk("application", mapOf("label" to appName), stringPool)
        baos.write(appBytes)

        // activity element
        val actBytes = buildStartElementChunk("activity", mapOf("name" to "$packageName.MainActivity"), stringPool)
        baos.write(actBytes)

        val total = baos.toByteArray()
        ByteBuffer.wrap(total).order(ByteOrder.LITTLE_ENDIAN).putInt(4, total.size)
        return total
    }

    private fun buildStringPool(strings: List<String>): ByteArray {
        val baos = ByteArrayOutputStream()
        val poolHeader = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN)
        poolHeader.putShort(0x0001.toShort()) // RES_STRING_POOL_TYPE
        poolHeader.putShort(28.toShort()) // headerSize
        poolHeader.putInt(0) // totalSize placeholder
        poolHeader.putInt(strings.size) // stringCount
        poolHeader.putInt(0) // styleCount
        poolHeader.putInt(1 shl 8) // flags UTF-8
        poolHeader.putInt(28 + strings.size * 4) // stringsStart
        poolHeader.putInt(0) // stylesStart
        baos.write(poolHeader.array())

        // Offsets
        val offsetsBuf = ByteBuffer.allocate(strings.size * 4).order(ByteOrder.LITTLE_ENDIAN)
        var curOff = 0
        val strData = ByteArrayOutputStream()
        for (s in strings) {
            offsetsBuf.putInt(curOff)
            val bytes = s.toByteArray(Charsets.UTF_8)
            strData.write(bytes.size and 0x7F)
            strData.write(bytes)
            strData.write(0)
            curOff += 1 + bytes.size + 1
        }
        baos.write(offsetsBuf.array())
        baos.write(strData.toByteArray())

        val total = baos.toByteArray()
        ByteBuffer.wrap(total).order(ByteOrder.LITTLE_ENDIAN).putInt(4, total.size)
        return total
    }

    private fun buildStartElementChunk(name: String, attrs: Map<String, String>, pool: List<String>): ByteArray {
        val nameIdx = pool.indexOf(name).coerceAtLeast(0)
        val buf = ByteBuffer.allocate(36 + (attrs.size * 20)).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0102.toShort()) // RES_XML_START_ELEMENT_TYPE
        buf.putShort(16.toShort()) // headerSize
        buf.putInt(36 + (attrs.size * 20)) // chunkSize
        buf.putInt(1) // lineNumber
        buf.putInt(-1) // comment
        buf.putInt(-1) // ns
        buf.putInt(nameIdx) // name
        buf.putShort(20.toShort()) // attrStart
        buf.putShort(20.toShort()) // attrSize
        buf.putShort(attrs.size.toShort()) // attrCount
        buf.putShort(0)
        buf.putShort(0)
        buf.putShort(0)

        for ((attrName, attrVal) in attrs) {
            val aNameIdx = pool.indexOf(attrName).coerceAtLeast(0)
            val aValIdx = pool.indexOf(attrVal).coerceAtLeast(0)
            buf.putInt(-1) // ns
            buf.putInt(aNameIdx)
            buf.putInt(aValIdx)
            buf.putInt(0x03000008) // type String
            buf.putInt(aValIdx) // data
        }
        return buf.array()
    }
}
