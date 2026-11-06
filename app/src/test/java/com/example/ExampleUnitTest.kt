package com.example

import com.example.core.analyzer.DexParser
import com.example.core.compatibility.CompatibilityEngine
import com.example.core.model.*
import com.example.core.signer.ApkSigner
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32

import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ExampleUnitTest {

    @Test
    fun testApkSignerGeneration() {
        val signer = ApkSigner()
        val dummyEntries = mapOf(
            "AndroidManifest.xml" to "binary_axml_content".toByteArray(Charsets.UTF_8),
            "classes.dex" to "dex_bytecode_content".toByteArray(Charsets.UTF_8),
            "resources.arsc" to "arsc_data".toByteArray(Charsets.UTF_8)
        )

        val result = signer.signApkEntries(dummyEntries)
        assertNotNull(result)
        assertTrue(result.manifestMfBytes.isNotEmpty())
        assertTrue(result.certSfBytes.isNotEmpty())
        assertTrue(result.certRsaBytes.isNotEmpty())
        assertTrue(result.sha256Fingerprint.contains(":"))
    }

    @Test
    fun testCompatibilityEngineEvaluation() {
        val engine = CompatibilityEngine()
        val dummyApk = ApkAnalysisResult(
            fileName = "TestApp.apk",
            filePath = "/tmp/TestApp.apk",
            fileSize = 1048576L,
            packageName = "com.test.app",
            appName = "Test App",
            versionCode = 100L,
            versionName = "1.0.0",
            minSdkVersion = 24,
            targetSdkVersion = 34,
            isDebuggable = false,
            allowsBackup = true,
            dexFiles = emptyList(),
            nativeLibs = listOf(
                NativeLibInfo("arm64-v8a", "libtest.so", 12000L, true, true, true)
            ),
            permissions = emptyList(),
            activities = listOf("com.test.app.MainActivity"),
            services = emptyList(),
            receivers = emptyList(),
            providers = emptyList(),
            signatureInfo = null,
            existingProtection = ExistingProtectionInfo(false, emptyList(), "None"),
            resourceSummary = ResourceSummary(100, true, 5, 20, 10),
            totalClasses = 150,
            totalMethods = 900,
            totalFields = 300,
            totalStrings = 1200,
            architectures = listOf("arm64-v8a"),
            reflectionCount = 2,
            jniMethodCount = 1,
            sensitiveStringCandidates = listOf("https://api.test.io")
        )

        val reportStandard = engine.evaluate(dummyApk, ProtectionConfig(profile = ProtectionProfile.STANDARD))
        assertEquals(CompatibilityStatus.COMPATIBLE, reportStandard.status)
        assertTrue(reportStandard.score >= 85)
        assertTrue(reportStandard.autoAppliedRules.isNotEmpty())

        val reportMax = engine.evaluate(dummyApk, ProtectionConfig(profile = ProtectionProfile.MAXIMUM))
        assertEquals(CompatibilityStatus.COMPATIBLE, reportMax.status)
    }

    @Test
    fun testDexParserHeader() {
        val header = ByteBuffer.allocate(112).order(ByteOrder.LITTLE_ENDIAN)
        header.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
        header.putInt(0) // checksum placeholder
        header.put(ByteArray(20)) // sha1 placeholder
        header.putInt(112) // file_size
        header.putInt(112) // header_size
        header.putInt(0x12345678) // endian_tag
        header.putInt(0)
        header.putInt(0)
        header.putInt(0)
        header.putInt(10) // string_ids_size
        header.putInt(0)
        header.putInt(5) // type_ids_size
        header.putInt(0)
        header.putInt(2) // proto_ids_size
        header.putInt(0)
        header.putInt(8) // field_ids_size
        header.putInt(0)
        header.putInt(15) // method_ids_size
        header.putInt(0)
        header.putInt(3) // class_defs_size
        header.putInt(0)
        header.putInt(0)
        header.putInt(0)

        val bytes = header.array()
        val md = MessageDigest.getInstance("SHA-1")
        md.update(bytes, 32, bytes.size - 32)
        val sha1 = md.digest()
        System.arraycopy(sha1, 0, bytes, 12, 20)

        val adler = Adler32()
        adler.update(bytes, 12, bytes.size - 12)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, adler.value.toInt())

        val parser = DexParser("classes.dex", bytes)
        val result = parser.parse()

        assertEquals("classes.dex", result.info.fileName)
        assertEquals("v035", result.info.version)
        assertEquals(3, result.info.classCount)
        assertEquals(15, result.info.methodCount)
        assertEquals(10, result.info.stringCount)
    }

    @Test
    fun testProtectionProfilesDefaults() {
        val standard = ProtectionConfig.defaultForProfile(ProtectionProfile.STANDARD)
        assertTrue(standard[SecurityModule.DEX_PROTECTION] == true)
        assertTrue(standard[SecurityModule.ANTI_TAMPER] == true)
        assertTrue(standard[SecurityModule.ANTI_DEBUG] == false)

        val max = ProtectionConfig.defaultForProfile(ProtectionProfile.MAXIMUM)
        assertTrue(max[SecurityModule.ANTI_DEBUG] == true)
        assertTrue(max[SecurityModule.ANTI_EMULATOR] == true)
        assertTrue(max[SecurityModule.STRING_ENCRYPTION] == true)
        assertTrue(max[SecurityModule.LICENSE_VERIFICATION] == true)
    }

    @Test
    fun testV2SignatureInjection() {
        val signer = ApkSigner()
        val sampleApk = java.io.File("src/main/assets/samples/SecureVaultApp-v1.0.apk")
        if (sampleApk.exists()) {
            val outputApk = java.io.File("/tmp/test_unit_v2_output.apk")
            val success = signer.injectV2Signature(sampleApk, outputApk)
            assertTrue(success)
            assertTrue(outputApk.exists())
            assertTrue(outputApk.length() > 5000)
        }
    }

    @Test
    fun testDexHardeningEngine() {
        val dexHardener = com.example.core.protection.DexHardeningEngine()
        val header = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)
        header.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
        header.putInt(0) // checksum
        header.put(ByteArray(20)) // sha1
        header.putInt(256) // file_size
        header.putInt(112) // header_size
        header.putInt(0x12345678) // endian_tag
        header.putInt(0); header.putInt(0); header.putInt(0)
        header.putInt(4); header.putInt(120) // string_ids
        header.putInt(2); header.putInt(136) // type_ids
        header.putInt(1); header.putInt(144) // proto_ids
        header.putInt(1); header.putInt(152) // field_ids
        header.putInt(1); header.putInt(160) // method_ids
        header.putInt(1); header.putInt(176) // class_defs
        header.putInt(48); header.putInt(208) // data

        val dexBytes = header.array()
        val result = dexHardener.hardenDex(dexBytes)
        assertTrue(result.success)
        assertNotNull(result.hardenedBytes)
        assertEquals(256, result.hardenedBytes.size)
        assertTrue(result.hardenedSha1.isNotEmpty())
    }

    @Test
    fun testResourceHardeningEngine() {
        val resHardener = com.example.core.protection.ResourceHardeningEngine()
        val arsc = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
        arsc.putShort(0x0002.toShort()) // RES_TABLE_TYPE
        arsc.putShort(12.toShort()) // headerSize
        arsc.putInt(64) // chunkSize
        arsc.putInt(1) // packageCount
        // Padding
        while (arsc.hasRemaining()) arsc.put(0)

        val result = resHardener.hardenResources(arsc.array())
        assertTrue(result.success)
        assertEquals(64, result.hardenedBytes.size)
        assertTrue(result.originalSize == 64L)
    }

    @Test
    fun testMultiDexProcessing() {
        val dexHardener = com.example.core.protection.DexHardeningEngine()
        val dexNames = listOf("classes.dex", "classes2.dex", "classes3.dex", "classes4.dex", "classes5.dex")

        for (name in dexNames) {
            val header = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)
            header.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
            header.putInt(0); header.put(ByteArray(20))
            header.putInt(256); header.putInt(112); header.putInt(0x12345678)
            header.putInt(0); header.putInt(0); header.putInt(0)
            header.putInt(4); header.putInt(120)
            header.putInt(2); header.putInt(136)
            header.putInt(1); header.putInt(144)
            header.putInt(1); header.putInt(152)
            header.putInt(1); header.putInt(160)
            header.putInt(1); header.putInt(176)
            header.putInt(48); header.putInt(208)

            val res = dexHardener.hardenDex(header.array())
            assertTrue("Failed to harden $name", res.success)
            assertEquals(256, res.hardenedBytes.size)
            assertTrue(res.hardenedSha1.isNotEmpty())
        }
    }

    @Test
    fun testApkTamperProtectionEngine() {
        val tamperEngine = com.example.core.protection.ApkTamperProtectionEngine()
        val mockEntries = mapOf(
            "AndroidManifest.xml" to "binary_manifest_data".toByteArray(Charsets.UTF_8),
            "classes.dex" to "dex_1_data".toByteArray(Charsets.UTF_8),
            "classes2.dex" to "dex_2_data".toByteArray(Charsets.UTF_8),
            "resources.arsc" to "resources_table".toByteArray(Charsets.UTF_8),
            "assets/config.json" to "{\"key\":\"val\"}".toByteArray(Charsets.UTF_8),
            "lib/arm64-v8a/libsec.so" to byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        )

        val result = tamperEngine.applyTamperProtection(
            entries = mockEntries,
            packageName = "com.sample.app",
            keyAlias = "test_key",
            signerSha256Fingerprint = "AA:BB:CC:DD:EE:FF"
        )

        assertTrue(result.success)
        assertEquals("PROTECTED", result.manifestIntegrityStatus)
        assertEquals("PROTECTED", result.assetIntegrityStatus)
        assertEquals("PROTECTED", result.nativeLibIntegrityStatus)
        assertEquals("PROTECTED", result.runtimeTamperStatus)
        assertEquals("PROTECTED", result.repackagingDetectionStatus)
        assertEquals(1, result.assetsProtectedCount)
        assertEquals(1, result.nativeLibsCount)
        assertTrue(result.newEntries.containsKey("assets/redx/integrity_manifest.json"))
        assertTrue(result.newEntries.containsKey("assets/redx/integrity_seal.bin"))
        assertTrue(result.newEntries.containsKey("assets/redx/runtime_policy.json"))
        assertTrue(result.newEntries.containsKey("assets/redx/repackage_guard.bin"))
    }

    @Test
    fun testDexScanningService() {
        val scanner = com.example.core.service.DexScanningService()

        fun buildMinimalDexHeader(classCount: Int, methodCount: Int): ByteArray {
            val header = ByteBuffer.allocate(112).order(ByteOrder.LITTLE_ENDIAN)
            header.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
            header.putInt(0)
            header.put(ByteArray(20))
            header.putInt(112); header.putInt(112); header.putInt(0x12345678)
            header.putInt(0); header.putInt(0); header.putInt(0)
            header.putInt(10); header.putInt(0) // string_ids
            header.putInt(0); header.putInt(0)
            header.putInt(0); header.putInt(0)
            header.putInt(0); header.putInt(0)
            header.putInt(methodCount); header.putInt(0) // method_ids
            header.putInt(classCount); header.putInt(0) // class_defs
            header.putInt(0); header.putInt(0)
            return header.array()
        }

        val entries = mapOf(
            "classes.dex" to buildMinimalDexHeader(50, 200),
            "classes2.dex" to buildMinimalDexHeader(80, 450),
            "classes3.dex" to buildMinimalDexHeader(120, 600),
            "AndroidManifest.xml" to ByteArray(100),
            "resources.arsc" to ByteArray(100)
        )

        val fixedTimestamp = 1730825475000L // 2024-11-05
        val scanned = scanner.scanEntries(entries, fixedTimestamp)

        assertEquals(3, scanned.size)

        // Check classes.dex
        val dex1 = scanned[0]
        assertEquals("classes.dex", dex1.name)
        assertEquals(1, dex1.partitionIndex)
        assertTrue(dex1.isPrimary)
        assertEquals(112L, dex1.sizeBytes)
        assertEquals("112 B", dex1.formattedSize)
        assertEquals(fixedTimestamp, dex1.timestamp)
        assertTrue(dex1.formattedTimestamp.isNotEmpty())
        assertEquals(50, dex1.classCount)
        assertEquals(200, dex1.methodCount)
        assertEquals(com.example.core.service.DexHardeningStatus.DETECTED, dex1.status)

        // Check classes2.dex
        val dex2 = scanned[1]
        assertEquals("classes2.dex", dex2.name)
        assertEquals(2, dex2.partitionIndex)
        assertFalse(dex2.isPrimary)
        assertEquals(80, dex2.classCount)
        assertEquals(450, dex2.methodCount)

        // Check classes3.dex
        val dex3 = scanned[2]
        assertEquals("classes3.dex", dex3.name)
        assertEquals(3, dex3.partitionIndex)
        assertFalse(dex3.isPrimary)
        assertEquals(120, dex3.classCount)
        assertEquals(600, dex3.methodCount)

        // Test formatFileSize helper
        assertEquals("0 B", com.example.core.service.DexScanningService.formatFileSize(0))
        assertEquals("500 B", com.example.core.service.DexScanningService.formatFileSize(500))
        assertEquals("1.00 KB", com.example.core.service.DexScanningService.formatFileSize(1024))
        assertEquals("24.70 MB", com.example.core.service.DexScanningService.formatFileSize(25900000))
    }

    @Test
    fun testSingleDexConsolidationAndTamperLock() {
        val dexHardener = com.example.core.protection.DexHardeningEngine()

        fun buildSampleDex(size: Int): ByteArray {
            val buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
            buf.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
            buf.putInt(0); buf.put(ByteArray(20))
            buf.putInt(size); buf.putInt(112); buf.putInt(0x12345678)
            while (buf.hasRemaining()) buf.put(0x22)
            return buf.array()
        }

        val primaryDex = buildSampleDex(256)
        val secondaryDexMap = mapOf(
            "classes2.dex" to buildSampleDex(300),
            "classes3.dex" to buildSampleDex(400)
        )

        val result = dexHardener.consolidateAndLockToSingleDex(primaryDex, secondaryDexMap)
        assertTrue(result.success)
        assertEquals(2, result.hiddenPartitions.size)
        assertTrue(result.hiddenPartitions.contains("classes2.dex"))
        assertTrue(result.hiddenPartitions.contains("classes3.dex"))
        assertTrue(result.antiTamperSeal.isNotEmpty())

        val consolidated = result.consolidatedDexBytes
        assertEquals(primaryDex.size, consolidated.size)

        // Verify valid DEX header
        val magic = String(consolidated.copyOfRange(0, 8), Charsets.US_ASCII)
        assertTrue(magic.startsWith("dex\n"))

        // Verify file size in header matches array size
        val headerFileSize = ByteBuffer.wrap(consolidated, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int
        assertEquals(consolidated.size, headerFileSize)
    }

    @Test
    fun testCrashReportingServiceDiagnostics() {
        val context = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        val crashService = com.example.core.crash.CrashReportingService.getInstance(context)

        // 1. Test Breadcrumb Logging
        crashService.logBreadcrumb("UNIT_TEST", "Test breadcrumb recorded")
        val eventsAfterBreadcrumb = crashService.diagnosticEvents.value
        assertTrue(eventsAfterBreadcrumb.isNotEmpty())
        assertEquals("UNIT_TEST", eventsAfterBreadcrumb.first().tag)
        assertEquals("Test breadcrumb recorded", eventsAfterBreadcrumb.first().message)

        // 2. Test Exception Recording with Root-Cause Analysis
        val cnfException = ClassNotFoundException("com.sample.target.SecondaryActivity not found")
        crashService.recordException(cnfException, "TEST_CLASSLOADER")

        val eventsAfterException = crashService.diagnosticEvents.value
        val latestEvent = eventsAfterException.first()
        assertEquals(com.example.core.crash.DiagnosticLevel.ERROR, latestEvent.level)
        assertNotNull(latestEvent.rootCause)
        assertTrue(latestEvent.rootCause!!.contains("ClassLoader") || latestEvent.rootCause!!.contains("Multi-DEX"))
        assertNotNull(latestEvent.fixRecommendation)

        // 3. Test VerifyError Root-Cause Analysis
        val verifyError = java.lang.VerifyError("Rejecting class com.target.MainActivity: Bad opcode")
        crashService.recordException(verifyError, "TEST_VERIFY")
        val verifyEvent = crashService.diagnosticEvents.value.first()
        assertTrue(verifyEvent.rootCause!!.contains("ART") || verifyEvent.rootCause!!.contains("bytecode"))
    }
}
