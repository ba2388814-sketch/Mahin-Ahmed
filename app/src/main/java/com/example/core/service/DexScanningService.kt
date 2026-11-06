package com.example.core.service

import com.example.core.analyzer.DexParser
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

/**
 * Status of an individual DEX partition during the APK hardening lifecycle.
 */
enum class DexHardeningStatus(val label: String) {
    DETECTED("DETECTED"),
    HARDENING("HARDENING..."),
    PROTECTED("PROTECTED"),
    CONSOLIDATED_HIDDEN("HIDDEN IN CLASSES.DEX"),
    TAMPER_LOCKED("TAMPER-LOCKED"),
    VERIFIED("VERIFIED")
}

/**
 * Detailed metadata of a scanned DEX partition (classes*.dex) extracted from an APK.
 */
data class ScannedDexEntry(
    val name: String,
    val partitionIndex: Int,
    val isPrimary: Boolean,
    val sizeBytes: Long,
    val compressedSizeBytes: Long,
    val formattedSize: String,
    val timestamp: Long,
    val formattedTimestamp: String,
    val checksum: Long,
    val sha1: String,
    val classCount: Int,
    val methodCount: Int,
    val status: DexHardeningStatus = DexHardeningStatus.DETECTED,
    val isConsolidated: Boolean = false,
    val isTamperLocked: Boolean = true
)

/**
 * DexScanningService
 *
 * Dedicated scanning service that detects and lists all 'classes*.dex' files within an uploaded APK
 * (including primary classes.dex and multidex partitions classes2.dex, classes3.dex, etc.),
 * extracting their uncompressed/compressed file sizes, timestamps, and header metrics.
 * Supports live status observation across the hardening pipeline.
 */
class DexScanningService {

    private val dexRegex = Regex("""classes\d*\.dex""")

    /**
     * Scans an APK file directly, leveraging ZipFile for optimal random access and accurate entry timestamps.
     */
    fun scanApk(file: File): List<ScannedDexEntry> {
        if (!file.exists() || file.length() < 100) return emptyList()

        return try {
            scanWithZipFile(file)
        } catch (_: Exception) {
            // Fallback to stream reading if ZipFile fails
            try {
                file.inputStream().use { scanStream(it, file.lastModified()) }
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    private fun scanWithZipFile(file: File): List<ScannedDexEntry> {
        val results = mutableListOf<ScannedDexEntry>()
        val zipFile = ZipFile(file)

        try {
            val entries = zipFile.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.name.matches(dexRegex)) {
                    val rawBytes = zipFile.getInputStream(entry).use { it.readBytes() }
                    val partition = parsePartitionIndex(entry.name)
                    val isPrimary = partition == 1
                    val entryTime = if (entry.time > 0L) entry.time else file.lastModified()
                    val dexResult = DexParser(entry.name, rawBytes, entryTime).parse()

                    val entrySize = if (entry.size >= 0) entry.size else rawBytes.size.toLong()
                    val compressedSize = if (entry.compressedSize >= 0) entry.compressedSize else entrySize

                    results.add(
                        ScannedDexEntry(
                            name = entry.name,
                            partitionIndex = partition,
                            isPrimary = isPrimary,
                            sizeBytes = entrySize,
                            compressedSizeBytes = compressedSize,
                            formattedSize = formatFileSize(entrySize),
                            timestamp = entryTime,
                            formattedTimestamp = formatTimestamp(entryTime),
                            checksum = dexResult.info.checksum,
                            sha1 = dexResult.info.sha1,
                            classCount = dexResult.info.classCount,
                            methodCount = dexResult.info.methodCount,
                            status = DexHardeningStatus.DETECTED
                        )
                    )
                }
            }
        } finally {
            try {
                zipFile.close()
            } catch (_: Exception) {}
        }

        return sortDexEntries(results)
    }

    /**
     * Scans a streaming APK input stream for all classes*.dex entries.
     */
    fun scanStream(inputStream: InputStream, fallbackTimestamp: Long = System.currentTimeMillis()): List<ScannedDexEntry> {
        val results = mutableListOf<ScannedDexEntry>()
        val zip = ZipInputStream(inputStream)
        var entry: ZipEntry? = zip.nextEntry

        while (entry != null) {
            val name = entry.name
            if (name.matches(dexRegex)) {
                val bos = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var len: Int
                while (zip.read(buffer).also { len = it } > 0) {
                    bos.write(buffer, 0, len)
                }
                val rawBytes = bos.toByteArray()
                val partition = parsePartitionIndex(name)
                val isPrimary = partition == 1
                val entryTime = if (entry.time > 0L) entry.time else fallbackTimestamp
                val dexResult = DexParser(name, rawBytes, entryTime).parse()

                val entrySize = if (entry.size >= 0) entry.size else rawBytes.size.toLong()
                val compressedSize = if (entry.compressedSize >= 0) entry.compressedSize else entrySize

                results.add(
                    ScannedDexEntry(
                        name = name,
                        partitionIndex = partition,
                        isPrimary = isPrimary,
                        sizeBytes = entrySize,
                        compressedSizeBytes = compressedSize,
                        formattedSize = formatFileSize(entrySize),
                        timestamp = entryTime,
                        formattedTimestamp = formatTimestamp(entryTime),
                        checksum = dexResult.info.checksum,
                        sha1 = dexResult.info.sha1,
                        classCount = dexResult.info.classCount,
                        methodCount = dexResult.info.methodCount,
                        status = DexHardeningStatus.DETECTED
                    )
                )
            }
            zip.closeEntry()
            entry = zip.nextEntry
        }

        return sortDexEntries(results)
    }

    /**
     * Scans in-memory entries map (e.g. during protection engine pipeline execution).
     */
    fun scanEntries(entries: Map<String, ByteArray>, timestamp: Long = System.currentTimeMillis()): List<ScannedDexEntry> {
        val results = mutableListOf<ScannedDexEntry>()
        for ((name, bytes) in entries) {
            if (name.matches(dexRegex)) {
                val partition = parsePartitionIndex(name)
                val isPrimary = partition == 1
                val dexResult = DexParser(name, bytes, timestamp).parse()

                results.add(
                    ScannedDexEntry(
                        name = name,
                        partitionIndex = partition,
                        isPrimary = isPrimary,
                        sizeBytes = bytes.size.toLong(),
                        compressedSizeBytes = bytes.size.toLong(),
                        formattedSize = formatFileSize(bytes.size.toLong()),
                        timestamp = timestamp,
                        formattedTimestamp = formatTimestamp(timestamp),
                        checksum = dexResult.info.checksum,
                        sha1 = dexResult.info.sha1,
                        classCount = dexResult.info.classCount,
                        methodCount = dexResult.info.methodCount,
                        status = DexHardeningStatus.DETECTED
                    )
                )
            }
        }
        return sortDexEntries(results)
    }

    private fun sortDexEntries(list: List<ScannedDexEntry>): List<ScannedDexEntry> {
        return list.sortedWith(Comparator { a, b ->
            a.partitionIndex.compareTo(b.partitionIndex)
        })
    }

    fun parsePartitionIndex(name: String): Int {
        if (name == "classes.dex") return 1
        val numStr = name.removePrefix("classes").removeSuffix(".dex")
        return numStr.toIntOrNull() ?: 1
    }

    companion object {
        fun formatFileSize(bytes: Long): String {
            if (bytes <= 0) return "0 B"
            val kb = bytes / 1024.0
            val mb = kb / 1024.0
            val gb = mb / 1024.0
            return when {
                gb >= 1.0 -> "%.2f GB".format(Locale.US, gb)
                mb >= 1.0 -> "%.2f MB".format(Locale.US, mb)
                kb >= 1.0 -> "%.2f KB".format(Locale.US, kb)
                else -> "$bytes B"
            }
        }

        fun formatTimestamp(epochMillis: Long): String {
            if (epochMillis <= 0L) return "Unknown"
            return try {
                val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                sdf.format(Date(epochMillis))
            } catch (_: Exception) {
                "Unknown"
            }
        }
    }
}
