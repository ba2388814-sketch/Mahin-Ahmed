package com.example.core.analyzer

import com.example.core.model.DexInfo
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DexParser(
    private val fileName: String,
    private val bytes: ByteArray,
    private val timestamp: Long = 0L
) {

    data class DexParseResult(
        val info: DexInfo,
        val reflectionIndicators: Int,
        val jniIndicators: Int,
        val sensitiveStrings: List<String>,
        val detectedPackers: List<String>
    )

    fun parse(): DexParseResult {
        val formattedSize = formatFileSize(bytes.size.toLong())
        val formattedTime = formatTimestamp(timestamp)

        if (bytes.size < 112) {
            return DexParseResult(
                info = DexInfo(
                    fileName = fileName,
                    size = bytes.size.toLong(),
                    version = "unknown",
                    checksum = 0L,
                    sha1 = "",
                    classCount = 0,
                    methodCount = 0,
                    fieldCount = 0,
                    stringCount = 0,
                    timestamp = timestamp,
                    formattedTimestamp = formattedTime,
                    formattedSize = formattedSize
                ),
                reflectionIndicators = 0,
                jniIndicators = 0,
                sensitiveStrings = emptyList(),
                detectedPackers = emptyList()
            )
        }

        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val magicBytes = ByteArray(8)
        buffer.get(magicBytes)
        val magic = String(magicBytes, Charsets.US_ASCII)
        val version = magic.filter { it.isDigit() }

        val checksum = buffer.int.toLong() and 0xFFFFFFFFL
        val sha1Bytes = ByteArray(20)
        buffer.get(sha1Bytes)
        val sha1 = sha1Bytes.joinToString("") { "%02x".format(it) }

        val fileSize = buffer.int
        val headerSize = buffer.int
        val endianTag = buffer.int
        val linkSize = buffer.int
        val linkOff = buffer.int
        val mapOff = buffer.int

        val stringIdsSize = buffer.int
        val stringIdsOff = buffer.int

        val typeIdsSize = buffer.int
        val typeIdsOff = buffer.int

        val protoIdsSize = buffer.int
        val protoIdsOff = buffer.int

        val fieldIdsSize = buffer.int
        val fieldIdsOff = buffer.int

        val methodIdsSize = buffer.int
        val methodIdsOff = buffer.int

        val classDefsSize = buffer.int
        val classDefsOff = buffer.int

        // Heuristic and string pool extraction
        var reflectionCount = 0
        var jniCount = 0
        val sensitiveStrings = mutableListOf<String>()
        val detectedPackers = mutableListOf<String>()

        // Scan strings for reflection, endpoints, and packer signatures
        try {
            val sampleStrings = extractSampleStrings(buffer, stringIdsSize, stringIdsOff)
            for (str in sampleStrings) {
                if (str.contains("Class.forName") || str.contains("getDeclaredMethod") || str.contains("getMethod") || str.contains("getDeclaredField")) {
                    reflectionCount++
                }
                if (str.contains("System.loadLibrary") || str.contains("JNI_OnLoad") || str.contains("native_method")) {
                    jniCount++
                }
                if (str.startsWith("https://") || str.startsWith("http://") || str.contains("api_key") || str.contains("secret") || str.contains("Bearer ") || str.contains("password")) {
                    if (str.length in 8..120) {
                        sensitiveStrings.add(str)
                    }
                }
                // Known obfuscator / packer signatures
                if (str.contains("com.secneo.") || str.contains("libsecmain.so")) {
                    detectedPackers.add("Bangcle / Secneo")
                } else if (str.contains("com.tencent.StubShell") || str.contains("libtxcore.so")) {
                    detectedPackers.add("Tencent Legu")
                } else if (str.contains("com.qihoo.util.") || str.contains("libjiagu")) {
                    detectedPackers.add("Qihoo 360 Jiagu")
                } else if (str.contains("com.ijiami.") || str.contains("libshell.so")) {
                    detectedPackers.add("IJiami Protector")
                } else if (str.contains("DexGuard") || str.contains("dxguard")) {
                    detectedPackers.add("DexGuard")
                }
            }
        } catch (_: Exception) {}

        return DexParseResult(
            info = DexInfo(
                fileName = fileName,
                size = bytes.size.toLong(),
                version = if (version.isNotEmpty()) "v$version" else "v035",
                checksum = checksum,
                sha1 = sha1,
                classCount = classDefsSize.coerceAtLeast(0),
                methodCount = methodIdsSize.coerceAtLeast(0),
                fieldCount = fieldIdsSize.coerceAtLeast(0),
                stringCount = stringIdsSize.coerceAtLeast(0),
                timestamp = timestamp,
                formattedTimestamp = formattedTime,
                formattedSize = formattedSize
            ),
            reflectionIndicators = reflectionCount,
            jniIndicators = jniCount,
            sensitiveStrings = sensitiveStrings.distinct().take(20),
            detectedPackers = detectedPackers.distinct()
        )
    }

    private fun formatFileSize(bytes: Long): String {
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

    private fun formatTimestamp(epochMillis: Long): String {
        if (epochMillis <= 0L) return "Unknown"
        return try {
            val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
            sdf.format(Date(epochMillis))
        } catch (_: Exception) {
            "Unknown"
        }
    }

    private fun extractSampleStrings(buffer: ByteBuffer, count: Int, offset: Int): List<String> {
        val strings = mutableListOf<String>()
        val scanCount = count.coerceAtMost(500) // Sample up to 500 strings for performance
        if (offset <= 0 || offset + (scanCount * 4) > bytes.size) return strings

        for (i in 0 until scanCount) {
            val strOffset = buffer.getInt(offset + i * 4)
            if (strOffset in 0 until bytes.size - 2) {
                // Read MUTF-8 length and content
                var pos = strOffset
                // skip ULEB128 length
                while (pos < bytes.size && (bytes[pos].toInt() and 0x80) != 0) {
                    pos++
                }
                pos++
                val start = pos
                while (pos < bytes.size && bytes[pos].toInt() != 0 && (pos - start) < 256) {
                    pos++
                }
                if (pos > start) {
                    val s = String(bytes, start, pos - start, Charsets.UTF_8)
                    if (s.isNotBlank()) strings.add(s)
                }
            }
        }
        return strings
    }
}
