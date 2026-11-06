package com.example.core.analyzer

import com.example.core.model.NativeLibInfo

object ElfParser {

    fun parse(abi: String, libName: String, bytes: ByteArray): NativeLibInfo {
        if (bytes.size < 16) {
            return NativeLibInfo(
                abi = abi,
                libName = libName,
                size = bytes.size.toLong(),
                isElf = false,
                is64Bit = abi.contains("64"),
                isStripped = true
            )
        }

        val isElf = bytes[0] == 0x7F.toByte() &&
                bytes[1] == 'E'.code.toByte() &&
                bytes[2] == 'L'.code.toByte() &&
                bytes[3] == 'F'.code.toByte()

        val is64Bit = if (isElf) bytes[4] == 2.toByte() else abi.contains("64")

        // Quick check for .symtab or .strtab in raw binary to determine stripped status
        val binaryText = String(bytes.take(4096).toByteArray(), Charsets.ISO_8859_1) +
                String(bytes.takeLast(4096).toByteArray(), Charsets.ISO_8859_1)
        val isStripped = !binaryText.contains(".symtab")

        return NativeLibInfo(
            abi = abi,
            libName = libName,
            size = bytes.size.toLong(),
            isElf = isElf,
            is64Bit = is64Bit,
            isStripped = isStripped
        )
    }
}
