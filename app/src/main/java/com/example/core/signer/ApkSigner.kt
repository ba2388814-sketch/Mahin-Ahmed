package com.example.core.signer

import android.content.Context
import com.example.core.model.DeveloperKeystore
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.X509Certificate
import java.util.*

class ApkSigner(private val context: Context? = null) {

    data class SigningResult(
        val manifestMfBytes: ByteArray,
        val certSfBytes: ByteArray,
        val certRsaBytes: ByteArray,
        val sha256Fingerprint: String
    )

    private var activePrivateKey: PrivateKey? = null
    private var activeCertificate: X509Certificate? = null

    init {
        loadOrGenerateKey()
    }

    private fun loadOrGenerateKey() {
        if (context != null) {
            try {
                val ks = KeyStore.getInstance("PKCS12")
                context.assets.open("redx_signer.p12").use { input ->
                    ks.load(input, "android".toCharArray())
                }
                val key = ks.getKey("androiddebugkey", "android".toCharArray()) as? PrivateKey
                val cert = ks.getCertificate("androiddebugkey") as? X509Certificate
                if (key != null && cert != null) {
                    activePrivateKey = key
                    activeCertificate = cert
                    return
                }
            } catch (_: Exception) {}
        }

        // Fallback: generate in-memory RSA keypair and certificate
        try {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048)
            val kp = kpg.generateKeyPair()
            activePrivateKey = kp.private
            activeCertificate = SelfSignedCertBuilder.buildCertificate(kp, "CN=A.K.M REDWAN, O=REDWAN HOME PROTECTION, OU=Security Research, C=BD")
        } catch (_: Exception) {}
    }

    fun signApkEntries(
        entries: Map<String, ByteArray>,
        keystore: DeveloperKeystore? = null
    ): SigningResult {
        if (activePrivateKey == null || activeCertificate == null) {
            loadOrGenerateKey()
        }

        val privateKey = activePrivateKey ?: throw IllegalStateException("No active private key for signing")
        val certificate = activeCertificate ?: throw IllegalStateException("No active certificate for signing")

        val md = MessageDigest.getInstance("SHA-256")

        // 1. Generate MANIFEST.MF
        val manifestSb = StringBuilder()
        manifestSb.append("Manifest-Version: 1.0\r\n")
        manifestSb.append("Created-By: A.K.M REDWAN - REDWAN HOME PROTECTION ULTRA\r\n")
        manifestSb.append("Built-By: A.K.M REDWAN (Android Security Researcher)\r\n\r\n")

        val entryManifestDigests = mutableMapOf<String, String>()

        for ((name, data) in entries) {
            if (name.startsWith("META-INF/")) continue
            val digest = encodeBase64(md.digest(data))
            entryManifestDigests[name] = digest

            manifestSb.append("Name: $name\r\n")
            manifestSb.append("SHA-256-Digest: $digest\r\n\r\n")
        }

        val manifestMfBytes = manifestSb.toString().toByteArray(Charsets.UTF_8)
        val manifestDigest = encodeBase64(md.digest(manifestMfBytes))

        // 2. Generate CERT.SF
        val sfSb = StringBuilder()
        sfSb.append("Signature-Version: 1.0\r\n")
        sfSb.append("Created-By: A.K.M REDWAN - REDWAN HOME PROTECTION ULTRA\r\n")
        sfSb.append("SHA-256-Digest-Manifest: $manifestDigest\r\n\r\n")

        for ((name, digest) in entryManifestDigests) {
            sfSb.append("Name: $name\r\n")
            sfSb.append("SHA-256-Digest: $digest\r\n\r\n")
        }

        val certSfBytes = sfSb.toString().toByteArray(Charsets.UTF_8)

        // 3. Sign CERT.SF with RSA Private Key
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(certSfBytes)
        val signatureBytes = sig.sign()

        // 4. Wrap into valid PKCS#7 SignedData structure
        val certRsaBytes = buildPkcs7SignatureBlock(certificate, signatureBytes)

        val pubKeyDigest = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        val sha256Fingerprint = pubKeyDigest.joinToString(":") { "%02X".format(it) }

        return SigningResult(
            manifestMfBytes = manifestMfBytes,
            certSfBytes = certSfBytes,
            certRsaBytes = certRsaBytes,
            sha256Fingerprint = sha256Fingerprint
        )
    }

    /**
     * Injects the APK Signature Scheme v2 block and updates the ZIP EOCD Central Directory offset.
     * This ensures the APK installs cleanly on Android 7.0 to Android 15+ without INSTALL_PARSE_FAILED_NO_CERTIFICATES.
     */
    fun injectV2Signature(inputApkFile: File, outputApkFile: File): Boolean {
        if (activePrivateKey == null || activeCertificate == null) {
            loadOrGenerateKey()
        }
        val privateKey = activePrivateKey ?: return false
        val cert = activeCertificate ?: return false

        try {
            val apkBytes = inputApkFile.readBytes()
            var eocdOffset = -1
            for (i in (apkBytes.size - 22) downTo (apkBytes.size - 65557).coerceAtLeast(0)) {
                if (apkBytes[i] == 0x50.toByte() && apkBytes[i + 1] == 0x4B.toByte() &&
                    apkBytes[i + 2] == 0x05.toByte() && apkBytes[i + 3] == 0x06.toByte()
                ) {
                    eocdOffset = i
                    break
                }
            }
            if (eocdOffset < 0) return false

            val eocdBuf = ByteBuffer.wrap(apkBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cdSize = eocdBuf.getInt(eocdOffset + 12)
            val cdOffset = eocdBuf.getInt(eocdOffset + 16)

            // Strip existing APK signing block if present
            var section1End = cdOffset
            if (cdOffset >= 24) {
                val magicOffset = cdOffset - 16
                val isOldBlock = apkBytes.copyOfRange(magicOffset, cdOffset).toString(Charsets.US_ASCII) == "APK Sig Block 42"
                if (isOldBlock) {
                    val oldBlockSize = ByteBuffer.wrap(apkBytes, cdOffset - 24, 8).order(ByteOrder.LITTLE_ENDIAN).long
                    section1End = (cdOffset - oldBlockSize - 8).toInt()
                }
            }

            val section1 = apkBytes.copyOfRange(0, section1End)
            val section2 = apkBytes.copyOfRange(cdOffset, cdOffset + cdSize)
            val originalEocd = apkBytes.copyOfRange(eocdOffset, apkBytes.size)

            val v2SigningBlock = buildApkSigningBlockV2(privateKey, cert, section1, section2, originalEocd)
            val newCdOffset = section1.size + v2SigningBlock.size

            val finalEocd = originalEocd.clone()
            ByteBuffer.wrap(finalEocd).order(ByteOrder.LITTLE_ENDIAN).putInt(16, newCdOffset)

            outputApkFile.parentFile?.mkdirs()
            FileOutputStream(outputApkFile).use { fos ->
                fos.write(section1)
                fos.write(v2SigningBlock)
                fos.write(section2)
                fos.write(finalEocd)
            }
            return true
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }

    private fun buildApkSigningBlockV2(
        privateKey: PrivateKey,
        cert: X509Certificate,
        section1: ByteArray,
        section2: ByteArray,
        originalEocd: ByteArray
    ): ByteArray {
        val digestEocd = originalEocd.clone()
        ByteBuffer.wrap(digestEocd).order(ByteOrder.LITTLE_ENDIAN).putInt(16, section1.size)

        val md = MessageDigest.getInstance("SHA-256")
        val chunkDigests = mutableListOf<ByteArray>()
        computeSectionChunkDigests(section1, md, chunkDigests)
        computeSectionChunkDigests(section2, md, chunkDigests)
        computeSectionChunkDigests(digestEocd, md, chunkDigests)

        val topBuf = ByteBuffer.allocate(5 + (chunkDigests.size * 32)).order(ByteOrder.LITTLE_ENDIAN)
        topBuf.put(0x5A.toByte())
        topBuf.putInt(chunkDigests.size)
        for (d in chunkDigests) {
            topBuf.put(d)
        }
        val topLevelDigest = md.digest(topBuf.array())

        val digestRecord = ByteArrayOutputStream()
        writeUint32(digestRecord, 0x0103) // SHA256withRSA
        writeLengthPrefixed(digestRecord, topLevelDigest)

        val digestsSequence = ByteArrayOutputStream()
        writeLengthPrefixed(digestsSequence, digestRecord.toByteArray())

        val certsSequence = ByteArrayOutputStream()
        writeLengthPrefixed(certsSequence, cert.encoded)

        val attrsSequence = ByteArrayOutputStream()

        val signedDataContent = ByteArrayOutputStream()
        writeLengthPrefixed(signedDataContent, digestsSequence.toByteArray())
        writeLengthPrefixed(signedDataContent, certsSequence.toByteArray())
        writeLengthPrefixed(signedDataContent, attrsSequence.toByteArray())
        val signedData = signedDataContent.toByteArray()

        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(signedData)
        val signatureBytes = sig.sign()

        val sigRecord = ByteArrayOutputStream()
        writeUint32(sigRecord, 0x0103)
        writeLengthPrefixed(sigRecord, signatureBytes)

        val signaturesSequence = ByteArrayOutputStream()
        writeLengthPrefixed(signaturesSequence, sigRecord.toByteArray())

        val publicKeyBytes = cert.publicKey.encoded

        val signerContent = ByteArrayOutputStream()
        writeLengthPrefixed(signerContent, signedData)
        writeLengthPrefixed(signerContent, signaturesSequence.toByteArray())
        writeLengthPrefixed(signerContent, publicKeyBytes)

        val signersSequence = ByteArrayOutputStream()
        writeLengthPrefixed(signersSequence, signerContent.toByteArray())

        val v2Value = ByteArrayOutputStream()
        writeLengthPrefixed(v2Value, signersSequence.toByteArray())
        val v2ValueBytes = v2Value.toByteArray()

        val idValueLen = 4L + v2ValueBytes.size
        val totalBlockSize = 8L + idValueLen + 8L + 16L

        val blockStream = ByteArrayOutputStream()
        writeUint64(blockStream, totalBlockSize)
        writeUint64(blockStream, idValueLen)
        writeUint32(blockStream, 0x7109871a.toInt())
        blockStream.write(v2ValueBytes)
        writeUint64(blockStream, totalBlockSize)
        blockStream.write("APK Sig Block 42".toByteArray(Charsets.US_ASCII))

        return blockStream.toByteArray()
    }

    private fun computeSectionChunkDigests(data: ByteArray, md: MessageDigest, out: MutableList<ByteArray>) {
        val chunkSize = 1048576
        var offset = 0
        while (offset < data.size) {
            val len = (data.size - offset).coerceAtMost(chunkSize)
            val buf = ByteBuffer.allocate(5 + len).order(ByteOrder.LITTLE_ENDIAN)
            buf.put(0xA5.toByte())
            buf.putInt(len)
            buf.put(data, offset, len)
            out.add(md.digest(buf.array()))
            offset += len
        }
    }

    private fun writeLengthPrefixed(os: OutputStream, data: ByteArray) {
        writeUint32(os, data.size)
        os.write(data)
    }

    private fun writeUint32(os: OutputStream, value: Int) {
        os.write(value and 0xFF)
        os.write((value shr 8) and 0xFF)
        os.write((value shr 16) and 0xFF)
        os.write((value shr 24) and 0xFF)
    }

    private fun writeUint64(os: OutputStream, value: Long) {
        for (i in 0 until 8) {
            os.write(((value shr (i * 8)) and 0xFF).toInt())
        }
    }

    private fun buildPkcs7SignatureBlock(
        cert: X509Certificate,
        signature: ByteArray
    ): ByteArray {
        val baos = ByteArrayOutputStream()

        val rsaOid = byteArrayOf(0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01)
        val sha256Oid = byteArrayOf(0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
        val dataOid = byteArrayOf(0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x07, 0x01)
        val signedDataOid = byteArrayOf(0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x07, 0x02)

        // SignerInfo
        val signerInfo = ByteArrayOutputStream()
        signerInfo.write(byteArrayOf(0x02, 0x01, 0x01)) // version 1

        // IssuerAndSerialNumber
        val issuerAndSerial = ByteArrayOutputStream()
        issuerAndSerial.write(cert.issuerX500Principal.encoded)
        writeDerElement(issuerAndSerial, 0x02, cert.serialNumber.toByteArray())
        writeDerSequence(signerInfo, issuerAndSerial.toByteArray())

        // digestAlgorithm (SHA-256)
        val digestAlgSeq = ByteArrayOutputStream()
        digestAlgSeq.write(sha256Oid)
        digestAlgSeq.write(byteArrayOf(0x05, 0x00)) // NULL
        writeDerSequence(signerInfo, digestAlgSeq.toByteArray())

        // digestEncryptionAlgorithm (RSA)
        val sigAlgSeq = ByteArrayOutputStream()
        sigAlgSeq.write(rsaOid)
        sigAlgSeq.write(byteArrayOf(0x05, 0x00)) // NULL
        writeDerSequence(signerInfo, sigAlgSeq.toByteArray())

        // encryptedDigest (OCTET STRING)
        writeDerElement(signerInfo, 0x04, signature)

        // SignerInfos SET
        val signerInfos = ByteArrayOutputStream()
        writeDerSequence(signerInfos, signerInfo.toByteArray())
        val signerInfosSet = ByteArrayOutputStream()
        writeDerElement(signerInfosSet, 0x31, signerInfos.toByteArray())

        // SignedData
        val signedData = ByteArrayOutputStream()
        signedData.write(byteArrayOf(0x02, 0x01, 0x01)) // version 1

        // digestAlgorithms SET
        val digestAlgs = ByteArrayOutputStream()
        writeDerSequence(digestAlgs, digestAlgSeq.toByteArray())
        writeDerElement(signedData, 0x31, digestAlgs.toByteArray())

        // encapContentInfo (id-data, detached so no content)
        val encapContent = ByteArrayOutputStream()
        encapContent.write(dataOid)
        writeDerSequence(signedData, encapContent.toByteArray())

        // certificates [0] IMPLICIT (tag 0xA0) containing cert.encoded
        writeDerElement(signedData, 0xA0, cert.encoded)

        // signerInfos
        signedData.write(signerInfosSet.toByteArray())

        // ContentInfo outer
        val contentInfo = ByteArrayOutputStream()
        contentInfo.write(signedDataOid)
        writeDerElement(contentInfo, 0xA0, encodeDerSequence(signedData.toByteArray()))

        writeDerSequence(baos, contentInfo.toByteArray())
        return baos.toByteArray()
    }

    private fun writeDerElement(out: ByteArrayOutputStream, tag: Int, content: ByteArray) {
        out.write(tag)
        writeDerLength(out, content.size)
        out.write(content, 0, content.size)
    }

    private fun writeDerSequence(out: ByteArrayOutputStream, content: ByteArray) {
        writeDerElement(out, 0x30, content)
    }

    private fun encodeDerSequence(content: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        writeDerElement(baos, 0x30, content)
        return baos.toByteArray()
    }

    private fun writeDerLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 128) {
            out.write(length)
        } else if (length < 256) {
            out.write(0x81)
            out.write(length)
        } else if (length < 65536) {
            out.write(0x82)
            out.write(length shr 8)
            out.write(length and 0xFF)
        } else {
            out.write(0x83)
            out.write(length shr 16)
            out.write((length shr 8) and 0xFF)
            out.write(length and 0xFF)
        }
    }

    private fun encodeBase64(bytes: ByteArray): String {
        return try {
            java.util.Base64.getEncoder().encodeToString(bytes)
        } catch (_: Throwable) {
            val table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            val sb = StringBuilder()
            var i = 0
            while (i < bytes.size) {
                val b0 = bytes[i].toInt() and 0xFF
                val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
                val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
                sb.append(table[b0 shr 2])
                sb.append(table[((b0 and 3) shl 4) or (b1 shr 4)])
                if (i + 1 < bytes.size) sb.append(table[((b1 and 0xF) shl 2) or (b2 shr 6)]) else sb.append('=')
                if (i + 2 < bytes.size) sb.append(table[b2 and 0x3F]) else sb.append('=')
                i += 3
            }
            sb.toString()
        }
    }
}
