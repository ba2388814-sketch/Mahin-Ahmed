package com.example.core.analyzer

import com.example.core.model.SignatureInfo
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale

object CertParser {

    fun parse(certBytes: ByteArray, hasV2: Boolean = false, hasV3: Boolean = false): SignatureInfo? {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val certs = cf.generateCertificates(ByteArrayInputStream(certBytes))
            val cert = certs.firstOrNull() as? X509Certificate ?: return null

            val mdSha1 = MessageDigest.getInstance("SHA-1")
            val mdSha256 = MessageDigest.getInstance("SHA-256")
            val encoded = cert.encoded
            val sha1 = mdSha1.digest(encoded).joinToString(":") { "%02X".format(it) }
            val sha256 = mdSha256.digest(encoded).joinToString(":") { "%02X".format(it) }

            val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.US)
            val validFrom = sdf.format(cert.notBefore)
            val validTo = sdf.format(cert.notAfter)

            SignatureInfo(
                hasV1Scheme = true,
                hasV2Scheme = hasV2,
                hasV3Scheme = hasV3,
                signerSubject = cert.subjectDN.name,
                signerIssuer = cert.issuerDN.name,
                serialNumber = cert.serialNumber.toString(16).uppercase(),
                validFrom = validFrom,
                validTo = validTo,
                signatureAlgorithm = cert.sigAlgName,
                sha1Fingerprint = sha1,
                sha256Fingerprint = sha256
            )
        } catch (_: Exception) {
            null
        }
    }
}
