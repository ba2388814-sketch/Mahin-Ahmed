package com.example.core.signer

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

object SelfSignedCertBuilder {

    fun buildCertificate(keyPair: KeyPair, dn: String): X509Certificate {
        // Construct a standard DER-encoded X.509 v3 certificate
        val serialNumber = BigInteger(64, Random())
        val notBefore = Date(System.currentTimeMillis() - 86400000L)
        val notAfter = Date(System.currentTimeMillis() + (3650L * 86400000L))

        val rsaOid = byteArrayOf(0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01)
        val sha256RsaOid = byteArrayOf(0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)

        // TBSCertificate
        val tbs = ByteArrayOutputStream()
        // version [0] EXPLICIT INTEGER 2 (v3)
        tbs.write(byteArrayOf(0xA0.toByte(), 0x03, 0x02, 0x01, 0x02))

        // serialNumber INTEGER
        writeDerElement(tbs, 0x02, serialNumber.toByteArray())

        // signature AlgorithmIdentifier (SHA256withRSA)
        val sigAlgSeq = ByteArrayOutputStream()
        sigAlgSeq.write(sha256RsaOid)
        sigAlgSeq.write(byteArrayOf(0x05, 0x00))
        writeDerSequence(tbs, sigAlgSeq.toByteArray())

        // issuer Name
        val nameSeq = buildX500Name(dn)
        tbs.write(nameSeq)

        // validity Validity
        val validity = ByteArrayOutputStream()
        writeDerTime(validity, notBefore)
        writeDerTime(validity, notAfter)
        writeDerSequence(tbs, validity.toByteArray())

        // subject Name (self-signed, identical to issuer)
        tbs.write(nameSeq)

        // subjectPublicKeyInfo SubjectPublicKeyInfo
        tbs.write(keyPair.public.encoded)

        val tbsBytes = encodeDerSequence(tbs.toByteArray())

        // Sign TBSCertificate with private key
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(keyPair.private)
        signer.update(tbsBytes)
        val signatureValue = signer.sign()

        // Assemble Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
        val certSeq = ByteArrayOutputStream()
        certSeq.write(tbsBytes)
        writeDerSequence(certSeq, sigAlgSeq.toByteArray())

        // BIT STRING for signatureValue (tag 0x03, first byte is unused bits = 0x00)
        val bitString = ByteArrayOutputStream()
        bitString.write(0x00)
        bitString.write(signatureValue)
        writeDerElement(certSeq, 0x03, bitString.toByteArray())

        val fullCertDer = encodeDerSequence(certSeq.toByteArray())
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(fullCertDer)) as X509Certificate
    }

    private fun buildX500Name(dn: String): ByteArray {
        val baos = ByteArrayOutputStream()
        // Common Name CN=
        val cnValue = dn.substringAfter("CN=").substringBefore(",")
        val rdn = ByteArrayOutputStream()
        val atv = ByteArrayOutputStream()
        // OID 2.5.4.3 (commonName)
        atv.write(byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03))
        writeDerElement(atv, 0x13, cnValue.toByteArray(Charsets.UTF_8))
        writeDerSequence(rdn, atv.toByteArray())

        val rdnSet = ByteArrayOutputStream()
        writeDerElement(rdnSet, 0x31, rdn.toByteArray())
        writeDerSequence(baos, rdnSet.toByteArray())
        return baos.toByteArray()
    }

    private fun writeDerTime(out: ByteArrayOutputStream, date: Date) {
        val sdf = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        val str = sdf.format(date)
        writeDerElement(out, 0x17, str.toByteArray(Charsets.US_ASCII))
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
}
