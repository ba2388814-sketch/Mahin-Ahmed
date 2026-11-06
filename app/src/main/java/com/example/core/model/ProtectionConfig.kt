package com.example.core.model

enum class ProtectionProfile(
    val title: String,
    val description: String,
    val recommendedFor: String,
    val isRedwanHome: Boolean = false
) {
    REDWAN_HOME(
        title = "REDWAN HOME PROTECTION",
        description = "Specialized Non-Destructive Protection Engine: 100% guarantees original app preservation (UI, Login, Firebase, APIs, Database, Services intact) with automatic backup and crash-immunity verification.",
        recommendedFor = "Recommended for zero-crash protection of custom and home-use applications",
        isRedwanHome = true
    ),
    STANDARD(
        title = "STANDARD PROTECTION",
        description = "Core code obfuscation, APK signature verification, integrity seal, and safe resource hardening.",
        recommendedFor = "Utility apps, enterprise tools, maximum backward compatibility"
    ),
    ADVANCED(
        title = "ADVANCED PROTECTION",
        description = "Standard plus control-flow scrambling, selected string encryption, native library hardening, anti-tamper, and anti-repackaging.",
        recommendedFor = "Commercial apps, proprietary business logic, in-app billing"
    ),
    MAXIMUM(
        title = "MAXIMUM PROTECTION",
        description = "Comprehensive defense-in-depth: multi-layer integrity seals, anti-debug, anti-emulator, watermark system, and license policy enforcement.",
        recommendedFor = "Fintech, crypto, gaming, mission-critical IP security"
    )
}

enum class SecurityModule(
    val key: String,
    val title: String,
    val category: String,
    val description: String,
    val defaultInRedwanHome: Boolean,
    val defaultInStandard: Boolean,
    val defaultInAdvanced: Boolean,
    val defaultInMaximum: Boolean
) {
    DEX_PROTECTION(
        key = "dex_protect",
        title = "DEX Code Hardening",
        category = "Code Security",
        description = "Bytecode re-alignment, symbol sanitization, control flow integrity, and debug metadata stripping.",
        defaultInRedwanHome = true,
        defaultInStandard = true,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    SINGLE_DEX_CONSOLIDATION(
        key = "single_dex_consolidate",
        title = "Single DEX Concealment & Tamper Lock",
        category = "Code Security",
        description = "Encapsulates and hides all secondary multidex files (classes2.dex, classes3.dex, etc.) inside a single protected classes.dex with strict cryptographic tamper resistance.",
        defaultInRedwanHome = true,
        defaultInStandard = true,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    CODE_OBFUSCATION(
        key = "code_obfuscate",
        title = "Symbol & Flow Obfuscation",
        category = "Code Security",
        description = "Obfuscate class, method, and field identifiers while preserving reflection and Android framework entrypoints.",
        defaultInRedwanHome = true,
        defaultInStandard = true,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    ANTI_TAMPER(
        key = "anti_tamper",
        title = "Runtime Anti-Tamper & Integrity",
        category = "Integrity",
        description = "Generates SHA-256 integrity seal for DEX bytecode, manifest, and resources with HMAC runtime verification stub.",
        defaultInRedwanHome = true,
        defaultInStandard = true,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    SIGNATURE_VERIFICATION(
        key = "sig_verify",
        title = "Signature Verification",
        category = "Authentication",
        description = "Enforces cryptographic signing certificates (v1 + v2 scheme) and pins authorized developer public key.",
        defaultInRedwanHome = true,
        defaultInStandard = true,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    ANTI_REPACKAGING(
        key = "anti_repack",
        title = "Anti-Repackaging Guard",
        category = "Integrity",
        description = "Binds application package ID with authorized signer certificate fingerprint to prevent re-cloning.",
        defaultInRedwanHome = true,
        defaultInStandard = false,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    STRING_ENCRYPTION(
        key = "string_encrypt",
        title = "Sensitive String Encryption",
        category = "Data Protection",
        description = "Encrypts URLs, API keys, credentials, and sensitive string literals using AES-GCM / polymorphic XOR cipher map.",
        defaultInRedwanHome = true,
        defaultInStandard = false,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    NATIVE_PROTECTION(
        key = "native_protect",
        title = "Native Library Hardening",
        category = "Binary Security",
        description = "Inspects ELF shared libraries, symbol table strip validation, ABI compatibility alignment, and JNI linkage defense.",
        defaultInRedwanHome = true,
        defaultInStandard = false,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    ANTI_DEBUG(
        key = "anti_debug",
        title = "Anti-Debugging & Tracer Guard",
        category = "Runtime Defense",
        description = "Detects ptrace attach, JDWP debugger listeners, and TracerPid monitoring with safe integrity policy.",
        defaultInRedwanHome = false,
        defaultInStandard = false,
        defaultInAdvanced = false,
        defaultInMaximum = true
    ),
    ANTI_EMULATOR(
        key = "anti_emulator",
        title = "Anti-Emulator Environment Check",
        category = "Runtime Defense",
        description = "Configurable runtime checks for QEMU, Nox, BlueStacks, and Genymotion device profiles without blocking real devices.",
        defaultInRedwanHome = false,
        defaultInStandard = false,
        defaultInAdvanced = false,
        defaultInMaximum = true
    ),
    RESOURCE_PROTECTION(
        key = "resource_protect",
        title = "Resource & Asset Hardening",
        category = "Resource Security",
        description = "Compresses and scrambles non-framework asset entry names while strictly preserving resource IDs.",
        defaultInRedwanHome = true,
        defaultInStandard = true,
        defaultInAdvanced = true,
        defaultInMaximum = true
    ),
    LICENSE_VERIFICATION(
        key = "license_verify",
        title = "Developer License Enforcement",
        category = "Licensing",
        description = "Injects client-side license verification policy with expiration dates, device binding, and remote server validation.",
        defaultInRedwanHome = false,
        defaultInStandard = false,
        defaultInAdvanced = false,
        defaultInMaximum = true
    ),
    WATERMARK_SYSTEM(
        key = "watermark",
        title = "Cryptographic Watermark System",
        category = "Identity",
        description = "Embeds developer identity watermark, immutable build UUID, timestamp, and security manifest signature.",
        defaultInRedwanHome = true,
        defaultInStandard = false,
        defaultInAdvanced = true,
        defaultInMaximum = true
    )
}

data class ProtectionConfig(
    val profile: ProtectionProfile = ProtectionProfile.REDWAN_HOME,
    val enabledModules: Map<SecurityModule, Boolean> = defaultForProfile(ProtectionProfile.REDWAN_HOME),
    val developerWatermark: String = "REDWAN HOME PROTECTION • VERIFIED SHIELD #001",
    val licenseServerUrl: String = "https://license.red-x.internal/v1/verify",
    val licenseExpiryDays: Int = 365,
    val selectedKeyAlias: String = "redx_production_key"
) {
    fun isModuleEnabled(module: SecurityModule): Boolean = enabledModules[module] ?: false

    fun withModule(module: SecurityModule, enabled: Boolean): ProtectionConfig {
        val updated = enabledModules.toMutableMap()
        updated[module] = enabled
        return copy(enabledModules = updated)
    }

    companion object {
        fun defaultForProfile(profile: ProtectionProfile): Map<SecurityModule, Boolean> {
            return SecurityModule.entries.associateWith { module ->
                when (profile) {
                    ProtectionProfile.REDWAN_HOME -> module.defaultInRedwanHome
                    ProtectionProfile.STANDARD -> module.defaultInStandard
                    ProtectionProfile.ADVANCED -> module.defaultInAdvanced
                    ProtectionProfile.MAXIMUM -> module.defaultInMaximum
                }
            }
        }
    }
}
