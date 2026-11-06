package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.core.model.ApkAnalysisResult
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel

@Composable
fun AnalyzerScreen(
    viewModel: MainViewModel,
    onLaunchFilePicker: () -> Unit,
    modifier: Modifier = Modifier
) {
    val analysis by viewModel.analysisResult.collectAsState()
    val isAnalyzing by viewModel.isAnalyzing.collectAsState()
    var selectedTab by remember { mutableStateOf(0) }

    val tabs = listOf("Overview", "DEX Code", "Native Libs", "Permissions", "Components", "Signatures")

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "APK Analyzer Engine",
                subtitle = "Deep structural, DEX bytecode, native ABI, and certificate inspection",
                badgeText = if (analysis != null) "READY" else "NO APK"
            )
        }

        if (isAnalyzing) {
            item {
                CyberCard {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        CircularProgressIndicator(color = NeonCyan, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "Extracting and parsing APK structures...",
                            style = MaterialTheme.typography.bodyLarge,
                            color = NeonCyan
                        )
                    }
                }
            }
        } else if (analysis != null) {
            val apk = analysis!!

            // SUB-TABS
            item {
                ScrollableTabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = CyberPanel,
                    contentColor = NeonCyan,
                    edgePadding = 0.dp
                ) {
                    tabs.forEachIndexed { index, title ->
                        Tab(
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            text = {
                                Text(
                                    text = title,
                                    style = MaterialTheme.typography.labelLarge,
                                    color = if (selectedTab == index) NeonCyan else TextMuted
                                )
                            }
                        )
                    }
                }
            }

            when (selectedTab) {
                0 -> {
                    // OVERVIEW TAB
                    item {
                        CyberCard(borderColor = NeonCyan.copy(alpha = 0.5f)) {
                            Text(
                                text = "PACKAGE & IDENTITY",
                                style = MaterialTheme.typography.labelSmall,
                                color = NeonCyan
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = apk.appName,
                                    style = MaterialTheme.typography.headlineMedium,
                                    color = TextPrimary
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                CyberBadge(
                                    text = if (apk.isDebuggable) "DEBUGGABLE" else "RELEASE",
                                    color = if (apk.isDebuggable) SecurityAmber else SecurityGreen
                                )
                            }
                            Text(
                                text = apk.packageName,
                                style = MaterialTheme.typography.labelMedium,
                                color = TextCode
                            )

                            Spacer(modifier = Modifier.height(12.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                HexDataViewer(label = "VERSION NAME", value = apk.versionName, modifier = Modifier.weight(1f))
                                Spacer(modifier = Modifier.width(8.dp))
                                HexDataViewer(label = "VERSION CODE", value = "${apk.versionCode}", modifier = Modifier.weight(1f))
                                Spacer(modifier = Modifier.width(8.dp))
                                HexDataViewer(label = "FILE SIZE", value = "%.2f MB".format(apk.fileSize / (1024.0 * 1024.0)), modifier = Modifier.weight(1f))
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                HexDataViewer(label = "MIN SDK", value = "Android ${apk.minSdkVersion}", modifier = Modifier.weight(1f))
                                Spacer(modifier = Modifier.width(8.dp))
                                HexDataViewer(label = "TARGET SDK", value = "Android ${apk.targetSdkVersion}", modifier = Modifier.weight(1f))
                                Spacer(modifier = Modifier.width(8.dp))
                                HexDataViewer(label = "ALLOW BACKUP", value = "${apk.allowsBackup}", modifier = Modifier.weight(1f))
                            }
                        }
                    }

                    // EXISTING HARDENING
                    item {
                        CyberCard(
                            borderColor = if (apk.existingProtection.isAlreadyProtected) SecurityAmber else SecurityGreen
                        ) {
                            Text(
                                text = "EXISTING PROTECTION SCAN",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = apk.existingProtection.details,
                                style = MaterialTheme.typography.bodyLarge,
                                color = if (apk.existingProtection.isAlreadyProtected) SecurityAmber else SecurityGreen
                            )
                        }
                    }

                    // AGGREGATE STATS
                    item {
                        CyberCard {
                            Text(
                                text = "BYTECODE & BINARY METRICS",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                MetricColumn(label = "CLASSES", value = "${apk.totalClasses}")
                                MetricColumn(label = "METHODS", value = "${apk.totalMethods}")
                                MetricColumn(label = "STRINGS", value = "${apk.totalStrings}")
                                MetricColumn(label = "FIELDS", value = "${apk.totalFields}")
                            }
                        }
                    }
                }

                1 -> {
                    // DEX CODE TAB
                    item {
                        SectionHeader(title = "DEX Files (${apk.dexFiles.size})", subtitle = "Compiled Dalvik executable modules")
                    }
                    items(apk.dexFiles) { dex ->
                        CyberCard(borderColor = NeonCyan.copy(alpha = 0.3f)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = dex.fileName,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = NeonCyan
                                )
                                CyberBadge(text = dex.version, color = ElectricRed)
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                HexDataViewer(
                                    label = "FILE SIZE",
                                    value = if (dex.formattedSize.isNotEmpty()) "${dex.formattedSize} (${dex.size} B)" else "${dex.size} B",
                                    modifier = Modifier.weight(1f)
                                )
                                HexDataViewer(
                                    label = "TIMESTAMP",
                                    value = if (dex.formattedTimestamp.isNotEmpty()) dex.formattedTimestamp else "N/A",
                                    modifier = Modifier.weight(1.2f)
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            HexDataViewer(label = "SHA-1 HEADER HASH", value = dex.sha1)
                            Spacer(modifier = Modifier.height(4.dp))
                            HexDataViewer(label = "ADLER32 CHECKSUM", value = "0x%08X".format(dex.checksum))
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                MetricColumn(label = "CLASSES", value = "${dex.classCount}")
                                MetricColumn(label = "METHODS", value = "${dex.methodCount}")
                                MetricColumn(label = "STRINGS", value = "${dex.stringCount}")
                                MetricColumn(label = "FIELDS", value = "${dex.fieldCount}")
                            }
                        }
                    }

                    if (apk.sensitiveStringCandidates.isNotEmpty()) {
                        item {
                            CyberCard(borderColor = ElectricRed.copy(alpha = 0.4f)) {
                                Text(
                                    text = "SENSITIVE STRING CANDIDATES DETECTED",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = ElectricRed
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                apk.sensitiveStringCandidates.forEach { s ->
                                    Text(
                                        text = "• $s",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextCode
                                    )
                                }
                            }
                        }
                    }
                }

                2 -> {
                    // NATIVE LIBS TAB
                    item {
                        SectionHeader(
                            title = "Native Shared Libraries (${apk.nativeLibs.size})",
                            subtitle = "ABI Architectures: ${apk.architectures.joinToString(", ")}"
                        )
                    }
                    if (apk.nativeLibs.isEmpty()) {
                        item {
                            CyberCard {
                                Text(
                                    text = "No native shared libraries (.so) found in APK archive.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = TextMuted
                                )
                            }
                        }
                    } else {
                        items(apk.nativeLibs) { lib ->
                            CyberCard {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = lib.libName,
                                        style = MaterialTheme.typography.titleMedium,
                                        color = TextPrimary
                                    )
                                    CyberBadge(text = lib.abi, color = NeonCyan)
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "Format: ${if (lib.isElf) "Valid ELF" else "Raw"}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = TextSecondary
                                    )
                                    Text(
                                        text = "Bit-Width: ${if (lib.is64Bit) "64-bit" else "32-bit"}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = TextSecondary
                                    )
                                    Text(
                                        text = "Symbols: ${if (lib.isStripped) "Stripped" else "Unstripped"}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = if (lib.isStripped) SecurityGreen else SecurityAmber
                                    )
                                }
                            }
                        }
                    }
                }

                3 -> {
                    // PERMISSIONS TAB
                    item {
                        SectionHeader(
                            title = "Permissions Analysis (${apk.permissions.size})",
                            subtitle = "Categorized by dangerous runtime vs normal install privileges"
                        )
                    }
                    items(apk.permissions) { perm ->
                        CyberCard(
                            borderColor = if (perm.isSensitive) ElectricRed.copy(alpha = 0.5f) else CyberPanelBorder
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = perm.name.substringAfterLast('.'),
                                    style = MaterialTheme.typography.labelLarge,
                                    color = if (perm.isSensitive) ElectricRed else TextPrimary
                                )
                                CyberBadge(
                                    text = perm.protectionLevel,
                                    color = if (perm.isSensitive) ElectricRed else SecurityGreen
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = perm.description,
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextSecondary
                            )
                        }
                    }
                }

                4 -> {
                    // COMPONENTS TAB
                    item {
                        SectionHeader(title = "Declared Components", subtitle = "Entrypoints, services, and system listeners")
                    }
                    item {
                        ComponentGroupCard("ACTIVITIES (${apk.activities.size})", apk.activities)
                    }
                    item {
                        ComponentGroupCard("SERVICES (${apk.services.size})", apk.services)
                    }
                    item {
                        ComponentGroupCard("BROADCAST RECEIVERS (${apk.receivers.size})", apk.receivers)
                    }
                    item {
                        ComponentGroupCard("CONTENT PROVIDERS (${apk.providers.size})", apk.providers)
                    }
                }

                5 -> {
                    // SIGNATURES TAB
                    item {
                        SectionHeader(title = "APK Signature & Certificate", subtitle = "Cryptographic signing authenticity")
                    }
                    item {
                        val sig = apk.signatureInfo
                        if (sig != null) {
                            CyberCard(borderColor = SecurityGreen.copy(alpha = 0.5f)) {
                                Text(
                                    text = "SIGNER SUBJECT",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = TextMuted
                                )
                                Text(
                                    text = sig.signerSubject,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = TextPrimary
                                )

                                Spacer(modifier = Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    CyberBadge(text = if (sig.hasV1Scheme) "v1 (JAR): VALID" else "v1: NONE", color = SecurityGreen)
                                    CyberBadge(text = if (sig.hasV2Scheme) "v2: YES" else "v2: OPTIONAL", color = NeonCyan)
                                    CyberBadge(text = sig.signatureAlgorithm, color = SecurityPurple)
                                }

                                Spacer(modifier = Modifier.height(10.dp))
                                HexDataViewer(label = "SHA-256 FINGERPRINT", value = sig.sha256Fingerprint, highlight = true)
                                Spacer(modifier = Modifier.height(6.dp))
                                HexDataViewer(label = "SHA-1 FINGERPRINT", value = sig.sha1Fingerprint)
                                Spacer(modifier = Modifier.height(6.dp))
                                HexDataViewer(label = "VALIDITY WINDOW", value = "${sig.validFrom} to ${sig.validTo}")
                            }
                        }
                    }
                }
            }
        } else {
            item {
                CyberCard {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "No APK currently loaded for analysis",
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Please select an APK from device storage to inspect its structure",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        CyberButton(
                            text = "SELECT APK FILE",
                            onClick = onLaunchFilePicker,
                            icon = Icons.Default.FileOpen,
                            isPrimary = true
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricColumn(label: String, value: String) {
    Column {
        Text(text = label, style = MaterialTheme.typography.labelSmall, color = TextMuted)
        Text(text = value, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
    }
}

@Composable
private fun ComponentGroupCard(title: String, items: List<String>) {
    CyberCard {
        Text(text = title, style = MaterialTheme.typography.labelSmall, color = NeonCyan)
        Spacer(modifier = Modifier.height(6.dp))
        if (items.isEmpty()) {
            Text(text = "None declared", style = MaterialTheme.typography.bodyMedium, color = TextMuted)
        } else {
            items.forEach { item ->
                Text(
                    text = "• ${item.substringAfterLast('.')}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextPrimary
                )
            }
        }
    }
}
