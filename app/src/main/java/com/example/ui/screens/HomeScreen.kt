package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.core.model.BuildStatus
import com.example.core.model.CompatibilityStatus
import com.example.core.model.ProtectionProfile
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel
import com.example.ui.viewmodel.ScreenTab
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HomeScreen(
    viewModel: MainViewModel,
    onLaunchFilePicker: () -> Unit,
    modifier: Modifier = Modifier
) {
    val stats = viewModel.getDashboardStats()
    val selectedFile by viewModel.selectedFile.collectAsState()
    val analysisResult by viewModel.analysisResult.collectAsState()
    val compatibilityReport by viewModel.compatibilityReport.collectAsState()
    val currentConfig by viewModel.protectionConfig.collectAsState()
    val sampleApks by viewModel.sampleApks.collectAsState()
    val buildHistory by viewModel.repository.buildHistory.collectAsState()

    var showSampleDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 32.dp)
    ) {
        // 1. BRAND HERO BANNER
        item {
            CyberCard(
                borderColor = ElectricRed.copy(alpha = 0.5f),
                glowEffect = true,
                backgroundColor = CyberPanelElevated
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(10.dp)
                                    .background(SecurityGreen, CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "CORE ENGINE ONLINE • PRODUCTION READY",
                                style = MaterialTheme.typography.labelSmall,
                                color = NeonCyan
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "RED-X APK PROTECTOR ULTRA",
                            style = MaterialTheme.typography.displayMedium,
                            color = TextPrimary
                        )
                        Text(
                            text = "ADVANCED APK SECURITY & PROTECTION ENGINE",
                            style = MaterialTheme.typography.labelMedium,
                            color = ElectricRed
                        )
                    }

                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .background(ElectricRed.copy(alpha = 0.15f), RoundedCornerShape(10.dp))
                            .border(1.dp, ElectricRed, RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = "Security Shield",
                            tint = ElectricRed,
                            modifier = Modifier.size(28.dp)
                        )
                    }
                }
            }
        }

        // DEVELOPER ATTRIBUTION & ZERO PARSE ERROR ARCHITECTURE
        item {
            CyberCard(
                borderColor = NeonCyan.copy(alpha = 0.5f),
                backgroundColor = CyberPanelElevated
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(NeonCyan.copy(alpha = 0.2f), CircleShape)
                                    .border(1.dp, NeonCyan, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.VerifiedUser,
                                    contentDescription = null,
                                    tint = NeonCyan,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "A.K.M REDWAN",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = NeonCyan,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "Android Application Developer & Security Researcher",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = TextPrimary
                                )
                            }
                        }
                        CyberBadge(text = "LEAD ARCHITECT", color = SecurityGreen)
                    }

                    Text(
                        text = "Specializing in APK modification, reverse engineering, application security auditing, and building advanced protection tools.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )

                    HorizontalDivider(color = CyberPanelBorder, modifier = Modifier.padding(vertical = 2.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = SecurityGreen,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "STORED (Method 0) mmap",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextPrimary
                            )
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = SecurityGreen,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "Dual v1 + v2 Signed",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextPrimary
                            )
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = SecurityGreen,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "Zero Parse Error",
                                style = MaterialTheme.typography.labelSmall,
                                color = SecurityGreen
                            )
                        }
                    }
                }
            }
        }

        // 2. DASHBOARD METRICS GRID
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                MetricCard(
                    title = "ANALYZED",
                    value = stats.totalAnalyzed.toString(),
                    icon = Icons.Default.Search,
                    color = NeonCyan,
                    modifier = Modifier.weight(1f)
                )
                MetricCard(
                    title = "PROTECTED",
                    value = stats.totalProtected.toString(),
                    icon = Icons.Default.Shield,
                    color = ElectricRed,
                    modifier = Modifier.weight(1f)
                )
                MetricCard(
                    title = "SUCCESS",
                    value = stats.successfulBuilds.toString(),
                    icon = Icons.Default.CheckCircle,
                    color = SecurityGreen,
                    modifier = Modifier.weight(1f)
                )
                MetricCard(
                    title = "FAILED",
                    value = stats.failedBuilds.toString(),
                    icon = Icons.Default.Error,
                    color = if (stats.failedBuilds > 0) SecurityAmber else TextMuted,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // 3. MAIN ACTION BUTTONS
        item {
            SectionHeader(title = "Primary Operations", subtitle = "Select source APK or test with built-in reference builds")
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                CyberButton(
                    text = "SELECT APK FILE",
                    onClick = onLaunchFilePicker,
                    icon = Icons.Default.FileOpen,
                    isPrimary = true,
                    modifier = Modifier.weight(1f).testTag("select_apk_button")
                )
                CyberButton(
                    text = "LOAD SAMPLE APK",
                    onClick = { showSampleDialog = true },
                    icon = Icons.Default.FolderZip,
                    isPrimary = false,
                    modifier = Modifier.weight(1f).testTag("sample_apk_button")
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                CyberButton(
                    text = "ANALYZE APK",
                    onClick = { viewModel.setTab(ScreenTab.ANALYZER) },
                    icon = Icons.Default.Analytics,
                    isPrimary = false,
                    modifier = Modifier.weight(1f)
                )
                CyberButton(
                    text = "START PROTECTION",
                    onClick = { viewModel.setTab(ScreenTab.PROTECT) },
                    icon = Icons.Default.Lock,
                    isPrimary = true,
                    modifier = Modifier.weight(1f)
                )
                CyberButton(
                    text = "VIEW REPORTS",
                    onClick = { viewModel.setTab(ScreenTab.REPORTS) },
                    icon = Icons.Default.Assessment,
                    isPrimary = false,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // 4. ACTIVE SELECTED APK CARD
        item {
            SectionHeader(
                title = "Loaded APK Target",
                badgeText = if (selectedFile != null) "LOADED" else "NO FILE"
            )

            if (analysisResult != null) {
                val apk = analysisResult!!
                CyberCard(
                    borderColor = NeonCyan.copy(alpha = 0.5f),
                    backgroundColor = CyberPanel
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .background(CyberPanelElevated, RoundedCornerShape(8.dp))
                                .border(1.dp, NeonCyan.copy(alpha = 0.6f), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Android,
                                contentDescription = null,
                                tint = NeonCyan,
                                modifier = Modifier.size(26.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(12.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = apk.appName,
                                style = MaterialTheme.typography.titleLarge,
                                color = TextPrimary
                            )
                            Text(
                                text = apk.packageName,
                                style = MaterialTheme.typography.labelMedium,
                                color = NeonCyan
                            )
                            Text(
                                text = "v${apk.versionName} (${apk.versionCode}) • SDK ${apk.minSdkVersion}+ -> ${apk.targetSdkVersion}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextSecondary
                            )
                        }

                        val compStatus = compatibilityReport?.status ?: CompatibilityStatus.COMPATIBLE
                        val badgeColor = when (compStatus) {
                            CompatibilityStatus.COMPATIBLE -> SecurityGreen
                            CompatibilityStatus.COMPATIBLE_WITH_WARNINGS -> SecurityAmber
                            CompatibilityStatus.UNSUPPORTED -> ElectricRed
                        }
                        CyberBadge(text = compStatus.label, color = badgeColor)
                    }

                    HorizontalDivider(
                        color = CyberPanelBorder,
                        thickness = 1.dp,
                        modifier = Modifier.padding(vertical = 12.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        DetailChip(label = "FILE SIZE", value = "%.2f MB".format(apk.fileSize / (1024.0 * 1024.0)))
                        DetailChip(label = "DEX FILES", value = "${apk.dexFiles.size} (${apk.totalClasses} classes)")
                        DetailChip(label = "ARCH", value = apk.architectures.firstOrNull() ?: "Universal")
                        DetailChip(label = "PERMISSIONS", value = "${apk.permissions.size}")
                    }
                }
            } else {
                CyberCard {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.UploadFile,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(40.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "No APK selected for processing",
                            style = MaterialTheme.typography.bodyLarge,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Choose an APK from storage or test with a sample above",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextMuted
                        )
                    }
                }
            }
        }

        // 5. ACTIVE PROTECTION PROFILE
        item {
            val isRedwan = currentConfig.profile.isRedwanHome
            SectionHeader(
                title = "Active Protection Engine",
                subtitle = "Configured defense matrix",
                badgeText = if (isRedwan) "ZERO CRASH CERTIFIED" else "CONFIGURED"
            )
            CyberCard(
                borderColor = if (isRedwan) SecurityGreen else ElectricRed.copy(alpha = 0.4f),
                backgroundColor = if (isRedwan) CyberPanelElevated else CyberPanel,
                glowEffect = isRedwan
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CyberBadge(
                                text = currentConfig.profile.title,
                                color = if (isRedwan) SecurityGreen else ElectricRed
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "${currentConfig.enabledModules.count { it.value }}/12 Modules Active",
                                style = MaterialTheme.typography.labelMedium,
                                color = TextSecondary
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = currentConfig.profile.description,
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )

                        if (isRedwan) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(SecurityGreen.copy(alpha = 0.1f), RoundedCornerShape(6.dp))
                                    .border(1.dp, SecurityGreen.copy(alpha = 0.35f), RoundedCornerShape(6.dp))
                                    .padding(8.dp)
                            ) {
                                Text(
                                    text = "✔ ZERO-CRASH GUARANTEE: Original UI, Layout, Login, APIs, Firebase, Database & Services remain 100% intact.",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = SecurityGreen
                                )
                            }
                        }
                    }

                    CyberButton(
                        text = "CHANGE",
                        onClick = { viewModel.setTab(ScreenTab.PROFILES) },
                        isPrimary = false,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }
            }
        }

        // 6. RECENT BUILD HISTORY
        item {
            SectionHeader(
                title = "Recent Protection Runs",
                subtitle = "Past output builds and validation seals",
                badgeText = "${buildHistory.size} TOTAL"
            )

            if (buildHistory.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    buildHistory.take(3).forEach { item ->
                        RecentBuildRow(item = item, onClick = { viewModel.setTab(ScreenTab.HISTORY) })
                    }
                }
            } else {
                Text(
                    text = "No build history yet. Run your first protection build to see records.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextMuted
                )
            }
        }
    }

    // Sample APK Selection Dialog
    if (showSampleDialog) {
        AlertDialog(
            onDismissRequest = { showSampleDialog = false },
            title = {
                Text(
                    text = "SELECT DEMO TEST APK",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Real pre-packaged APK files ready for structural analysis, DEX protection, and signing tests:",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                    sampleApks.forEach { file ->
                        val isSelected = selectedFile?.name == file.name
                        CyberCard(
                            borderColor = if (isSelected) ElectricRed else CyberPanelBorder,
                            backgroundColor = if (isSelected) CyberPanelElevated else CyberPanel,
                            modifier = Modifier.clickable {
                                viewModel.selectApkFile(file)
                                showSampleDialog = false
                            }
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.FolderZip,
                                    contentDescription = null,
                                    tint = if (isSelected) ElectricRed else NeonCyan
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = file.name,
                                        style = MaterialTheme.typography.titleMedium,
                                        color = TextPrimary
                                    )
                                    Text(
                                        text = "Size: %.2f KB".format(file.length() / 1024.0),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextMuted
                                    )
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showSampleDialog = false }) {
                    Text("CLOSE", color = NeonCyan)
                }
            },
            containerColor = CyberPanelElevated,
            shape = RoundedCornerShape(12.dp)
        )
    }
}

@Composable
private fun MetricCard(
    title: String,
    value: String,
    icon: ImageVector,
    color: Color,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .background(CyberPanel, RoundedCornerShape(8.dp))
            .border(1.dp, CyberPanelBorder, RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(14.dp)
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge,
                color = color,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
private fun DetailChip(label: String, value: String) {
    Column {
        Text(text = label, style = MaterialTheme.typography.labelSmall, color = TextMuted)
        Text(text = value, style = MaterialTheme.typography.labelMedium, color = TextPrimary)
    }
}

@Composable
private fun RecentBuildRow(
    item: com.example.core.model.BuildHistoryItem,
    onClick: () -> Unit
) {
    val sdf = SimpleDateFormat("MMM dd, HH:mm", Locale.US)
    CyberCard(
        borderColor = CyberPanelBorder,
        backgroundColor = CyberPanel,
        modifier = Modifier.clickable { onClick() }
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.appName,
                    style = MaterialTheme.typography.titleMedium,
                    color = TextPrimary
                )
                Text(
                    text = "${item.originalApkName} • ${sdf.format(Date(item.timestamp))}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary
                )
            }
            CyberBadge(
                text = item.status.name,
                color = if (item.status == BuildStatus.SUCCESS) SecurityGreen else ElectricRed
            )
        }
    }
}
