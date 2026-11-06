package com.example.ui.screens

import android.content.Intent
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.core.model.BuildStatus
import com.example.core.model.ProtectionProfile
import com.example.core.util.ApkExportHelper
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val history by viewModel.repository.buildHistory.collectAsState()
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "Protection Build History",
                subtitle = "Cryptographic audit trail of all processed and signed APK packages",
                badgeText = "${history.size} TOTAL"
            )
        }

        if (history.isEmpty()) {
            item {
                CyberCard {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.History,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "No builds recorded yet",
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Run your first protection build in APK Protect tab",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                    }
                }
            }
        } else {
            items(history) { item ->
                CyberCard(
                    borderColor = if (item.status == BuildStatus.SUCCESS) CyberPanelBorder else ElectricRed
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = item.appName,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = TextPrimary
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                CyberBadge(
                                    text = item.profile.title,
                                    color = if (item.profile.isRedwanHome) SecurityGreen else ElectricRed
                                )
                            }
                            Text(
                                text = "${item.packageName} • ${item.id}",
                                style = MaterialTheme.typography.labelMedium,
                                color = NeonCyan
                            )
                            Text(
                                text = "Build Time: ${sdf.format(Date(item.timestamp))} (${item.buildDurationMs} ms)",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted
                            )

                            if (item.backupPath.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(4.dp))
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Save,
                                        contentDescription = null,
                                        tint = NeonCyan,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = "Original Backup Saved",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = NeonCyan
                                    )
                                }
                            }
                        }

                        IconButton(onClick = { viewModel.deleteBuildRecord(item.id) }) {
                            Icon(
                                imageVector = Icons.Default.DeleteOutline,
                                contentDescription = "Delete Record",
                                tint = TextMuted
                            )
                        }
                    }

                    // Security Dashboard Status Badges
                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        CyberBadge(
                            text = "MULTI-DEX (${item.dexFilesProtected}): ${item.multiDexProtectionStatus}",
                            color = if (item.multiDexProtectionStatus == "PROTECTED") SecurityGreen else ElectricRed
                        )
                        CyberBadge(
                            text = "RES: ${item.resourceProtectionStatus}",
                            color = if (item.resourceProtectionStatus == "PROTECTED") SecurityGreen else ElectricRed
                        )
                        CyberBadge(
                            text = "TAMPER: ${item.runtimeTamperStatus}",
                            color = if (item.runtimeTamperStatus == "PROTECTED") SecurityGreen else ElectricRed
                        )
                        CyberBadge(
                            text = "V2: ${item.apkSignatureStatus}",
                            color = if (item.apkSignatureStatus == "PROTECTED" || item.apkSignatureStatus == "VERIFIED") NeonCyan else ElectricRed
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        HexDataViewer(
                            label = "ORIGINAL SIZE",
                            value = "%.2f KB".format(item.originalSize / 1024.0),
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        HexDataViewer(
                            label = "PROTECTED SIZE",
                            value = "%.2f KB".format(item.protectedSize / 1024.0),
                            highlight = true,
                            modifier = Modifier.weight(1f)
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "APPLIED MODULES (${item.appliedModules.size}):",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted
                    )
                    item.appliedModules.take(4).forEach { mod ->
                        Text(
                            text = "• $mod",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                    }
                    if (item.appliedModules.size > 4) {
                        Text(
                            text = "+ ${item.appliedModules.size - 4} more modules...",
                            style = MaterialTheme.typography.labelSmall,
                            color = NeonCyan
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    HexDataViewer(label = "SIGNATURE CERTIFICATE FINGERPRINT", value = item.signatureFingerprint)

                    Spacer(modifier = Modifier.height(12.dp))
                    // Row 1: Download & Share
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        CyberButton(
                            text = "DOWNLOAD",
                            onClick = {
                                val targetFile = if (item.outputPath.isNotEmpty()) File(item.outputPath) else null
                                if (targetFile != null && targetFile.exists()) {
                                    val (success, msg) = ApkExportHelper.saveToDownloads(context, targetFile)
                                    viewModel.showUiMessage(msg)
                                } else {
                                    viewModel.showUiMessage("APK file is no longer available on disk.")
                                }
                            },
                            icon = Icons.Default.Download,
                            isPrimary = true,
                            modifier = Modifier.weight(1f).testTag("history_download_${item.id}")
                        )

                        CyberButton(
                            text = "SHARE",
                            onClick = {
                                val targetFile = if (item.outputPath.isNotEmpty()) File(item.outputPath) else null
                                if (targetFile != null && targetFile.exists()) {
                                    val ok = ApkExportHelper.shareApk(context, targetFile)
                                    if (!ok) viewModel.showUiMessage("Unable to share APK.")
                                } else {
                                    viewModel.showUiMessage("APK file not found.")
                                }
                            },
                            icon = Icons.Default.Share,
                            isPrimary = false,
                            modifier = Modifier.weight(1f).testTag("history_share_${item.id}")
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Row 2: Install & Delete
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        CyberButton(
                            text = "INSTALL APK",
                            onClick = {
                                val targetFile = if (item.outputPath.isNotEmpty()) File(item.outputPath) else null
                                if (targetFile != null && targetFile.exists()) {
                                    val (success, msg) = ApkExportHelper.installApk(context, targetFile)
                                    viewModel.showUiMessage(msg)
                                } else {
                                    viewModel.showUiMessage("APK file not found.")
                                }
                            },
                            icon = Icons.Default.InstallMobile,
                            isPrimary = true,
                            modifier = Modifier.weight(1f).testTag("history_install_${item.id}")
                        )

                        CyberButton(
                            text = "DELETE",
                            onClick = { viewModel.deleteBuildRecord(item.id) },
                            icon = Icons.Default.Delete,
                            isPrimary = false,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }
    }
}
