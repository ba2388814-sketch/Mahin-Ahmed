package com.example.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel

@Composable
fun SettingsScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val config by viewModel.protectionConfig.collectAsState()
    var watermarkText by remember(config.developerWatermark) { mutableStateOf(config.developerWatermark) }
    var serverUrl by remember(config.licenseServerUrl) { mutableStateOf(config.licenseServerUrl) }
    var expiryDaysText by remember(config.licenseExpiryDays) { mutableStateOf(config.licenseExpiryDays.toString()) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "Settings & Workspace",
                subtitle = "Manage security engine parameters, build storage, and licensing policies",
                badgeText = "v3.2.0"
            )
        }

        // WATERMARK & IDENTITY
        item {
            CyberCard {
                Text(
                    text = "DEVELOPER WATERMARK CONFIGURATION",
                    style = MaterialTheme.typography.labelSmall,
                    color = NeonCyan
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = watermarkText,
                    onValueChange = { watermarkText = it },
                    label = { Text("Watermark String") },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                CyberButton(
                    text = "SAVE WATERMARK",
                    onClick = { viewModel.setDeveloperWatermark(watermarkText) },
                    icon = Icons.Default.Save,
                    isPrimary = false
                )
            }
        }

        // LICENSING ENDPOINT
        item {
            CyberCard {
                Text(
                    text = "LICENSE SERVER & DURATION",
                    style = MaterialTheme.typography.labelSmall,
                    color = NeonCyan
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = { serverUrl = it },
                    label = { Text("Remote Verification Server Endpoint") },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = expiryDaysText,
                    onValueChange = { expiryDaysText = it },
                    label = { Text("Default Expiry Duration (Days)") },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                CyberButton(
                    text = "UPDATE LICENSE POLICY",
                    onClick = {
                        val days = expiryDaysText.toIntOrNull() ?: 365
                        viewModel.setLicenseConfig(serverUrl, days)
                    },
                    icon = Icons.Default.Save,
                    isPrimary = false
                )
            }
        }

        // WORKSPACE CLEANUP
        item {
            CyberCard {
                Text(
                    text = "WORKSPACE CLEANUP",
                    style = MaterialTheme.typography.labelSmall,
                    color = ElectricRed
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Removes temporary unpacked DEX cache files and intermediate build archives while preserving your original APK and build logs.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(12.dp))
                CyberButton(
                    text = "PURGE TEMPORARY WORKSPACE",
                    onClick = { viewModel.clearWorkspace() },
                    icon = Icons.Default.CleaningServices,
                    isPrimary = true
                )
            }
        }

        // SYSTEM DIAGNOSTICS & SPECS
        item {
            CyberCard {
                Text(
                    text = "RED-X SECURITY ENGINE SPECS",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
                Spacer(modifier = Modifier.height(8.dp))
                HexDataViewer(label = "ENGINE CORE", value = "RED-X ULTRA v3.2.0-PROD")
                Spacer(modifier = Modifier.height(4.dp))
                HexDataViewer(label = "BYTECODE TARGET", value = "Dalvik DEX v035 - v039 / Android ART Multi-Dex")
                Spacer(modifier = Modifier.height(4.dp))
                HexDataViewer(label = "SIGNATURE SCHEMES", value = "APK Signature Scheme v1 (JAR) & v2 (Full APK)")
                Spacer(modifier = Modifier.height(4.dp))
                HexDataViewer(label = "INTEGRITY ALGORITHM", value = "SHA-256 HMAC Digital Sealing & Verification")
            }
        }
    }
}
