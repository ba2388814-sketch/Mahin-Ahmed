package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.core.model.LicenseType
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun LicenseManagerScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val licenses by viewModel.repository.licenses.collectAsState()
    val config by viewModel.protectionConfig.collectAsState()
    var showCreateDialog by remember { mutableStateOf(false) }

    val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "Developer License Manager",
                subtitle = "Cryptographic client-side license verification, device activation, and remote revocation",
                badgeText = "${licenses.size} ACTIVE"
            )
        }

        item {
            CyberCard {
                Text(
                    text = "ONLINE VERIFICATION ENDPOINT",
                    style = MaterialTheme.typography.labelSmall,
                    color = NeonCyan
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = config.licenseServerUrl,
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextPrimary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Configured in assets/redx/license_policy.json with secure cryptographic signature token",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
            }
        }

        item {
            CyberButton(
                text = "ISSUE NEW APPLICATION LICENSE",
                onClick = { showCreateDialog = true },
                icon = Icons.Default.Add,
                isPrimary = true,
                modifier = Modifier.fillMaxWidth()
            )
        }

        items(licenses) { lic ->
            CyberCard(
                borderColor = if (lic.isRevoked) ElectricRed else CyberPanelBorder,
                backgroundColor = if (lic.isRevoked) CyberPanel.copy(alpha = 0.5f) else CyberPanelElevated
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = lic.licenseKey,
                                style = MaterialTheme.typography.titleMedium,
                                color = if (lic.isRevoked) ElectricRed else NeonCyan
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            CyberBadge(
                                text = if (lic.isRevoked) "REVOKED" else "VALID",
                                color = if (lic.isRevoked) ElectricRed else SecurityGreen
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Target: ${lic.targetPackage} • Type: ${lic.licenseType.label}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                    }

                    CyberButton(
                        text = if (lic.isRevoked) "RESTORE" else "REVOKE",
                        onClick = { viewModel.repository.toggleLicenseRevocation(lic.licenseKey) },
                        isPrimary = lic.isRevoked,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Expires: ${sdf.format(Date(lic.expiryTimestamp))}",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted
                    )
                    Text(
                        text = "Device Bound Limit: ${lic.maxDeviceCount} Nodes",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))
                HexDataViewer(label = "SIGNATURE VERIFICATION TOKEN", value = lic.signatureToken)
            }
        }
    }

    if (showCreateDialog) {
        var targetPkg by remember { mutableStateOf("com.redx.securevault") }
        var selectedType by remember { mutableStateOf(LicenseType.ANNUAL_SUBSCRIPTION) }
        var expiryDays by remember { mutableStateOf("365") }
        var maxDevices by remember { mutableStateOf("10") }

        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            title = {
                Text(
                    text = "ISSUE APPLICATION LICENSE",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = targetPkg,
                        onValueChange = { targetPkg = it },
                        label = { Text("Target Package ID") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = expiryDays,
                        onValueChange = { expiryDays = it },
                        label = { Text("Validity Duration (Days)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = maxDevices,
                        onValueChange = { maxDevices = it },
                        label = { Text("Max Authorized Devices") },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val d = expiryDays.toIntOrNull() ?: 365
                        val m = maxDevices.toIntOrNull() ?: 10
                        viewModel.generateNewLicense(targetPkg, selectedType, d, m)
                        showCreateDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricRed)
                ) {
                    Text("ISSUE LICENSE", color = TextPrimary)
                }
            },
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) {
                    Text("CANCEL", color = TextMuted)
                }
            },
            containerColor = CyberPanelElevated
        )
    }
}
