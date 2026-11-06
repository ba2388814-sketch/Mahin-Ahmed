package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.core.model.DeveloperKeystore
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel

@Composable
fun SignatureManagerScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val keystores by viewModel.repository.keystores.collectAsState()
    val currentConfig by viewModel.protectionConfig.collectAsState()
    var showCreateDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "Signature & Keystore Manager",
                subtitle = "Manage developer RSA signing keys, certificate chains, and APK Signature Schemes",
                badgeText = "${keystores.size} KEYS"
            )
        }

        item {
            CyberButton(
                text = "GENERATE NEW DEVELOPER KEYSTORE",
                onClick = { showCreateDialog = true },
                icon = Icons.Default.Add,
                isPrimary = true,
                modifier = Modifier.fillMaxWidth()
            )
        }

        items(keystores) { key ->
            val isSelected = currentConfig.selectedKeyAlias == key.alias
            CyberCard(
                borderColor = if (isSelected) ElectricRed else CyberPanelBorder,
                backgroundColor = if (isSelected) CyberPanelElevated else CyberPanel
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                        Icon(
                            imageVector = Icons.Default.Key,
                            contentDescription = null,
                            tint = if (isSelected) ElectricRed else NeonCyan
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = key.keyName,
                                style = MaterialTheme.typography.titleMedium,
                                color = TextPrimary
                            )
                            Text(
                                text = "Alias: ${key.alias} • ${key.organization}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextSecondary
                            )
                        }
                    }

                    CyberButton(
                        text = if (isSelected) "SELECTED" else "USE KEY",
                        onClick = { viewModel.setSelectedKeystore(key.alias) },
                        enabled = !isSelected,
                        isPrimary = isSelected,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    CyberBadge(text = key.algorithm, color = NeonCyan)
                    CyberBadge(text = key.signatureScheme, color = SecurityGreen)
                    CyberBadge(text = "${key.validityYears} Years Valid", color = SecurityPurple)
                }

                Spacer(modifier = Modifier.height(10.dp))
                HexDataViewer(label = "SHA-256 CERTIFICATE FINGERPRINT", value = key.sha256Fingerprint, highlight = isSelected)
                Spacer(modifier = Modifier.height(4.dp))
                HexDataViewer(label = "SHA-1 FINGERPRINT", value = key.sha1Fingerprint)
            }
        }
    }

    if (showCreateDialog) {
        var alias by remember { mutableStateOf("my_release_key") }
        var commonName by remember { mutableStateOf("My Company Release") }
        var organization by remember { mutableStateOf("Mobile Security Team") }
        var country by remember { mutableStateOf("US") }
        var years by remember { mutableStateOf("25") }

        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            title = {
                Text(
                    text = "GENERATE DEVELOPER KEYSTORE",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = alias,
                        onValueChange = { alias = it },
                        label = { Text("Key Alias") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = commonName,
                        onValueChange = { commonName = it },
                        label = { Text("Common Name (CN)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = organization,
                        onValueChange = { organization = it },
                        label = { Text("Organization (O)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = country,
                            onValueChange = { country = it },
                            label = { Text("Country") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = years,
                            onValueChange = { years = it },
                            label = { Text("Validity (Years)") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val y = years.toIntOrNull() ?: 25
                        viewModel.createNewKeystore(alias, commonName, organization, country, y)
                        showCreateDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricRed)
                ) {
                    Text("GENERATE KEY", color = TextPrimary)
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
