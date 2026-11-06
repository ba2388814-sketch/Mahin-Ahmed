package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.core.model.SecurityModule
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel

@Composable
fun SecurityEngineScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val config by viewModel.protectionConfig.collectAsState()
    var selectedCategory by remember { mutableStateOf("ALL") }

    val categories = listOf("ALL", "Code Security", "Integrity", "Authentication", "Data Protection", "Binary Security", "Runtime Defense", "Licensing")

    val filteredModules = if (selectedCategory == "ALL") {
        SecurityModule.entries
    } else {
        SecurityModule.entries.filter { it.category == selectedCategory }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "12 Modular Security Engines",
                subtitle = "Fine-grained control over individual protection layers and runtime hooks",
                badgeText = "${config.enabledModules.count { it.value }}/12 ACTIVE"
            )
        }

        item {
            CyberCard(
                borderColor = SecurityGreen.copy(alpha = 0.4f),
                backgroundColor = CyberPanelElevated
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "SECURITY ARCHITECT & DEVELOPER",
                            style = MaterialTheme.typography.labelSmall,
                            color = SecurityGreen
                        )
                        Text(
                            text = "A.K.M REDWAN",
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
                        )
                        Text(
                            text = "Android Application Developer & Security Researcher (APK modification, reverse engineering, security auditing)",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                    CyberBadge(text = "VERIFIED", color = SecurityGreen)
                }
            }
        }

        // CATEGORY CHIPS
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(categories) { cat ->
                    val isSelected = selectedCategory == cat
                    Box(
                        modifier = Modifier
                            .background(if (isSelected) ElectricRed else CyberPanel, RoundedCornerShape(20.dp))
                            .border(1.dp, if (isSelected) ElectricRed else CyberPanelBorder, RoundedCornerShape(20.dp))
                            .padding(horizontal = 14.dp, vertical = 6.dp)
                    ) {
                        TextButton(
                            onClick = { selectedCategory = cat },
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text(
                                text = cat,
                                style = MaterialTheme.typography.labelSmall,
                                color = if (isSelected) TextPrimary else TextSecondary
                            )
                        }
                    }
                }
            }
        }

        items(filteredModules) { module ->
            val isEnabled = config.isModuleEnabled(module)
            CyberCard(
                borderColor = if (isEnabled) ElectricRed.copy(alpha = 0.5f) else CyberPanelBorder,
                backgroundColor = if (isEnabled) CyberPanelElevated else CyberPanel
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = module.title,
                                style = MaterialTheme.typography.titleMedium,
                                color = if (isEnabled) TextPrimary else TextMuted
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            CyberBadge(text = module.category, color = NeonCyan)
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = module.description,
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                    }

                    Switch(
                        checked = isEnabled,
                        onCheckedChange = { viewModel.toggleModule(module, it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = TextPrimary,
                            checkedTrackColor = ElectricRed,
                            uncheckedThumbColor = TextMuted,
                            uncheckedTrackColor = CyberPanel
                        )
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Compatibility Rule: Automatic reflection & framework preservation active",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted
                    )
                    Text(
                        text = if (isEnabled) "Active in build" else "Skipped",
                        style = MaterialTheme.typography.labelSmall,
                        color = if (isEnabled) SecurityGreen else TextMuted
                    )
                }
            }
        }
    }
}
