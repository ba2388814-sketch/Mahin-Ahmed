package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.core.model.ProtectionConfig
import com.example.core.model.ProtectionProfile
import com.example.core.model.SecurityModule
import com.example.ui.components.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel

@Composable
fun ProfilesScreen(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val currentConfig by viewModel.protectionConfig.collectAsState()

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 40.dp)
    ) {
        item {
            SectionHeader(
                title = "Protection Profiles",
                subtitle = "Pre-configured security presets engineered for different application requirements",
                badgeText = currentConfig.profile.name
            )
        }

        items(ProtectionProfile.entries) { profile ->
            val isSelected = currentConfig.profile == profile
            val activeModules = ProtectionConfig.defaultForProfile(profile)

            CyberCard(
                borderColor = if (isSelected) ElectricRed else CyberPanelBorder,
                backgroundColor = if (isSelected) CyberPanelElevated else CyberPanel,
                glowEffect = isSelected
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = profile.title,
                                style = MaterialTheme.typography.titleLarge,
                                color = if (profile.isRedwanHome) SecurityGreen else if (isSelected) ElectricRed else TextPrimary,
                                fontWeight = FontWeight.Bold
                            )
                            if (profile.isRedwanHome) {
                                Spacer(modifier = Modifier.width(8.dp))
                                CyberBadge(text = "RECOMMENDED", color = SecurityGreen)
                            }
                            if (isSelected) {
                                Spacer(modifier = Modifier.width(8.dp))
                                CyberBadge(text = "CURRENT ACTIVE", color = SecurityGreen)
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = profile.description,
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Recommended for: ${profile.recommendedFor}",
                            style = MaterialTheme.typography.labelSmall,
                            color = NeonCyan
                        )
                        if (profile.isRedwanHome) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(SecurityGreen.copy(alpha = 0.08f), RoundedCornerShape(6.dp))
                                    .border(1.dp, SecurityGreen.copy(alpha = 0.3f), RoundedCornerShape(6.dp))
                                    .padding(8.dp)
                            ) {
                                Text(
                                    text = "🛡️ ZERO-CRASH GUARANTEE: Preserves original UI, Layout, Login, API, Firebase, Database & Background Services. Features automatic immutable backup & v1+v2 signing block.",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = SecurityGreen
                                )
                            }
                        }
                    }

                    CyberButton(
                        text = if (isSelected) "ACTIVE" else "ACTIVATE",
                        onClick = { viewModel.setProfile(profile) },
                        enabled = !isSelected,
                        isPrimary = !isSelected,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }

                HorizontalDivider(
                    color = CyberPanelBorder,
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                Text(
                    text = "MODULE INCLUSION MATRIX (${activeModules.count { it.value }}/12):",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
                Spacer(modifier = Modifier.height(6.dp))

                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    SecurityModule.entries.forEach { module ->
                        val included = activeModules[module] ?: false
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = if (included) Icons.Default.Check else Icons.Default.Close,
                                contentDescription = null,
                                tint = if (included) SecurityGreen else TextMuted,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = module.title,
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (included) TextPrimary else TextMuted
                            )
                        }
                    }
                }
            }
        }
    }
}
