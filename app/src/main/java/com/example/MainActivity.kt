package com.example

import android.content.ContentResolver
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.components.CyberBadge
import com.example.ui.screens.*
import com.example.ui.theme.*
import com.example.ui.viewmodel.MainViewModel
import com.example.ui.viewmodel.ScreenTab
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                RedXApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RedXApp(viewModel: MainViewModel = viewModel()) {
    val currentTab by viewModel.currentTab.collectAsState()
    val uiMessage by viewModel.uiMessage.collectAsState()
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

    val context = androidx.compose.ui.platform.LocalContext.current

    // SAF File Picker
    val pickApkLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            val displayName = queryDisplayName(context.contentResolver, uri) ?: "uploaded_target.apk"
            viewModel.selectApkUri(uri, displayName)
        }
    }

    // Handle back button: return to Home if on other screen
    if (currentTab != ScreenTab.HOME) {
        BackHandler {
            viewModel.setTab(ScreenTab.HOME)
        }
    }

    // Show Snackbar when uiMessage updates
    LaunchedEffect(uiMessage) {
        if (!uiMessage.isNullOrBlank()) {
            snackbarHostState.showSnackbar(uiMessage!!)
            viewModel.clearUiMessage()
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = CyberPanel,
                drawerContentColor = TextPrimary,
                modifier = Modifier.width(300.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(CyberPanelElevated)
                        .padding(20.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(ElectricRed.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
                                .border(1.dp, ElectricRed, RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = null,
                                tint = ElectricRed,
                                modifier = Modifier.size(22.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "RED-X ULTRA",
                                style = MaterialTheme.typography.titleLarge,
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "v3.2.0 • Security Core",
                                style = MaterialTheme.typography.labelSmall,
                                color = NeonCyan
                            )
                        }
                    }
                }

                HorizontalDivider(color = CyberPanelBorder)

                Column(
                    modifier = Modifier
                        .fillMaxHeight()
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    ScreenTab.entries.forEach { tab ->
                        val isSelected = currentTab == tab
                        NavigationDrawerItem(
                            icon = {
                                Icon(
                                    imageVector = getTabIcon(tab),
                                    contentDescription = tab.title,
                                    tint = if (isSelected) ElectricRed else TextSecondary
                                )
                            },
                            label = {
                                Text(
                                    text = tab.title.uppercase(),
                                    style = MaterialTheme.typography.labelLarge,
                                    color = if (isSelected) TextPrimary else TextSecondary,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                                )
                            },
                            selected = isSelected,
                            onClick = {
                                viewModel.setTab(tab)
                                scope.launch { drawerState.close() }
                            },
                            colors = NavigationDrawerItemDefaults.colors(
                                selectedContainerColor = CyberPanelElevated,
                                unselectedContainerColor = CyberPanel
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.testTag("drawer_tab_${tab.name.lowercase()}")
                        )
                    }
                }
            }
        }
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "RED-X",
                                style = MaterialTheme.typography.titleLarge,
                                color = ElectricRed,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = currentTab.title.uppercase(),
                                style = MaterialTheme.typography.titleLarge,
                                color = TextPrimary
                            )
                        }
                    },
                    navigationIcon = {
                        IconButton(
                            onClick = { scope.launch { drawerState.open() } },
                            modifier = Modifier.testTag("navigation_drawer_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.Menu,
                                contentDescription = "Menu",
                                tint = TextPrimary
                            )
                        }
                    },
                    actions = {
                        IconButton(
                            onClick = { pickApkLauncher.launch("application/vnd.android.package-archive") },
                            modifier = Modifier.testTag("appbar_upload_button")
                        ) {
                            Icon(
                                imageVector = Icons.Default.FolderOpen,
                                contentDescription = "Select APK",
                                tint = NeonCyan
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = CyberBlack,
                        titleContentColor = TextPrimary
                    )
                )
            },
            bottomBar = {
                NavigationBar(
                    containerColor = CyberPanel,
                    contentColor = TextPrimary,
                    tonalElevation = 8.dp,
                    windowInsets = WindowInsets.navigationBars
                ) {
                    val primaryTabs = listOf(
                        ScreenTab.HOME,
                        ScreenTab.PROTECT,
                        ScreenTab.ANALYZER,
                        ScreenTab.HISTORY,
                        ScreenTab.SETTINGS
                    )

                    primaryTabs.forEach { tab ->
                        val isSelected = currentTab == tab
                        NavigationBarItem(
                            icon = {
                                Icon(
                                    imageVector = getTabIcon(tab),
                                    contentDescription = tab.title,
                                    modifier = Modifier.size(22.dp)
                                )
                            },
                            label = {
                                Text(
                                    text = tab.title,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontSize = 10.sp
                                )
                            },
                            selected = isSelected,
                            onClick = { viewModel.setTab(tab) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = ElectricRed,
                                selectedTextColor = ElectricRed,
                                indicatorColor = CyberPanelElevated,
                                unselectedIconColor = TextMuted,
                                unselectedTextColor = TextMuted
                            ),
                            modifier = Modifier.testTag("bottom_tab_${tab.name.lowercase()}")
                        )
                    }
                }
            },
            snackbarHost = {
                SnackbarHost(
                    hostState = snackbarHostState,
                    modifier = Modifier.padding(16.dp)
                ) { data ->
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(CyberPanelElevated, RoundedCornerShape(8.dp))
                            .border(1.dp, NeonCyan.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
                            .padding(14.dp)
                    ) {
                        Text(
                            text = data.visuals.message,
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextPrimary
                        )
                    }
                }
            },
            containerColor = CyberBlack
        ) { paddingValues ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
            ) {
                AnimatedContent(
                    targetState = currentTab,
                    transitionSpec = { fadeIn() togetherWith fadeOut() },
                    label = "TabTransition"
                ) { tab ->
                    when (tab) {
                        ScreenTab.HOME -> HomeScreen(viewModel, onLaunchFilePicker = { pickApkLauncher.launch("*/*") })
                        ScreenTab.PROTECT -> ProtectScreen(viewModel, onLaunchFilePicker = { pickApkLauncher.launch("*/*") })
                        ScreenTab.ANALYZER -> AnalyzerScreen(viewModel, onLaunchFilePicker = { pickApkLauncher.launch("*/*") })
                        ScreenTab.SECURITY_ENGINE -> SecurityEngineScreen(viewModel)
                        ScreenTab.PROFILES -> ProfilesScreen(viewModel)
                        ScreenTab.SIGNATURES -> SignatureManagerScreen(viewModel)
                        ScreenTab.LICENSES -> LicenseManagerScreen(viewModel)
                        ScreenTab.HISTORY -> HistoryScreen(viewModel)
                        ScreenTab.REPORTS -> ReportsScreen(viewModel)
                        ScreenTab.SETTINGS -> SettingsScreen(viewModel)
                    }
                }
            }
        }
    }
}

private fun getTabIcon(tab: ScreenTab): ImageVector {
    return when (tab) {
        ScreenTab.HOME -> Icons.Default.Dashboard
        ScreenTab.PROTECT -> Icons.Default.Shield
        ScreenTab.ANALYZER -> Icons.Default.Search
        ScreenTab.SECURITY_ENGINE -> Icons.Default.Security
        ScreenTab.PROFILES -> Icons.Default.Tune
        ScreenTab.SIGNATURES -> Icons.Default.Key
        ScreenTab.LICENSES -> Icons.Default.VpnKey
        ScreenTab.HISTORY -> Icons.Default.History
        ScreenTab.REPORTS -> Icons.Default.Assessment
        ScreenTab.SETTINGS -> Icons.Default.Settings
    }
}

private fun queryDisplayName(resolver: ContentResolver, uri: Uri): String? {
    return try {
        resolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex != -1 && cursor.moveToFirst()) {
                cursor.getString(nameIndex)
            } else null
        }
    } catch (_: Exception) {
        null
    }
}
