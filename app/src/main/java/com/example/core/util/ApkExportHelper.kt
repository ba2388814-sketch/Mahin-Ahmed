package com.example.core.util

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

object ApkExportHelper {

    fun saveToDownloads(context: Context, sourceApk: File): Pair<Boolean, String> {
        try {
            val fileName = sourceApk.name

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/vnd.android.package-archive")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/RED-X")
                }

                val resolver = context.contentResolver
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                    ?: return fallbackCopy(context, sourceApk)

                resolver.openOutputStream(uri)?.use { out ->
                    sourceApk.inputStream().use { input ->
                        input.copyTo(out)
                    }
                }
                return Pair(true, "Saved to Downloads/RED-X/$fileName")
            } else {
                @Suppress("DEPRECATION")
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val targetDir = File(downloadsDir, "RED-X")
                if (!targetDir.exists()) targetDir.mkdirs()
                val targetFile = File(targetDir, fileName)
                sourceApk.copyTo(targetFile, overwrite = true)
                return Pair(true, "Saved to ${targetFile.absolutePath}")
            }
        } catch (e: Exception) {
            return fallbackCopy(context, sourceApk)
        }
    }

    private fun fallbackCopy(context: Context, sourceApk: File): Pair<Boolean, String> {
        return try {
            val extDir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                ?: context.filesDir
            val dest = File(extDir, sourceApk.name)
            sourceApk.copyTo(dest, overwrite = true)
            Pair(true, "Saved to ${dest.absolutePath}")
        } catch (e: Exception) {
            Pair(false, "Failed to save: ${e.message}")
        }
    }

    fun shareApk(context: Context, apkFile: File): Boolean {
        return try {
            if (!apkFile.exists()) return false
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                apkFile
            )
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/vnd.android.package-archive"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "Protected APK: ${apkFile.name}")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val chooser = Intent.createChooser(intent, "Share Protected APK")
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(chooser)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun installApk(context: Context, apkFile: File): Pair<Boolean, String> {
        try {
            if (!apkFile.exists()) return Pair(false, "APK file not found.")

            // On Android 8.0+ (Oreo), verify unknown app install permission
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (!context.packageManager.canRequestPackageInstalls()) {
                    val settingsIntent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                        data = Uri.parse("package:${context.packageName}")
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(settingsIntent)
                    return Pair(false, "Please grant 'Install Unknown Apps' permission in Settings, then tap Install again.")
                }
            }

            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                apkFile
            )

            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(installIntent)
            return Pair(true, "Launching Android Package Installer...")
        } catch (e: Exception) {
            return Pair(false, "Cannot launch installer: ${e.message}")
        }
    }
}
