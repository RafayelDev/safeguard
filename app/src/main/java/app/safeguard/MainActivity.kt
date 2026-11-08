package app.safeguard

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.DocumentsContract
import android.util.Log
import app.safeguard.service.SafeguardVpnService
import app.safeguard.storage.SafBlocklistSource
import app.safeguard.storage.SafeguardPrefs

/**
 * Technical activity without a layout. Steps: notification permission -> pick the SAFEGUARD folder
 * (persistent SAF grant) -> VPN consent -> start the service and close.
 */
class MainActivity : Activity() {
    private lateinit var prefs: SafeguardPrefs
    private var notificationsAsked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = SafeguardPrefs(this)
        advance()
    }

    private fun advance() {
        if (!notificationsAsked &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationsAsked = true
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
            return
        }
        if (!hasFolderAccess()) {
            pickFolder()
            return
        }
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, REQ_VPN)
            return
        }
        startProtection()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIFICATIONS) advance() // denial is fine: VPN works without the notification UI
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_FOLDER -> {
                val uri = data?.data
                if (resultCode == RESULT_OK && uri != null && saveFolder(uri)) advance() else finish()
            }
            REQ_VPN -> if (resultCode == RESULT_OK) advance() else finish()
        }
    }

    private fun hasFolderAccess(): Boolean {
        val uri = prefs.treeUri ?: return false
        return contentResolver.persistedUriPermissions.any {
            it.uri == uri && it.isReadPermission && it.isWritePermission
        }
    }

    private fun pickFolder() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
        )
        intent.putExtra(
            DocumentsContract.EXTRA_INITIAL_URI,
            DocumentsContract.buildDocumentUri("com.android.externalstorage.documents", "primary:SAFEGUARD"),
        )
        startActivityForResult(intent, REQ_FOLDER)
    }

    private fun saveFolder(uri: Uri): Boolean {
        try {
            contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        } catch (e: SecurityException) {
            Log.w(TAG, "cannot persist folder permission", e)
            return false
        }
        prefs.treeUri = uri
        try {
            SafBlocklistSource.ensureFile(this, uri)
        } catch (e: Exception) {
            Log.w(TAG, "cannot create blocklist.txt", e)
        }
        return true
    }

    private fun startProtection() {
        prefs.enabled = true
        startForegroundService(Intent(this, SafeguardVpnService::class.java).setAction(SafeguardVpnService.ACTION_START))
        finish()
    }

    private companion object {
        const val TAG = "SafeguardMain"
        const val REQ_NOTIFICATIONS = 1
        const val REQ_FOLDER = 2
        const val REQ_VPN = 3
    }
}
