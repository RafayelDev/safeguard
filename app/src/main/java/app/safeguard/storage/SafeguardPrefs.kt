package app.safeguard.storage

import android.content.Context
import android.net.Uri

class SafeguardPrefs(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("safeguard", Context.MODE_PRIVATE)

    /** Persisted SAF tree URI of the folder that holds blocklist.txt. */
    var treeUri: Uri?
        get() = sp.getString(K_TREE, null)?.let { Uri.parse(it) }
        set(value) {
            sp.edit().putString(K_TREE, value?.toString()).apply()
        }

    /** True when the user wants protection running (used for restart and boot recovery). */
    var enabled: Boolean
        get() = sp.getBoolean(K_ENABLED, false)
        set(value) {
            sp.edit().putBoolean(K_ENABLED, value).apply()
        }

    private companion object {
        const val K_TREE = "tree_uri"
        const val K_ENABLED = "enabled"
    }
}
