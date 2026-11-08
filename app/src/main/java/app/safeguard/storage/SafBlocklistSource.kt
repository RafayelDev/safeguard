package app.safeguard.storage

import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Handler
import android.os.HandlerThread
import android.provider.DocumentsContract
import java.io.IOException

/**
 * Reads blocklist.txt from a SAF folder. The document is looked up by name on every read, so a
 * file replaced by an editor (new document, same name) is picked up.
 */
class SafBlocklistSource(
    private val context: Context,
    private val treeUri: Uri,
) : BlocklistSource {

    override fun read(): ByteArray? {
        try {
            val doc = findDocument() ?: return null
            val stream = context.contentResolver.openInputStream(doc)
                ?: throw IOException("provider returned null stream")
            return stream.use { it.readLimited(BlocklistSource.MAX_BYTES) }
        } catch (e: IOException) {
            throw e
        } catch (e: Exception) {
            throw IOException("SAF read failed: ${e.message}", e)
        }
    }

    internal fun findDocument(): Uri? {
        val cursor = context.contentResolver.query(
            childrenUri(treeUri),
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
            ),
            null, null, null,
        ) ?: throw IOException("provider returned null cursor")
        cursor.use { c ->
            while (c.moveToNext()) {
                val name = c.getString(1)
                val mime = c.getString(2)
                if (name == FILE_NAME && mime != DocumentsContract.Document.MIME_TYPE_DIR) {
                    return DocumentsContract.buildDocumentUriUsingTree(treeUri, c.getString(0))
                }
            }
        }
        return null
    }

    companion object {
        const val FILE_NAME = "blocklist.txt"
        private const val TEMPLATE =
            "# SAFEGUARD BLOCKLIST\n# One domain per line. Subdomains are blocked too.\n\n"

        fun childrenUri(tree: Uri): Uri =
            DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))

        /** Creates an empty blocklist.txt in the chosen folder when it does not exist yet. */
        @Throws(IOException::class)
        fun ensureFile(context: Context, tree: Uri) {
            if (SafBlocklistSource(context, tree).findDocument() != null) return
            val parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
            val created = DocumentsContract.createDocument(context.contentResolver, parent, "text/plain", FILE_NAME)
                ?: throw IOException("cannot create $FILE_NAME")
            context.contentResolver.openOutputStream(created, "wt")?.use {
                it.write(TEMPLATE.toByteArray(Charsets.UTF_8))
            }
        }
    }
}

/** Notifies when the folder content changes (if the provider supports it). Polling is the fallback. */
class BlocklistObserver(
    private val context: Context,
    private val treeUri: Uri,
    private val callback: () -> Unit,
) {
    private var thread: HandlerThread? = null
    private var observer: ContentObserver? = null

    fun start() {
        val t = HandlerThread("sg-observer")
        t.start()
        thread = t
        val o = object : ContentObserver(Handler(t.looper)) {
            override fun onChange(selfChange: Boolean) {
                callback()
            }
        }
        observer = o
        try {
            context.contentResolver.registerContentObserver(SafBlocklistSource.childrenUri(treeUri), true, o)
        } catch (e: Exception) {
            // provider does not support observing; the 5 s poll still works
        }
    }

    fun stop() {
        observer?.let {
            try {
                context.contentResolver.unregisterContentObserver(it)
            } catch (e: Exception) {
            }
        }
        observer = null
        thread?.quitSafely()
        thread = null
    }
}
