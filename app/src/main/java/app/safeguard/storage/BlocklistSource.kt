package app.safeguard.storage

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

interface BlocklistSource {
    /** Returns the file bytes, or null when the file does not exist. */
    @Throws(IOException::class)
    fun read(): ByteArray?

    companion object {
        const val MAX_BYTES = 16 * 1024 * 1024
    }
}

object NullBlocklistSource : BlocklistSource {
    override fun read(): ByteArray? = null
}

@Throws(IOException::class)
fun InputStream.readLimited(max: Int): ByteArray {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(8192)
    var total = 0
    while (true) {
        val n = read(buf)
        if (n < 0) break
        total += n
        if (total > max) throw IOException("file too large")
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}
