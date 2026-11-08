package app.safeguard.storage

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Private copy of the last successfully applied blocklist; survives process death and reboot. */
class RuleCache(private val dir: File) {
    private val file = File(dir, "last_good_blocklist.txt")
    private val tmp = File(dir, "last_good_blocklist.txt.tmp")

    @Throws(IOException::class)
    fun load(): ByteArray? {
        if (!file.isFile) return null
        return file.inputStream().use { it.readLimited(BlocklistSource.MAX_BYTES) }
    }

    @Throws(IOException::class)
    fun save(bytes: ByteArray) {
        dir.mkdirs()
        FileOutputStream(tmp).use {
            it.write(bytes)
            it.fd.sync()
        }
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }
}
