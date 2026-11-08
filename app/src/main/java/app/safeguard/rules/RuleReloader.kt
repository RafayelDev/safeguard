package app.safeguard.rules

import app.safeguard.storage.BlocklistSource
import app.safeguard.storage.RuleCache
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference

enum class RefreshResult { APPLIED, UNCHANGED, MISSING, UNREADABLE, UNSTABLE, CORRUPT }

/**
 * Reads the blocklist and swaps the active [RuleSet] atomically.
 * On any problem (missing file, I/O error, corrupt content, file still being written)
 * the last working rules stay active.
 */
class RuleReloader(
    private val source: BlocklistSource,
    private val cache: RuleCache?,
    private val stabilityDelayMs: Long = 400L,
) {
    private val ref = AtomicReference(RuleSet.EMPTY)
    private var appliedHash: String? = null
    private var rejectedHash: String? = null

    val rules: RuleSet get() = ref.get()

    /** Restores the last good rules persisted by a previous run. */
    @Synchronized
    fun loadFromCache(): Boolean {
        val bytes: ByteArray? = try {
            cache?.load()
        } catch (e: IOException) {
            null
        }
        if (bytes == null) return false
        val parsed = BlocklistParser.parse(bytes) ?: return false
        ref.set(RuleSet(parsed.domains))
        appliedHash = hash(bytes)
        return true
    }

    @Synchronized
    fun refresh(): RefreshResult {
        val first: ByteArray? = try {
            source.read()
        } catch (e: IOException) {
            return RefreshResult.UNREADABLE
        } catch (e: RuntimeException) {
            return RefreshResult.UNREADABLE
        }
        if (first == null) return RefreshResult.MISSING

        val h1 = hash(first)
        if (h1 == appliedHash) return RefreshResult.UNCHANGED
        if (h1 == rejectedHash) return RefreshResult.CORRUPT

        // Editors may truncate-then-write: require identical content on two reads before applying.
        if (stabilityDelayMs > 0) Thread.sleep(stabilityDelayMs)
        val second: ByteArray? = try {
            source.read()
        } catch (e: IOException) {
            return RefreshResult.UNREADABLE
        } catch (e: RuntimeException) {
            return RefreshResult.UNREADABLE
        }
        if (second == null || !second.contentEquals(first)) return RefreshResult.UNSTABLE

        val parsed = BlocklistParser.parse(first)
        if (parsed == null) {
            rejectedHash = h1
            return RefreshResult.CORRUPT
        }
        ref.set(RuleSet(parsed.domains))
        appliedHash = h1
        rejectedHash = null
        try {
            cache?.save(first)
        } catch (e: IOException) {
            // cache is best-effort
        }
        return RefreshResult.APPLIED
    }

    private fun hash(bytes: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(bytes)
        return d.joinToString("") { "%02x".format(it) }
    }
}
