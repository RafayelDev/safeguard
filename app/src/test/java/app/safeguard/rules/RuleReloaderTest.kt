package app.safeguard.rules

import app.safeguard.storage.BlocklistSource
import app.safeguard.storage.RuleCache
import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RuleReloaderTest {
    private class FakeSource : BlocklistSource {
        @Volatile var content: ByteArray? = null
        @Volatile var failure: IOException? = null
        var perReadOverride: ((Int) -> ByteArray?)? = null
        private var reads = 0

        fun set(text: String) { content = text.toByteArray(Charsets.UTF_8) }

        override fun read(): ByteArray? {
            failure?.let { throw it }
            val o = perReadOverride
            if (o != null) return o(reads++)
            return content
        }
    }

    private lateinit var dir: File
    private val source = FakeSource()

    @Before fun setUp() { dir = Files.createTempDirectory("sg-cache").toFile() }
    @After fun tearDown() { dir.deleteRecursively() }

    private fun reloader(cache: RuleCache? = null) = RuleReloader(source, cache, stabilityDelayMs = 0)

    @Test fun appliesNewRulesAndReportsUnchanged() {
        val r = reloader()
        source.set("a.com\n")
        assertEquals(RefreshResult.APPLIED, r.refresh())
        assertTrue(r.rules.isBlocked("www.a.com"))
        assertEquals(RefreshResult.UNCHANGED, r.refresh())
    }

    @Test fun editsAreAppliedWithoutRestart() {
        val r = reloader()
        source.set("a.com\n")
        r.refresh()
        source.set("a.com\nb.org\n")
        assertEquals(RefreshResult.APPLIED, r.refresh())
        assertTrue(r.rules.isBlocked("b.org"))
        source.set("b.org\n")
        r.refresh()
        assertFalse(r.rules.isBlocked("a.com"))
    }

    @Test fun emptyFileClearsRules() {
        val r = reloader()
        source.set("a.com\n")
        r.refresh()
        source.set("")
        assertEquals(RefreshResult.APPLIED, r.refresh())
        assertFalse(r.rules.isBlocked("a.com"))
    }

    @Test fun corruptFileKeepsLastGoodRules() {
        val r = reloader()
        source.set("a.com\n")
        r.refresh()
        source.content = byteArrayOf(0, 1, 2, 3)
        assertEquals(RefreshResult.CORRUPT, r.refresh())
        assertEquals(RefreshResult.CORRUPT, r.refresh())
        assertTrue(r.rules.isBlocked("a.com"))
        source.set("c.net\n")
        assertEquals(RefreshResult.APPLIED, r.refresh())
        assertTrue(r.rules.isBlocked("c.net"))
    }

    @Test fun missingFileAndIoErrorsKeepLastGoodRules() {
        val r = reloader()
        source.set("a.com\n")
        r.refresh()
        source.content = null
        assertEquals(RefreshResult.MISSING, r.refresh())
        assertTrue(r.rules.isBlocked("a.com"))
        source.failure = IOException("boom")
        assertEquals(RefreshResult.UNREADABLE, r.refresh())
        assertTrue(r.rules.isBlocked("a.com"))
        source.failure = null
        source.set("a.com\n")
        assertEquals(RefreshResult.UNCHANGED, r.refresh())
    }

    @Test fun fileChangingBetweenTwoReadsIsNotAppliedYet() {
        val r = reloader()
        source.set("a.com\n")
        r.refresh()
        source.perReadOverride = { n -> if (n == 0) "x.com\n".toByteArray() else "".toByteArray() }
        assertEquals(RefreshResult.UNSTABLE, r.refresh())
        assertTrue(r.rules.isBlocked("a.com"))
        assertFalse(r.rules.isBlocked("x.com"))
    }

    @Test fun restoresLastGoodRulesFromCacheAfterRestart() {
        val cache = RuleCache(dir)
        val first = reloader(cache)
        source.set("a.com\n")
        first.refresh()

        val second = reloader(RuleCache(dir)) // "new process"
        source.failure = IOException("storage not available yet")
        assertTrue(second.loadFromCache())
        assertTrue(second.rules.isBlocked("a.com"))
        assertEquals(RefreshResult.UNREADABLE, second.refresh())
        assertTrue(second.rules.isBlocked("a.com"))
        source.failure = null
        assertEquals(RefreshResult.UNCHANGED, second.refresh())
    }
}
