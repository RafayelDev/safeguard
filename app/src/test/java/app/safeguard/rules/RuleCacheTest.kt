package app.safeguard.rules

import app.safeguard.storage.RuleCache
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RuleCacheTest {
    @Test fun roundTripAndOverwrite() {
        val dir = Files.createTempDirectory("sg-cache2").toFile()
        try {
            val cache = RuleCache(dir)
            assertNull(cache.load())
            cache.save("one.com\n".toByteArray())
            assertArrayEquals("one.com\n".toByteArray(), cache.load())
            cache.save("two.com\n".toByteArray())
            assertArrayEquals("two.com\n".toByteArray(), cache.load())
        } finally {
            dir.deleteRecursively()
        }
    }
}
