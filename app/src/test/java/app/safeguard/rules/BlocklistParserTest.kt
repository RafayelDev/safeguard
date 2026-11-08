package app.safeguard.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BlocklistParserTest {
    private fun parse(text: String) = BlocklistParser.parse(text.toByteArray(Charsets.UTF_8))

    @Test fun parsesSampleFile() {
        val r = parse("# SAFEGUARD BLOCKLIST\n\nexample.com\ncasino-example.net\nunwanted-site.org\n")!!
        assertEquals(setOf("example.com", "casino-example.net", "unwanted-site.org"), r.domains)
        assertEquals(0, r.invalidLines)
    }

    @Test fun ignoresCommentsBlankLinesAndInlineComments() {
        val r = parse("# c\n\n   \nexample.com # inline\n#another.com\n")!!
        assertEquals(setOf("example.com"), r.domains)
    }

    @Test fun deduplicatesAfterNormalization() {
        val r = parse("Example.com\nexample.com.\n*.example.com\n")!!
        assertEquals(1, r.domains.size)
        assertEquals(2, r.duplicates)
    }

    @Test fun handlesCrLfCrAndBom() {
        val r = parse("\uFEFFa.com\r\nb.com\rc.com\n")!!
        assertEquals(setOf("a.com", "b.com", "c.com"), r.domains)
    }

    @Test fun skipsInvalidLinesButKeepsValidOnes() {
        val r = parse("good.com\nhttps://bad\nalso-good.org\n")!!
        assertEquals(setOf("good.com", "also-good.org"), r.domains)
        assertEquals(1, r.invalidLines)
    }

    @Test fun emptyAndCommentOnlyFilesAreValidAndBlockNothing() {
        assertTrue(BlocklistParser.parse(ByteArray(0))!!.domains.isEmpty())
        assertTrue(parse("# nothing here\n\n")!!.domains.isEmpty())
    }

    @Test fun supportsIdnLines() {
        val r = parse("пример.рф\n")!!
        assertEquals(setOf("xn--e1afmkfd.xn--p1ai"), r.domains)
    }

    @Test fun binaryOrInvalidUtf8IsCorrupt() {
        assertNull(BlocklistParser.parse(byteArrayOf(0x41, 0x00, 0x42)))
        assertNull(BlocklistParser.parse(byteArrayOf(0xC3.toByte(), 0x28)))
    }

    @Test fun fileWithOnlyGarbageLinesIsCorrupt() {
        assertNull(parse("!!!\n???\nnot a domain\n"))
    }

    @Test fun decodeAcceptsPlainUtf8() {
        assertNotNull(BlocklistParser.decode("пример.рф".toByteArray(Charsets.UTF_8)))
    }
}
