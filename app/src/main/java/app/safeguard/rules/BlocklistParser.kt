package app.safeguard.rules

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

class ParseResult(val domains: Set<String>, val invalidLines: Int, val duplicates: Int)

object BlocklistParser {

    /** Strict UTF-8 decode. Returns null for binary data (NUL bytes) or invalid UTF-8. */
    fun decode(bytes: ByteArray): String? {
        for (b in bytes) {
            if (b.toInt() == 0) return null
        }
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (e: CharacterCodingException) {
            null
        }
    }

    fun parseText(text: String): ParseResult {
        val domains = HashSet<String>()
        var invalid = 0
        var duplicates = 0
        for (line in text.split("\r\n", "\n", "\r")) {
            var l = line
            val hash = l.indexOf('#')
            if (hash >= 0) l = l.substring(0, hash)
            l = l.trim { it.isWhitespace() || it == '\uFEFF' }
            if (l.isEmpty()) continue
            val d = DomainNormalizer.normalize(l)
            if (d == null) {
                invalid++
            } else if (!domains.add(d)) {
                duplicates++
            }
        }
        return ParseResult(domains, invalid, duplicates)
    }

    /**
     * Parses file bytes. Returns null when the file looks corrupt (not UTF-8 text, or it has
     * only invalid lines and no valid domain) so the caller keeps the last working rules.
     * An empty file, or a file with only comments, is valid and means "block nothing".
     */
    fun parse(bytes: ByteArray): ParseResult? {
        val text = decode(bytes) ?: return null
        val result = parseText(text)
        if (result.domains.isEmpty() && result.invalidLines > 0) return null
        return result
    }
}
