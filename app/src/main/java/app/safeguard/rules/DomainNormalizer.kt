package app.safeguard.rules

import java.net.IDN
import java.util.Locale

/** Validates blocklist entries and normalizes them to lowercase ASCII (punycode). */
object DomainNormalizer {
    private const val MAX_DOMAIN_LENGTH = 253
    private const val MAX_LABEL_LENGTH = 63

    /**
     * Returns the normalized domain or null when [raw] is not a valid blockable domain.
     * Accepts "example.com", "Example.COM.", ".example.com", "*.example.com", IDN ("пример.рф").
     * Rejects URLs, paths, ports, IP addresses and single-label names (so a TLD can't be blocked by accident).
     */
    fun normalize(raw: String): String? {
        var s = raw.trim { it.isWhitespace() || it == '\uFEFF' }
        if (s.isEmpty()) return null
        s = s.lowercase(Locale.ROOT)
        if (s.startsWith("*.")) {
            s = s.substring(2)
        } else if (s.startsWith(".")) {
            s = s.substring(1)
        }
        if (s.endsWith(".")) s = s.substring(0, s.length - 1)
        if (s.isEmpty()) return null

        val converted: String
        try {
            converted = IDN.toASCII(s, IDN.ALLOW_UNASSIGNED)
        } catch (e: IllegalArgumentException) {
            return null
        }
        val ascii = converted.lowercase(Locale.ROOT)
        if (ascii.length > MAX_DOMAIN_LENGTH) return null

        val labels = ascii.split('.')
        if (labels.size < 2) return null
        for (label in labels) {
            if (label.isEmpty() || label.length > MAX_LABEL_LENGTH) return null
            if (!isValidLabel(label)) return null
        }
        // all-numeric TLD => looks like an IP address
        if (labels.last().all { it in '0'..'9' }) return null
        return ascii
    }

    private fun isLabelChar(c: Char): Boolean = c in 'a'..'z' || c in '0'..'9' || c == '_'

    private fun isValidLabel(label: String): Boolean {
        if (!isLabelChar(label.first()) || !isLabelChar(label.last())) return false
        return label.all { isLabelChar(it) || it == '-' }
    }
}
