package app.safeguard.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DomainNormalizerTest {
    @Test fun lowercasesAndTrims() {
        assertEquals("example.com", DomainNormalizer.normalize("  Example.COM  "))
    }

    @Test fun stripsTrailingDotAndWildcardPrefixes() {
        assertEquals("example.com", DomainNormalizer.normalize("example.com."))
        assertEquals("example.com", DomainNormalizer.normalize("*.example.com"))
        assertEquals("example.com", DomainNormalizer.normalize(".example.com"))
    }

    @Test fun convertsIdnToPunycode() {
        assertEquals("xn--e1afmkfd.xn--p1ai", DomainNormalizer.normalize("пример.рф"))
        assertEquals("xn--e1afmkfd.xn--p1ai", DomainNormalizer.normalize("Пример.РФ"))
        assertEquals("xn--mnchen-3ya.de", DomainNormalizer.normalize("münchen.de"))
        assertEquals("xn--bcher-kva.example", DomainNormalizer.normalize("bücher.example"))
    }

    @Test fun keepsExistingPunycode() {
        assertEquals("xn--e1afmkfd.xn--p1ai", DomainNormalizer.normalize("xn--e1afmkfd.xn--p1ai"))
    }

    @Test fun acceptsSubdomainsAndHyphensAndUnderscores() {
        assertEquals("a.b.c.example.org", DomainNormalizer.normalize("a.b.c.example.org"))
        assertEquals("casino-example.net", DomainNormalizer.normalize("casino-example.net"))
        assertEquals("my_host.example.com", DomainNormalizer.normalize("my_host.example.com"))
    }

    @Test fun rejectsInvalidEntries() {
        val bad = listOf(
            "", "   ", ".", "com", "localhost",
            "https://example.com", "example.com/path", "example.com:8080", "user@example.com",
            "exa mple.com", "-bad.com", "bad-.com", "a..b.com", "1.2.3.4", "example.123",
            "exam!ple.com",
        )
        for (b in bad) assertNull("should be rejected: '$b'", DomainNormalizer.normalize(b))
    }

    @Test fun rejectsTooLongLabelsAndNames() {
        assertNull(DomainNormalizer.normalize("a".repeat(64) + ".com"))
        assertEquals("a".repeat(63) + ".com", DomainNormalizer.normalize("a".repeat(63) + ".com"))
        val long = (1..60).joinToString(".") { "abcd" } + ".com"
        assertNull(DomainNormalizer.normalize(long))
    }
}
