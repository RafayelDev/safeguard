package app.safeguard.rules

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleSetTest {
    private val rules = RuleSet(setOf("example.com", "casino-example.net", "sub.partial.org"))

    @Test fun blocksMainDomain() {
        assertTrue(rules.isBlocked("example.com"))
    }

    @Test fun blocksAllSubdomains() {
        assertTrue(rules.isBlocked("www.example.com"))
        assertTrue(rules.isBlocked("a.b.c.example.com"))
    }

    @Test fun ignoresCaseAndTrailingDot() {
        assertTrue(rules.isBlocked("WWW.Example.COM."))
    }

    @Test fun noFalsePositivesOnSimilarNames() {
        assertFalse(rules.isBlocked("notexample.com"))
        assertFalse(rules.isBlocked("myexample.com"))
        assertFalse(rules.isBlocked("example.com.evil.org"))
        assertFalse(rules.isBlocked("example.org"))
        assertFalse(rules.isBlocked("example.comx"))
        assertFalse(rules.isBlocked("com"))
    }

    @Test fun ruleForSubdomainDoesNotBlockParent() {
        assertTrue(rules.isBlocked("x.sub.partial.org"))
        assertFalse(rules.isBlocked("partial.org"))
        assertFalse(rules.isBlocked("other.partial.org"))
    }

    @Test fun emptyRulesBlockNothing() {
        assertFalse(RuleSet.EMPTY.isBlocked("example.com"))
        assertFalse(RuleSet(emptySet()).isBlocked(""))
    }
}
