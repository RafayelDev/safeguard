package app.safeguard.dns

import app.safeguard.FakeUpstream
import app.safeguard.TestDns
import app.safeguard.rules.RuleSet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsFilterTest {
    private var rules = RuleSet(setOf("blocked.example", "ads.tracker.net"))
    private val upstream = FakeUpstream()
    private val filter = DnsFilter({ rules }, upstream)

    @Test fun blockedDomainGetsNxdomainWithoutTouchingUpstream() {
        val r = filter.handle(TestDns.query(1, "blocked.example"), true)!!
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(r))
        assertEquals(0, upstream.calls.get())
    }

    @Test fun subdomainsAreBlockedForAllRecordTypes() {
        for (type in listOf(1, 28, 65, 15, 16)) {
            val r = filter.handle(TestDns.query(2, "cdn.blocked.example", type), true)!!
            assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(r))
        }
        assertEquals(0, upstream.calls.get())
    }

    @Test fun similarNamesAreForwarded() {
        for (n in listOf("notblocked.example", "blocked.example.org", "tracker.net")) {
            val r = filter.handle(TestDns.query(3, n), true)!!
            assertEquals(DnsMessage.RCODE_NOERROR, DnsMessage.rcode(r))
            assertEquals(1, TestDns.ancount(r))
        }
        assertEquals(3, upstream.calls.get())
    }

    @Test fun responseKeepsClientQueryId() {
        val r = filter.handle(TestDns.query(0xABCD, "ok.example"), true)!!
        assertEquals(0xABCD, DnsMessage.u16(r, 0))
    }

    @Test fun rulesSwapAppliesToNextQuery() {
        assertEquals(DnsMessage.RCODE_NOERROR, DnsMessage.rcode(filter.handle(TestDns.query(1, "new.example"), true)!!))
        rules = RuleSet(setOf("new.example"))
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(filter.handle(TestDns.query(2, "new.example"), true)!!))
        rules = RuleSet.EMPTY
        assertEquals(DnsMessage.RCODE_NOERROR, DnsMessage.rcode(filter.handle(TestDns.query(3, "new.example"), true)!!))
    }

    @Test fun upstreamFailureGivesServfail() {
        val failing = DnsFilter({ rules }, object : Upstream {
            override fun resolve(query: ByteArray, useTcp: Boolean): ByteArray? = null
        })
        val r = failing.handle(TestDns.query(5, "ok.example"), true)!!
        assertEquals(DnsMessage.RCODE_SERVFAIL, DnsMessage.rcode(r))
    }

    @Test fun upstreamExceptionGivesServfail() {
        val throwing = DnsFilter({ rules }, object : Upstream {
            override fun resolve(query: ByteArray, useTcp: Boolean): ByteArray? = throw IllegalStateException("x")
        })
        assertEquals(DnsMessage.RCODE_SERVFAIL, DnsMessage.rcode(throwing.handle(TestDns.query(5, "ok.example"), true)!!))
    }

    @Test fun malformedPacketsAreAnsweredWithFormerrOrDropped() {
        assertNull(filter.handle(ByteArray(5), true))
        val q = TestDns.query(9, "ok.example")
        val broken = filter.handle(q.copyOf(q.size - 4), true)
        assertNotNull(broken)
        assertEquals(DnsMessage.RCODE_FORMERR, DnsMessage.rcode(broken!!))
        assertEquals(0, upstream.calls.get())
    }

    @Test fun responsesAreNotAnsweredAsQueries() {
        val response = TestDns.response(TestDns.query(1, "ok.example"))
        assertNull(filter.handle(response, true))
    }

    @Test fun nonQueryOpcodeGetsNotimp() {
        val q = TestDns.query(1, "ok.example")
        q[2] = (q[2].toInt() or (4 shl 3)).toByte() // opcode 4 (NOTIFY)
        assertEquals(DnsMessage.RCODE_NOTIMP, DnsMessage.rcode(filter.handle(q, true)!!))
    }

    @Test fun udpTruncatesHugeAnswersButTcpDoesNot() {
        val big = DnsFilter({ rules }, FakeUpstream(rdataSize = 3000))
        val udp = big.handle(TestDns.query(1, "big.example"), true)!!
        assertTrue(udp.size < 200)
        assertTrue((DnsMessage.u16(udp, 2) and 0x0200) != 0)
        val tcp = big.handle(TestDns.query(2, "big.example"), false)!!
        assertTrue(tcp.size > 3000)
    }

    @Test fun tcpQueriesUseTcpUpstream() {
        filter.handle(TestDns.query(1, "ok.example"), false)
        assertTrue(upstream.lastUseTcp)
        filter.handle(TestDns.query(2, "ok.example"), true)
        assertEquals(false, upstream.lastUseTcp)
    }
}
