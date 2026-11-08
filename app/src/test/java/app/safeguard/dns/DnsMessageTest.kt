package app.safeguard.dns

import app.safeguard.TestDns
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsMessageTest {
    @Test fun parsesQuery() {
        val q = DnsMessage.parseQuery(TestDns.query(0xBEEF, "WWW.Example.com", 28))!!
        assertEquals(0xBEEF, q.id)
        assertEquals(1, q.questions.size)
        assertEquals("www.example.com", q.questions[0].name)
        assertEquals(28, q.questions[0].type)
    }

    @Test fun rejectsMalformedMessages() {
        assertNull(DnsMessage.parse(ByteArray(5)))
        val q = TestDns.query(1, "example.com")
        assertNull(DnsMessage.parse(q.copyOf(q.size - 3))) // truncated question
        val zeroQd = q.copyOf(); zeroQd[5] = 0
        assertNull(DnsMessage.parse(zeroQd))
        val response = q.copyOf(); response[2] = (response[2].toInt() or 0x80).toByte()
        assertNull(DnsMessage.parseQuery(response))
        assertNotNull(DnsMessage.parse(response))
    }

    @Test fun rejectsCompressionLoopAndReservedLabelTypes() {
        val loop = ByteArray(12 + 2 + 4)
        loop[5] = 1
        loop[12] = 0xC0.toByte(); loop[13] = 12 // pointer to itself
        assertNull(DnsMessage.parse(loop))
        val reserved = ByteArray(12 + 2 + 4)
        reserved[5] = 1
        reserved[12] = 0x40
        assertNull(DnsMessage.parse(reserved))
    }

    @Test fun acceptsCompressionPointerInSecondQuestion() {
        val first = TestDns.query(1, "example.com")
        // append a second question whose name is a pointer to offset 12
        val msg = first + byteArrayOf(0xC0.toByte(), 12, 0, 28, 0, 1)
        msg[5] = 2
        val p = DnsMessage.parse(msg)!!
        assertEquals(listOf("example.com", "example.com"), p.questions.map { it.name })
    }

    @Test fun nxdomainResponseIsWellFormed() {
        val query = TestDns.query(0x1234, "ads.example.com")
        val q = DnsMessage.parseQuery(query)!!
        val r = DnsMessage.buildResponse(query, q, DnsMessage.RCODE_NXDOMAIN, true)
        assertEquals(0x1234, DnsMessage.u16(r, 0))
        assertTrue((DnsMessage.u16(r, 2) and 0x8000) != 0) // QR
        assertTrue((DnsMessage.u16(r, 2) and 0x0100) != 0) // RD echoed
        assertTrue((DnsMessage.u16(r, 2) and 0x0080) != 0) // RA
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(r))
        assertEquals(1, DnsMessage.u16(r, 4))
        assertEquals(0, DnsMessage.u16(r, 6))
        assertEquals(1, DnsMessage.u16(r, 8)) // SOA in authority
        assertArrayEquals(query.copyOfRange(12, q.questionEnd), r.copyOfRange(12, q.questionEnd))
        // the response must itself be parseable as a message with the same question
        assertEquals("ads.example.com", DnsMessage.parse(r)!!.questions[0].name)
    }

    @Test fun formErrIsBuiltOnlyForQueries() {
        val garbage = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55)
        val r = DnsMessage.buildFormErr(garbage)!!
        assertEquals(0x1234, DnsMessage.u16(r, 0))
        assertEquals(DnsMessage.RCODE_FORMERR, DnsMessage.rcode(r))
        val asResponse = garbage.copyOf(); asResponse[2] = 0x81.toByte()
        assertNull(DnsMessage.buildFormErr(asResponse))
        assertNull(DnsMessage.buildFormErr(ByteArray(2)))
    }

    @Test fun truncateForUdpSetsTcBitAndKeepsQuestion() {
        val query = TestDns.query(7, "big.example.org")
        val big = TestDns.response(query, 3000)
        val t = DnsMessage.truncateForUdp(big, 1452)
        assertTrue(t.size < 100)
        assertTrue((DnsMessage.u16(t, 2) and 0x0200) != 0)
        assertEquals(0, DnsMessage.u16(t, 6))
        assertEquals("big.example.org", DnsMessage.parse(t)!!.questions[0].name)
        val small = TestDns.response(query, 4)
        assertArrayEquals(small, DnsMessage.truncateForUdp(small, 1452))
    }
}
