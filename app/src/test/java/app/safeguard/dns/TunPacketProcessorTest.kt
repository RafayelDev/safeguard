package app.safeguard.dns

import app.safeguard.FakeUpstream
import app.safeguard.TestDns
import app.safeguard.rules.RuleSet
import java.util.Collections
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunPacketProcessorTest {
    private val out: MutableList<ByteArray> = Collections.synchronizedList(ArrayList<ByteArray>())
    private val rules = RuleSet(setOf("blocked.example"))
    private val direct = Executor { it.run() }

    private fun processor(upstream: FakeUpstream = FakeUpstream(), executor: Executor = direct) =
        TunPacketProcessor(DnsFilter({ rules }, upstream), executor, { out.add(it) })

    private fun send(p: TunPacketProcessor, pkt: ByteArray) = p.onPacket(pkt, pkt.size)

    private fun udpParse(pkt: ByteArray): Pair<IpPacket, UdpDatagram> {
        val ip = IpPackets.parse(pkt, pkt.size)!!
        assertTrue(IpPackets.verifyTransportChecksum(ip))
        return Pair(ip, IpPackets.parseUdp(ip)!!)
    }

    // ------------------------------------------------------------ UDP

    @Test fun udpIpv4BlockedQueryGetsNxdomainFromTheDnsAddress() {
        val p = processor()
        send(p, IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 40000, 53, TestDns.query(0x1234, "ads.blocked.example")))
        assertEquals(1, out.size)
        val (ip, udp) = udpParse(out[0])
        assertArrayEquals(TestDns.DNS4, ip.src)
        assertArrayEquals(TestDns.CLIENT4, ip.dst)
        assertEquals(53, udp.srcPort)
        assertEquals(40000, udp.dstPort)
        assertEquals(0x1234, DnsMessage.u16(udp.payload, 0))
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(udp.payload))
    }

    @Test fun udpIpv6AllowedQueryIsForwardedAndAnswered() {
        val upstream = FakeUpstream()
        val p = processor(upstream)
        send(p, IpPackets.buildUdp(6, TestDns.CLIENT6, TestDns.DNS6, 41000, 53, TestDns.query(0x2222, "ok.example", 28)))
        assertEquals(1, upstream.calls.get())
        val (ip, udp) = udpParse(out[0])
        assertEquals(6, ip.version)
        assertArrayEquals(TestDns.CLIENT6, ip.dst)
        assertEquals(1, TestDns.ancount(udp.payload))
        assertEquals(0x2222, DnsMessage.u16(udp.payload, 0))
    }

    @Test fun repliesComeFromTheAddressTheClientQueried() {
        // e.g. a hard-coded 8.8.8.8 that we hijack through the TUN
        val google = byteArrayOf(8, 8, 8, 8)
        val p = processor()
        send(p, IpPackets.buildUdp(4, TestDns.CLIENT4, google, 5000, 53, TestDns.query(1, "blocked.example")))
        assertArrayEquals(google, udpParse(out[0]).first.src)
    }

    @Test fun malformedDnsPayloadGetsFormerr() {
        val p = processor()
        val bad = TestDns.query(0x7777, "ok.example").let { it.copyOf(it.size - 4) }
        send(p, IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 40000, 53, bad))
        assertEquals(DnsMessage.RCODE_FORMERR, DnsMessage.rcode(udpParse(out[0]).second.payload))
    }

    @Test fun nonDnsUdpAndGarbageAreIgnored() {
        val p = processor()
        send(p, IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 40000, 443, byteArrayOf(1, 2, 3)))
        p.onPacket(ByteArray(3), 3)
        val garbage = ByteArray(60) { 0x45 }
        p.onPacket(garbage, garbage.size)
        assertEquals(0, out.size)
    }

    @Test fun manyParallelQueriesAreAllAnsweredWithTheirOwnId() {
        val pool = Executors.newFixedThreadPool(16)
        try {
            val p = processor(FakeUpstream(delayMs = 50), pool)
            val n = 100
            val started = System.nanoTime()
            for (i in 1..n) {
                send(p, IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 30000 + i, 53, TestDns.query(i, "h$i.ok.example")))
            }
            val deadline = System.currentTimeMillis() + 10_000
            while (out.size < n && System.currentTimeMillis() < deadline) Thread.sleep(10)
            val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertEquals(n, out.size)
            val ids = HashSet<Int>()
            val ports = HashSet<Int>()
            for (pkt in ArrayList(out)) {
                val (_, udp) = udpParse(pkt)
                ids.add(DnsMessage.u16(udp.payload, 0))
                ports.add(udp.dstPort)
                // id i must go back to port 30000 + i
                assertEquals(30000 + DnsMessage.u16(udp.payload, 0), udp.dstPort)
            }
            assertEquals(n, ids.size)
            assertEquals(n, ports.size)
            assertTrue("queries were serialized: ${elapsedMs}ms", elapsedMs < 3000) // serial would be >= 5000ms
        } finally {
            pool.shutdownNow()
        }
    }

    // ------------------------------------------------------------ TCP

    private class Conn(val v: Int, val client: ByteArray, val server: ByteArray, val port: Int) {
        var seq = 1000L
        var srvNext = 0L
        var srvIsn = 0L
    }

    private fun tcp(c: Conn, flags: Int, data: ByteArray = ByteArray(0), mss: Int = 0, dstPort: Int = 53, seq: Long = c.seq, ack: Long = c.srvNext) =
        IpPackets.buildTcp(c.v, c.client, c.server, c.port, dstPort, seq, ack, flags, data, 0, data.size, mss)

    private fun segs(from: Int): List<TcpSegment> {
        val list = ArrayList<TcpSegment>()
        for (i in from until out.size) {
            val ip = IpPackets.parse(out[i], out[i].size)!!
            assertTrue(IpPackets.verifyTransportChecksum(ip))
            list.add(IpPackets.parseTcp(ip)!!)
        }
        return list
    }

    private fun handshake(p: TunPacketProcessor, c: Conn, mss: Int) {
        val before = out.size
        send(p, tcp(c, IpPackets.TCP_SYN, mss = mss, ack = 0))
        val synAck = segs(before).single()
        assertEquals(IpPackets.TCP_SYN or IpPackets.TCP_ACK, synAck.flags)
        assertEquals(c.seq + 1, synAck.ack)
        c.seq += 1
        c.srvIsn = synAck.seq
        c.srvNext = synAck.seq + 1
        send(p, tcp(c, IpPackets.TCP_ACK))
    }

    private fun framed(q: ByteArray): ByteArray = byteArrayOf((q.size shr 8).toByte(), q.size.toByte()) + q

    /** Reassembles the DNS message the server sent in data segments after [from], checking seq continuity. */
    private fun collectResponse(c: Conn, from: Int): ByteArray {
        var expected = c.srvNext
        val buf = java.io.ByteArrayOutputStream()
        for (s in segs(from)) {
            if (s.payload.isEmpty()) continue
            assertEquals("segment sequence must be contiguous", expected, s.seq)
            expected += s.payload.size
            buf.write(s.payload)
        }
        c.srvNext = expected
        val bytes = buf.toByteArray()
        assertEquals(bytes.size - 2, DnsMessage.u16(bytes, 0))
        return bytes.copyOfRange(2, bytes.size)
    }

    private fun tcpRoundTrip(version: Int) {
        val c = Conn(version, if (version == 4) TestDns.CLIENT4 else TestDns.CLIENT6, if (version == 4) TestDns.DNS4 else TestDns.DNS6, 50000)
        val p = processor()
        handshake(p, c, 1460)
        assertEquals(1, p.activeTcpSessions)

        var before = out.size
        val blockedQ = framed(TestDns.query(0x0A0A, "x.blocked.example"))
        send(p, tcp(c, IpPackets.TCP_PSH or IpPackets.TCP_ACK, blockedQ))
        c.seq += blockedQ.size
        val resp = collectResponse(c, before)
        assertEquals(0x0A0A, DnsMessage.u16(resp, 0))
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(resp))

        // second query on the same connection, allowed
        before = out.size
        val okQ = framed(TestDns.query(0x0B0B, "ok.example"))
        send(p, tcp(c, IpPackets.TCP_PSH or IpPackets.TCP_ACK, okQ))
        c.seq += okQ.size
        assertEquals(1, TestDns.ancount(collectResponse(c, before)))

        // client closes: server ACKs and sends FIN
        before = out.size
        send(p, tcp(c, IpPackets.TCP_FIN or IpPackets.TCP_ACK))
        c.seq += 1
        val flags = segs(before).map { it.flags }
        assertTrue(flags.any { (it and IpPackets.TCP_FIN) != 0 })
        // final ACK of our FIN removes the session
        send(p, tcp(c, IpPackets.TCP_ACK, ack = c.srvNext + 1))
        assertEquals(0, p.activeTcpSessions)
    }

    @Test fun tcpDnsIpv4() = tcpRoundTrip(4)

    @Test fun tcpDnsIpv6() = tcpRoundTrip(6)

    @Test fun tcpQueryArrivingInTwoSegmentsIsAssembled() {
        val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50001)
        val p = processor()
        handshake(p, c, 1460)
        val q = framed(TestDns.query(0x0C0C, "blocked.example"))
        val before = out.size
        send(p, tcp(c, IpPackets.TCP_ACK, q.copyOfRange(0, 5)))
        c.seq += 5
        assertTrue(segs(before).all { it.payload.isEmpty() }) // only ACKs so far
        send(p, tcp(c, IpPackets.TCP_ACK, q.copyOfRange(5, q.size)))
        c.seq += q.size - 5
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(collectResponse(c, before)))
    }

    @Test fun largeTcpResponseIsSplitIntoSegmentsRespectingMss() {
        val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50002)
        val p = processor(FakeUpstream(rdataSize = 3000))
        handshake(p, c, 536)
        val q = framed(TestDns.query(0x0D0D, "big.example"))
        val before = out.size
        send(p, tcp(c, IpPackets.TCP_PSH or IpPackets.TCP_ACK, q))
        c.seq += q.size
        val dataSegs = segs(before).filter { it.payload.isNotEmpty() }
        assertTrue(dataSegs.size >= 6)
        assertTrue(dataSegs.all { it.payload.size <= 536 })
        val resp = collectResponse(c, before)
        assertTrue(resp.size > 3000)
        assertEquals(0x0D0D, DnsMessage.u16(resp, 0))
    }

    @Test fun finWithPendingQueryDelaysOurFinUntilResponseIsSent() {
        val pool = Executors.newFixedThreadPool(2)
        try {
            val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50003)
            val p = processor(FakeUpstream(delayMs = 200), pool)
            // handshake manually (async executor does not matter for SYN)
            val before0 = out.size
            send(p, tcp(c, IpPackets.TCP_SYN, ack = 0))
            val synAck = segs(before0).single()
            c.seq += 1; c.srvNext = synAck.seq + 1
            send(p, tcp(c, IpPackets.TCP_ACK))
            val q = framed(TestDns.query(0x0E0E, "slow.example"))
            send(p, tcp(c, IpPackets.TCP_PSH or IpPackets.TCP_ACK or IpPackets.TCP_FIN, q))
            val deadline = System.currentTimeMillis() + 5000
            while (System.currentTimeMillis() < deadline && segs(before0 + 1).none { (it.flags and IpPackets.TCP_FIN) != 0 }) Thread.sleep(10)
            val all = segs(before0 + 1)
            val finIdx = all.indexOfFirst { (it.flags and IpPackets.TCP_FIN) != 0 }
            val dataIdx = all.indexOfFirst { it.payload.isNotEmpty() }
            assertTrue("response data expected", dataIdx >= 0)
            assertTrue("FIN must follow the response", finIdx > dataIdx)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun tcpToNonDnsPortIsResetImmediately() {
        val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50004)
        val p = processor()
        send(p, tcp(c, IpPackets.TCP_SYN, dstPort = 853, ack = 0))
        val rst = segs(0).single()
        assertTrue((rst.flags and IpPackets.TCP_RST) != 0)
        assertEquals(c.seq + 1, rst.ack)
        assertEquals(0, p.activeTcpSessions)
    }

    @Test fun strayTcpSegmentWithoutSessionGetsRst() {
        val c = Conn(6, TestDns.CLIENT6, TestDns.DNS6, 50005)
        val p = processor()
        c.srvNext = 5555
        send(p, tcp(c, IpPackets.TCP_ACK, byteArrayOf(1, 2, 3)))
        val rst = segs(0).single()
        assertTrue((rst.flags and IpPackets.TCP_RST) != 0)
        assertEquals(5555L, rst.seq)
    }

    @Test fun clientRstRemovesSession() {
        val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50006)
        val p = processor()
        handshake(p, c, 1460)
        send(p, tcp(c, IpPackets.TCP_RST))
        assertEquals(0, p.activeTcpSessions)
    }

    @Test fun zeroLengthDnsFrameAbortsConnection() {
        val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50007)
        val p = processor()
        handshake(p, c, 1460)
        val before = out.size
        send(p, tcp(c, IpPackets.TCP_PSH or IpPackets.TCP_ACK, byteArrayOf(0, 0)))
        assertTrue(segs(before).any { (it.flags and IpPackets.TCP_RST) != 0 })
        assertEquals(0, p.activeTcpSessions)
    }

    @Test fun idleSessionsAreSweptAndRetransmittedSynGetsSameSynAck() {
        var now = 1_000L
        val sessionsProc = TunPacketProcessor(DnsFilter({ rules }, FakeUpstream()), direct, { out.add(it) }, { now })
        val c = Conn(4, TestDns.CLIENT4, TestDns.DNS4, 50008)
        send(sessionsProc, tcp(c, IpPackets.TCP_SYN, ack = 0))
        send(sessionsProc, tcp(c, IpPackets.TCP_SYN, ack = 0))
        val s = segs(0)
        assertEquals(2, s.size)
        assertEquals(s[0].seq, s[1].seq)
        now += 31_000
        sessionsProc.sweep()
        assertEquals(0, sessionsProc.activeTcpSessions)
    }
}
