package app.safeguard.network

import app.safeguard.TestDns
import app.safeguard.dns.DnsFilter
import app.safeguard.dns.DnsMessage
import app.safeguard.dns.IpPackets
import app.safeguard.dns.TunPacketProcessor
import app.safeguard.rules.RuleSet
import java.io.DataInputStream
import java.net.BindException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.SocketException
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Test

/**
 * "Real network" tests: actual UDP/TCP sockets on the loopback interface against a fake DNS server.
 * They exercise UpstreamResolver and the full packet path, but NOT the Android TUN device.
 */
class UpstreamResolverNetworkTest {

    enum class UdpMode { NORMAL, SILENT, BOGUS_FIRST }

    /** Fake authoritative server answering on the same port over UDP and TCP. */
    private class LoopbackDnsServer(bind: InetAddress) : AutoCloseable {
        val udp: DatagramSocket
        val tcp: ServerSocket
        val names: MutableList<String> = Collections.synchronizedList(ArrayList<String>())
        @Volatile var udpMode = UdpMode.NORMAL
        @Volatile var rdata = 4
        private val pool = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

        init {
            var u: DatagramSocket? = null
            var t: ServerSocket? = null
            var attempts = 0
            while (t == null) {
                u = DatagramSocket(InetSocketAddress(bind, 0))
                try {
                    t = ServerSocket(u.localPort, 50, bind)
                } catch (e: BindException) {
                    u?.close()
                    if (++attempts > 30) throw e
                }
            }
            udp = u!!
            tcp = t
            pool.execute { udpLoop() }
            pool.execute { tcpLoop() }
        }

        val address: InetSocketAddress get() = InetSocketAddress(udp.localAddress, udp.localPort)

        private fun record(q: ByteArray) {
            DnsMessage.parse(q)?.let { names.add(it.questions[0].name) }
        }

        private fun udpLoop() {
            val buf = ByteArray(4096)
            try {
                while (true) {
                    val p = DatagramPacket(buf, buf.size)
                    udp.receive(p)
                    val q = buf.copyOf(p.length)
                    record(q)
                    if (udpMode == UdpMode.SILENT) continue
                    if (udpMode == UdpMode.BOGUS_FIRST) {
                        val bogus = TestDns.response(q, rdata)
                        bogus[0] = (bogus[0].toInt() xor 0x55).toByte()
                        udp.send(DatagramPacket(bogus, bogus.size, p.socketAddress))
                    }
                    val r = TestDns.response(q, rdata)
                    udp.send(DatagramPacket(r, r.size, p.socketAddress))
                }
            } catch (e: Exception) {
                // closed
            }
        }

        private fun tcpLoop() {
            try {
                while (true) {
                    val s = tcp.accept()
                    pool.execute {
                        try {
                            s.use {
                                val input = DataInputStream(it.getInputStream())
                                val len = input.readUnsignedShort()
                                val q = ByteArray(len)
                                input.readFully(q)
                                record(q)
                                val r = TestDns.response(q, rdata)
                                val out = it.getOutputStream()
                                out.write(byteArrayOf((r.size shr 8).toByte(), r.size.toByte()) + r)
                                out.flush()
                            }
                        } catch (e: Exception) {
                        }
                    }
                }
            } catch (e: Exception) {
                // closed
            }
        }

        override fun close() {
            udp.close()
            tcp.close()
            pool.shutdownNow()
        }
    }

    private val toClose = ArrayList<AutoCloseable>()

    @After fun tearDown() {
        toClose.forEach { try { it.close() } catch (e: Exception) {} }
    }

    private fun server(bind: InetAddress = InetAddress.getLoopbackAddress()): LoopbackDnsServer {
        val s = LoopbackDnsServer(bind)
        toClose.add(s)
        return s
    }

    private fun resolver(vararg addrs: InetSocketAddress, timeout: Int = 1500) =
        UpstreamResolver({ addrs.toList() }, SocketGuard.None, timeout)

    @Test fun udpQueryRoundTrip() {
        val s = server()
        val q = TestDns.query(0x4242, "real.example")
        val r = resolver(s.address).resolve(q, false)!!
        assertEquals(0x4242, DnsMessage.u16(r, 0))
        assertEquals(1, TestDns.ancount(r))
        assertEquals(listOf("real.example"), s.names)
    }

    @Test fun udpIgnoresResponsesWithWrongId() {
        val s = server()
        s.udpMode = UdpMode.BOGUS_FIRST
        val r = resolver(s.address).resolve(TestDns.query(0x1111, "spoof.example"), false)!!
        assertEquals(0x1111, DnsMessage.u16(r, 0))
    }

    @Test fun udpTimeoutReturnsNullInTime() {
        val s = server()
        s.udpMode = UdpMode.SILENT
        val started = System.nanoTime()
        val r = resolver(s.address, timeout = 400).resolve(TestDns.query(1, "silent.example"), false)
        val ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertNull(r)
        assertTrue("took ${ms}ms", ms in 300L..2500L)
    }

    @Test fun tcpQueryRoundTripWithLargeAnswer() {
        val s = server()
        s.rdata = 3000
        val r = resolver(s.address).resolve(TestDns.query(0x5151, "big.example"), true)!!
        assertEquals(0x5151, DnsMessage.u16(r, 0))
        assertTrue(r.size > 3000)
    }

    @Test fun failsOverToNextServerWhenFirstIsDead() {
        val dead = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        val deadAddr = InetSocketAddress(InetAddress.getLoopbackAddress(), dead.localPort)
        dead.close() // port now closed: ICMP port unreachable / refused
        val good = server()
        val r = resolver(deadAddr, good.address, timeout = 500).resolve(TestDns.query(9, "failover.example"), false)
        assertNotNull(r)
        assertEquals(listOf("failover.example"), good.names)
    }

    @Test fun noServersMeansNull() {
        assertNull(resolver().resolve(TestDns.query(1, "none.example"), false))
    }

    @Test fun concurrentQueriesAllGetTheirOwnAnswers() {
        val s = server()
        val r = resolver(s.address)
        val n = 40
        val pool = Executors.newFixedThreadPool(20)
        val latch = CountDownLatch(n)
        val results = Collections.synchronizedMap(HashMap<Int, Int>())
        try {
            for (i in 1..n) {
                pool.execute {
                    val resp = r.resolve(TestDns.query(i, "c$i.example"), i % 2 == 0)
                    if (resp != null) results[i] = DnsMessage.u16(resp, 0)
                    latch.countDown()
                }
            }
            assertTrue(latch.await(15, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        assertEquals(n, results.size)
        for ((k, v) in results) assertEquals(k, v)
    }

    @Test fun ipv6LoopbackUpstream() {
        val s: LoopbackDnsServer
        try {
            s = server(InetAddress.getByName("::1"))
        } catch (e: SocketException) {
            assumeNoException("IPv6 loopback not available", e)
            return
        }
        val r = resolver(s.address).resolve(TestDns.query(0x6666, "v6.example", 28), false)!!
        assertEquals(0x6666, DnsMessage.u16(r, 0))
        val t = resolver(s.address).resolve(TestDns.query(0x6667, "v6.example", 28), true)!!
        assertEquals(0x6667, DnsMessage.u16(t, 0))
    }

    // ---- full path: TUN packet -> filter -> real sockets -> fake upstream -> TUN packet

    @Test fun endToEndUdpBlockedNeverReachesUpstreamAllowedDoes() {
        val s = server()
        val out: MutableList<ByteArray> = Collections.synchronizedList(ArrayList<ByteArray>())
        val filter = DnsFilter({ RuleSet(setOf("blocked.example")) }, resolver(s.address))
        val p = TunPacketProcessor(filter, Executor { it.run() }, { out.add(it) })

        val q1 = IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 40001, 53, TestDns.query(1, "www.blocked.example"))
        val q2 = IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 40002, 53, TestDns.query(2, "allowed.example"))
        val q3 = IpPackets.buildUdp(6, TestDns.CLIENT6, TestDns.DNS6, 40003, 53, TestDns.query(3, "allowed6.example", 28))
        for (q in listOf(q1, q2, q3)) p.onPacket(q, q.size)

        assertEquals(3, out.size)
        val byPort = HashMap<Int, ByteArray>()
        for (pkt in out) {
            val ip = IpPackets.parse(pkt, pkt.size)!!
            val udp = IpPackets.parseUdp(ip)!!
            byPort[udp.dstPort] = udp.payload
        }
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(byPort[40001]!!))
        assertEquals(1, TestDns.ancount(byPort[40002]!!))
        assertEquals(1, TestDns.ancount(byPort[40003]!!))
        assertEquals(listOf("allowed.example", "allowed6.example"), s.names.sorted())
        assertFalse(s.names.any { it.contains("blocked.example") })
    }
}
