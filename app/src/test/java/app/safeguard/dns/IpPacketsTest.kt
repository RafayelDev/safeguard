package app.safeguard.dns

import app.safeguard.TestDns
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpPacketsTest {
    private val payload = byteArrayOf(1, 2, 3, 4, 5)

    @Test fun udpRoundTripIpv4() {
        val pkt = IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 40000, 53, payload)
        val ip = IpPackets.parse(pkt, pkt.size)!!
        assertEquals(4, ip.version)
        assertTrue(IpPackets.verifyTransportChecksum(ip))
        val udp = IpPackets.parseUdp(ip)!!
        assertEquals(40000, udp.srcPort)
        assertEquals(53, udp.dstPort)
        assertArrayEquals(payload, udp.payload)
        assertArrayEquals(TestDns.CLIENT4, ip.src)
    }

    @Test fun udpRoundTripIpv6() {
        val pkt = IpPackets.buildUdp(6, TestDns.CLIENT6, TestDns.DNS6, 40001, 53, payload)
        val ip = IpPackets.parse(pkt, pkt.size)!!
        assertEquals(6, ip.version)
        assertTrue(IpPackets.verifyTransportChecksum(ip))
        assertArrayEquals(payload, IpPackets.parseUdp(ip)!!.payload)
        assertArrayEquals(TestDns.DNS6, ip.dst)
    }

    @Test fun ipv4HeaderChecksumIsValid() {
        val pkt = IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 1, 53, payload)
        var sum = 0
        for (i in 0 until 20 step 2) sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }

    @Test fun tcpRoundTripWithMssOptionIpv4AndIpv6() {
        for (v in listOf(4, 6)) {
            val src = if (v == 4) TestDns.CLIENT4 else TestDns.CLIENT6
            val dst = if (v == 4) TestDns.DNS4 else TestDns.DNS6
            val pkt = IpPackets.buildTcp(
                v, src, dst, 50000, 53, 0xFFFFFFF0L, 77L,
                IpPackets.TCP_SYN or IpPackets.TCP_ACK, payload, 0, payload.size, 1400,
            )
            val ip = IpPackets.parse(pkt, pkt.size)!!
            assertTrue(IpPackets.verifyTransportChecksum(ip))
            val seg = IpPackets.parseTcp(ip)!!
            assertEquals(0xFFFFFFF0L, seg.seq)
            assertEquals(77L, seg.ack)
            assertEquals(1400, seg.mss)
            assertEquals(IpPackets.TCP_SYN or IpPackets.TCP_ACK, seg.flags)
            assertArrayEquals(payload, seg.payload)
        }
    }

    @Test fun rejectsGarbageFragmentsAndBadLengths() {
        assertNull(IpPackets.parse(ByteArray(0), 0))
        assertNull(IpPackets.parse(ByteArray(10), 10))
        assertNull(IpPackets.parse(ByteArray(40), 40)) // version 0
        val pkt = IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 1, 53, payload)
        assertNull(IpPackets.parse(pkt, pkt.size - 1)) // shorter than total length
        val frag = pkt.copyOf(); frag[6] = 0x20 // MF set
        assertNull(IpPackets.parse(frag, frag.size))
        val icmp = pkt.copyOf(); icmp[9] = 1
        assertNull(IpPackets.parse(icmp, icmp.size))
        val v6 = IpPackets.buildUdp(6, TestDns.CLIENT6, TestDns.DNS6, 1, 53, payload)
        val ext = v6.copyOf(); ext[6] = 0 // hop-by-hop extension header: unsupported
        assertNull(IpPackets.parse(ext, ext.size))
        assertNotNull(IpPackets.parse(v6, v6.size))
    }

    @Test fun udpWithBadLengthFieldIsRejected() {
        val pkt = IpPackets.buildUdp(4, TestDns.CLIENT4, TestDns.DNS4, 1, 53, payload)
        pkt[24] = 0x7F // UDP length field huge
        val ip = IpPackets.parse(pkt, pkt.size)!!
        assertNull(IpPackets.parseUdp(ip))
    }
}
