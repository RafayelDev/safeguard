package app.safeguard.dns

/** Parsed IP packet. [data] is the caller's buffer (valid only during the call); src/dst are copies. */
class IpPacket(
    val version: Int,
    val protocol: Int,
    val src: ByteArray,
    val dst: ByteArray,
    val data: ByteArray,
    val transportOffset: Int,
    val transportLength: Int,
)

class UdpDatagram(val srcPort: Int, val dstPort: Int, val payload: ByteArray)

class TcpSegment(
    val srcPort: Int,
    val dstPort: Int,
    val seq: Long,
    val ack: Long,
    val flags: Int,
    val window: Int,
    val payload: ByteArray,
    /** MSS option value, 0 if absent. */
    val mss: Int,
)

/** IPv4/IPv6 + UDP/TCP parsing and building with correct checksums. No Android dependencies. */
object IpPackets {
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    private val EMPTY = ByteArray(0)

    fun u16(b: ByteArray, o: Int): Int = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    fun u32(b: ByteArray, o: Int): Long = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 8).toByte()
        b[o + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v shr 24).toByte()
        b[o + 1] = (v shr 16).toByte()
        b[o + 2] = (v shr 8).toByte()
        b[o + 3] = v.toByte()
    }

    /** Returns null for unsupported, fragmented or malformed packets (only TCP/UDP, no IPv6 extension headers). */
    fun parse(buf: ByteArray, len: Int): IpPacket? {
        if (len < 1 || len > buf.size) return null
        return when ((buf[0].toInt() and 0xF0) shr 4) {
            4 -> parseV4(buf, len)
            6 -> parseV6(buf, len)
            else -> null
        }
    }

    private fun parseV4(buf: ByteArray, len: Int): IpPacket? {
        if (len < 20) return null
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > len) return null
        val total = u16(buf, 2)
        if (total < ihl || total > len) return null
        if ((u16(buf, 6) and 0x3FFF) != 0) return null // fragment (MF or offset != 0)
        val proto = buf[9].toInt() and 0xFF
        if (proto != PROTO_TCP && proto != PROTO_UDP) return null
        return IpPacket(4, proto, buf.copyOfRange(12, 16), buf.copyOfRange(16, 20), buf, ihl, total - ihl)
    }

    private fun parseV6(buf: ByteArray, len: Int): IpPacket? {
        if (len < 40) return null
        val payloadLen = u16(buf, 4)
        if (40 + payloadLen > len) return null
        val next = buf[6].toInt() and 0xFF
        if (next != PROTO_TCP && next != PROTO_UDP) return null
        return IpPacket(6, next, buf.copyOfRange(8, 24), buf.copyOfRange(24, 40), buf, 40, payloadLen)
    }

    fun parseUdp(p: IpPacket): UdpDatagram? {
        if (p.protocol != PROTO_UDP || p.transportLength < 8) return null
        val o = p.transportOffset
        val length = u16(p.data, o + 4)
        if (length < 8 || length > p.transportLength) return null
        return UdpDatagram(u16(p.data, o), u16(p.data, o + 2), p.data.copyOfRange(o + 8, o + length))
    }

    fun parseTcp(p: IpPacket): TcpSegment? {
        if (p.protocol != PROTO_TCP || p.transportLength < 20) return null
        val o = p.transportOffset
        val d = p.data
        val dataOff = ((d[o + 12].toInt() and 0xF0) shr 4) * 4
        if (dataOff < 20 || dataOff > p.transportLength) return null
        var mss = 0
        var i = o + 20
        val optEnd = o + dataOff
        while (i < optEnd) {
            val kind = d[i].toInt() and 0xFF
            if (kind == 0) break
            if (kind == 1) {
                i++
                continue
            }
            if (i + 1 >= optEnd) break
            val l = d[i + 1].toInt() and 0xFF
            if (l < 2 || i + l > optEnd) break
            if (kind == 2 && l == 4) mss = u16(d, i + 2)
            i += l
        }
        return TcpSegment(
            u16(d, o), u16(d, o + 2), u32(d, o + 4), u32(d, o + 8),
            d[o + 13].toInt() and 0x3F, u16(d, o + 14),
            d.copyOfRange(o + dataOff, o + p.transportLength), mss,
        )
    }

    fun buildUdp(
        version: Int, src: ByteArray, dst: ByteArray,
        srcPort: Int, dstPort: Int, payload: ByteArray,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val l4 = ByteArray(udpLen)
        put16(l4, 0, srcPort)
        put16(l4, 2, dstPort)
        put16(l4, 4, udpLen)
        System.arraycopy(payload, 0, l4, 8, payload.size)
        var cs = transportChecksum(src, dst, PROTO_UDP, l4)
        if (cs == 0) cs = 0xFFFF
        put16(l4, 6, cs)
        return wrapIp(version, src, dst, PROTO_UDP, l4)
    }

    fun buildTcp(
        version: Int, src: ByteArray, dst: ByteArray,
        srcPort: Int, dstPort: Int, seq: Long, ack: Long, flags: Int,
        payload: ByteArray = EMPTY, payloadOff: Int = 0, payloadLen: Int = 0,
        mssOption: Int = 0,
    ): ByteArray {
        val hdr = if (mssOption > 0) 24 else 20
        val l4 = ByteArray(hdr + payloadLen)
        put16(l4, 0, srcPort)
        put16(l4, 2, dstPort)
        put32(l4, 4, seq and 0xFFFFFFFFL)
        put32(l4, 8, ack and 0xFFFFFFFFL)
        l4[12] = ((hdr / 4) shl 4).toByte()
        l4[13] = flags.toByte()
        put16(l4, 14, 65535)
        if (mssOption > 0) {
            l4[20] = 2
            l4[21] = 4
            put16(l4, 22, mssOption)
        }
        System.arraycopy(payload, payloadOff, l4, hdr, payloadLen)
        put16(l4, 16, transportChecksum(src, dst, PROTO_TCP, l4))
        return wrapIp(version, src, dst, PROTO_TCP, l4)
    }

    /** True when the TCP/UDP checksum of [p] is valid (used by tests). */
    fun verifyTransportChecksum(p: IpPacket): Boolean {
        val l4 = p.data.copyOfRange(p.transportOffset, p.transportOffset + p.transportLength)
        return transportChecksum(p.src, p.dst, p.protocol, l4) == 0
    }

    private fun wrapIp(version: Int, src: ByteArray, dst: ByteArray, proto: Int, l4: ByteArray): ByteArray {
        if (version == 4) {
            val total = 20 + l4.size
            val p = ByteArray(total)
            p[0] = 0x45
            put16(p, 2, total)
            put16(p, 6, 0x4000)
            p[8] = 64
            p[9] = proto.toByte()
            System.arraycopy(src, 0, p, 12, 4)
            System.arraycopy(dst, 0, p, 16, 4)
            put16(p, 10, fold(addBytes(0L, p, 0, 20)))
            System.arraycopy(l4, 0, p, 20, l4.size)
            return p
        }
        val p = ByteArray(40 + l4.size)
        p[0] = 0x60
        put16(p, 4, l4.size)
        p[6] = proto.toByte()
        p[7] = 64
        System.arraycopy(src, 0, p, 8, 16)
        System.arraycopy(dst, 0, p, 24, 16)
        System.arraycopy(l4, 0, p, 40, l4.size)
        return p
    }

    private fun transportChecksum(src: ByteArray, dst: ByteArray, proto: Int, l4: ByteArray): Int {
        var sum = 0L
        sum = addBytes(sum, src, 0, src.size)
        sum = addBytes(sum, dst, 0, dst.size)
        sum += proto.toLong()
        sum += l4.size.toLong()
        sum = addBytes(sum, l4, 0, l4.size)
        return fold(sum)
    }

    private fun addBytes(initial: Long, b: ByteArray, off: Int, len: Int): Long {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) sum += ((b[i].toInt() and 0xFF) shl 8).toLong()
        return sum
    }

    /** Folds to 16 bits and returns the one's complement. */
    private fun fold(s: Long): Int {
        var sum = s
        while ((sum shr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }
}
