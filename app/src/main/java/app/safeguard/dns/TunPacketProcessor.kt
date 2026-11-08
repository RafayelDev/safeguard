package app.safeguard.dns

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

/**
 * Handles raw IP packets read from the TUN device: DNS over UDP and a minimal user-space
 * TCP endpoint for DNS over TCP (IPv4 and IPv6). Replies are passed to [writer].
 *
 * Everything that is not DNS (port 53) is refused: TCP gets a RST (so DoT/DoH to hijacked
 * public resolvers fails fast), UDP is dropped.
 *
 * The TUN link is local and lossless, so there is no retransmission of our own segments.
 */
class TunPacketProcessor(
    private val handler: DnsQueryHandler,
    private val executor: Executor,
    private val writer: (ByteArray) -> Unit,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private class TcpSession(
        val version: Int,
        val client: ByteArray,
        val clientPort: Int,
        val server: ByteArray,
        val serverPort: Int,
    ) {
        var established = false
        var rcvNext = 0L
        var sndNext = 0L
        var mss = 536
        var buffer = ByteArray(0)
        var pending = 0
        var clientFin = false
        var finSent = false
        var closed = false
        var lastActive = 0L
    }

    private val sessions = ConcurrentHashMap<String, TcpSession>()
    private val random = SecureRandom()

    val activeTcpSessions: Int get() = sessions.size

    fun onPacket(buf: ByteArray, len: Int) {
        val ip = IpPackets.parse(buf, len) ?: return
        try {
            when (ip.protocol) {
                IpPackets.PROTO_UDP -> handleUdp(ip)
                IpPackets.PROTO_TCP -> handleTcp(ip)
            }
        } catch (e: RuntimeException) {
            // malformed packet: ignore, never kill the read loop
        }
    }

    /** Removes idle TCP sessions. Call periodically. */
    fun sweep() {
        val now = clock()
        sessions.entries.removeIf { now - it.value.lastActive > TCP_IDLE_MS }
    }

    // ---------------------------------------------------------------- UDP

    private fun handleUdp(ip: IpPacket) {
        val udp = IpPackets.parseUdp(ip) ?: return
        if (udp.dstPort != DNS_PORT) return
        val version = ip.version
        val client = ip.src
        val server = ip.dst
        dispatch {
            val resp = handler.handle(udp.payload, true) ?: return@dispatch
            safeWrite(IpPackets.buildUdp(version, server, client, DNS_PORT, udp.srcPort, resp))
        }
    }

    // ---------------------------------------------------------------- TCP

    private fun has(flags: Int, bit: Int): Boolean = (flags and bit) != 0

    private fun handleTcp(ip: IpPacket) {
        val seg = IpPackets.parseTcp(ip) ?: return
        val now = clock()
        val key = "${ip.version}|${ip.src.contentToString()}|${seg.srcPort}|${ip.dst.contentToString()}|${seg.dstPort}"

        if (has(seg.flags, IpPackets.TCP_RST)) {
            sessions.remove(key)
            return
        }
        if (seg.dstPort != DNS_PORT) {
            sendRstFor(ip, seg)
            return
        }

        val existing = sessions[key]
        if (existing == null) {
            if (has(seg.flags, IpPackets.TCP_SYN) && !has(seg.flags, IpPackets.TCP_ACK)) {
                if (sessions.size >= MAX_SESSIONS) sweep()
                if (sessions.size >= MAX_SESSIONS) {
                    sendRstFor(ip, seg)
                    return
                }
                val s = TcpSession(ip.version, ip.src, seg.srcPort, ip.dst, seg.dstPort)
                s.rcvNext = (seg.seq + 1) and MASK
                s.sndNext = random.nextInt().toLong() and MASK
                s.mss = if (seg.mss > 0) seg.mss else if (ip.version == 6) 1220 else 536
                s.lastActive = now
                sessions[key] = s
                synchronized(s) {
                    emit(s, s.sndNext, IpPackets.TCP_SYN or IpPackets.TCP_ACK, EMPTY, 0, 0, ADVERTISED_MSS)
                    s.sndNext = (s.sndNext + 1) and MASK
                }
            } else {
                sendRstFor(ip, seg)
            }
            return
        }

        synchronized(existing) { process(existing, seg, now) }
        if (existing.closed) sessions.remove(key, existing)
    }

    private fun process(s: TcpSession, seg: TcpSegment, now: Long) {
        s.lastActive = now
        if (s.closed) return

        if (has(seg.flags, IpPackets.TCP_SYN)) {
            // retransmitted SYN: repeat our SYN-ACK
            if (!s.established) {
                emit(s, (s.sndNext - 1) and MASK, IpPackets.TCP_SYN or IpPackets.TCP_ACK, EMPTY, 0, 0, ADVERTISED_MSS)
            }
            return
        }
        if (!s.established && has(seg.flags, IpPackets.TCP_ACK)) s.established = true

        if (s.finSent && has(seg.flags, IpPackets.TCP_ACK) && seg.ack == s.sndNext) {
            s.closed = true
            return
        }

        var payload = seg.payload
        if (payload.isNotEmpty()) {
            var inOrder = false
            val diff = (seg.seq - s.rcvNext) and MASK
            if (diff == 0L) {
                inOrder = true
            } else if (diff > HALF) {
                val behind = (s.rcvNext - seg.seq) and MASK
                if (behind < payload.size) {
                    payload = payload.copyOfRange(behind.toInt(), payload.size)
                    inOrder = true
                }
            }
            if (inOrder) {
                s.rcvNext = (s.rcvNext + payload.size) and MASK
                sendAck(s)
                appendAndExtract(s, payload)
            } else {
                sendAck(s) // duplicate / out-of-order: re-ack what we expect
            }
        }

        if (has(seg.flags, IpPackets.TCP_FIN) && !s.clientFin) {
            val finSeq = (seg.seq + seg.payload.size) and MASK
            if (finSeq == s.rcvNext) {
                s.clientFin = true
                s.rcvNext = (s.rcvNext + 1) and MASK
                sendAck(s)
            }
        }
        maybeSendFin(s)
    }

    private fun appendAndExtract(s: TcpSession, payload: ByteArray) {
        s.buffer = s.buffer + payload
        if (s.buffer.size > MAX_BUFFER) {
            abort(s)
            return
        }
        while (s.buffer.size >= 2) {
            val len = DnsMessage.u16(s.buffer, 0)
            if (len == 0) {
                abort(s)
                return
            }
            if (s.buffer.size < 2 + len) break
            val msg = s.buffer.copyOfRange(2, 2 + len)
            s.buffer = s.buffer.copyOfRange(2 + len, s.buffer.size)
            if (s.pending >= MAX_PENDING_PER_SESSION) continue
            s.pending++
            val accepted = dispatch {
                val resp: ByteArray? = try {
                    handler.handle(msg, false)
                } catch (e: Exception) {
                    null
                }
                synchronized(s) {
                    if (resp != null && !s.closed) sendFramed(s, resp)
                    s.pending--
                    maybeSendFin(s)
                }
            }
            if (!accepted) s.pending--
        }
    }

    private fun abort(s: TcpSession) {
        emit(s, s.sndNext, IpPackets.TCP_RST or IpPackets.TCP_ACK, EMPTY, 0, 0, 0)
        s.closed = true
    }

    private fun sendFramed(s: TcpSession, resp: ByteArray) {
        if (resp.size > 0xFFFF) return
        val framed = ByteArray(2 + resp.size)
        framed[0] = (resp.size shr 8).toByte()
        framed[1] = resp.size.toByte()
        System.arraycopy(resp, 0, framed, 2, resp.size)
        val segSize = minOf(s.mss, MAX_SEGMENT)
        var off = 0
        while (off < framed.size) {
            val n = minOf(segSize, framed.size - off)
            val last = off + n == framed.size
            val flags = IpPackets.TCP_ACK or (if (last) IpPackets.TCP_PSH else 0)
            emit(s, s.sndNext, flags, framed, off, n, 0)
            s.sndNext = (s.sndNext + n) and MASK
            off += n
        }
    }

    private fun sendAck(s: TcpSession) {
        emit(s, s.sndNext, IpPackets.TCP_ACK, EMPTY, 0, 0, 0)
    }

    private fun maybeSendFin(s: TcpSession) {
        if (s.clientFin && s.pending == 0 && !s.finSent && !s.closed) {
            emit(s, s.sndNext, IpPackets.TCP_FIN or IpPackets.TCP_ACK, EMPTY, 0, 0, 0)
            s.sndNext = (s.sndNext + 1) and MASK
            s.finSent = true
        }
    }

    private fun emit(s: TcpSession, seq: Long, flags: Int, data: ByteArray, off: Int, len: Int, mssOpt: Int) {
        safeWrite(
            IpPackets.buildTcp(
                s.version, s.server, s.client, s.serverPort, s.clientPort,
                seq, s.rcvNext, flags, data, off, len, mssOpt,
            ),
        )
    }

    /** RFC 793 reset for a segment that belongs to no session. */
    private fun sendRstFor(ip: IpPacket, seg: TcpSegment) {
        val pkt = if (has(seg.flags, IpPackets.TCP_ACK)) {
            IpPackets.buildTcp(ip.version, ip.dst, ip.src, seg.dstPort, seg.srcPort, seg.ack, 0L, IpPackets.TCP_RST)
        } else {
            var segLen = seg.payload.size.toLong()
            if (has(seg.flags, IpPackets.TCP_SYN)) segLen++
            if (has(seg.flags, IpPackets.TCP_FIN)) segLen++
            IpPackets.buildTcp(
                ip.version, ip.dst, ip.src, seg.dstPort, seg.srcPort,
                0L, (seg.seq + segLen) and MASK, IpPackets.TCP_RST or IpPackets.TCP_ACK,
            )
        }
        safeWrite(pkt)
    }

    // ---------------------------------------------------------------- helpers

    private fun dispatch(task: () -> Unit): Boolean {
        return try {
            executor.execute {
                try {
                    task()
                } catch (e: Exception) {
                    // a failing query must not affect others
                }
            }
            true
        } catch (e: RejectedExecutionException) {
            false
        }
    }

    private fun safeWrite(pkt: ByteArray) {
        try {
            writer(pkt)
        } catch (e: Exception) {
            // TUN closed while shutting down
        }
    }

    private companion object {
        const val DNS_PORT = 53
        const val MASK = 0xFFFFFFFFL
        const val HALF = 0x80000000L
        const val MAX_SESSIONS = 256
        const val MAX_PENDING_PER_SESSION = 16
        const val MAX_BUFFER = 70_000
        const val MAX_SEGMENT = 1200
        const val ADVERTISED_MSS = 1400
        const val TCP_IDLE_MS = 30_000L
        val EMPTY = ByteArray(0)
    }
}
