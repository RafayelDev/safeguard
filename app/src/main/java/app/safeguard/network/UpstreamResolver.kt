package app.safeguard.network

import app.safeguard.dns.Upstream
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket

/** Makes a socket bypass the VPN (so upstream queries never loop back into the TUN). */
interface SocketGuard {
    @Throws(IOException::class)
    fun guard(socket: DatagramSocket)

    @Throws(IOException::class)
    fun guard(socket: Socket)

    object None : SocketGuard {
        override fun guard(socket: DatagramSocket) {}
        override fun guard(socket: Socket) {}
    }
}

/**
 * Forwards queries to the real DNS servers over UDP or TCP. One fresh socket per query
 * (random source port), response ID and QR bit are verified, servers are tried in order.
 */
class UpstreamResolver(
    private val servers: () -> List<InetSocketAddress>,
    private val guard: SocketGuard,
    private val timeoutMs: Int = 2500,
    private val maxServers: Int = 3,
) : Upstream {

    override fun resolve(query: ByteArray, useTcp: Boolean): ByteArray? {
        if (query.size < 12) return null
        var tried = 0
        for (server in servers()) {
            if (tried >= maxServers) break
            tried++
            val r: ByteArray? = try {
                if (useTcp) queryTcp(server, query) else queryUdp(server, query)
            } catch (e: IOException) {
                null
            }
            if (r != null) return r
        }
        return null
    }

    private fun queryUdp(server: InetSocketAddress, query: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        try {
            guard.guard(socket)
            socket.connect(server)
            socket.send(DatagramPacket(query, query.size))
            val buf = ByteArray(8192)
            val deadline = System.nanoTime() + timeoutMs * 1_000_000L
            while (true) {
                val remainingMs = (deadline - System.nanoTime()) / 1_000_000L
                if (remainingMs <= 0) return null
                socket.soTimeout = remainingMs.toInt()
                val p = DatagramPacket(buf, buf.size)
                socket.receive(p)
                if (p.length >= 12 && matches(buf, query)) return buf.copyOf(p.length)
                // otherwise: wrong ID / not a response -> ignore and keep waiting
            }
        } finally {
            socket.close()
        }
    }

    private fun queryTcp(server: InetSocketAddress, query: ByteArray): ByteArray? {
        val socket = Socket()
        try {
            guard.guard(socket)
            socket.connect(server, timeoutMs)
            socket.soTimeout = timeoutMs
            val framed = ByteArray(2 + query.size)
            framed[0] = (query.size shr 8).toByte()
            framed[1] = query.size.toByte()
            System.arraycopy(query, 0, framed, 2, query.size)
            val out = socket.getOutputStream()
            out.write(framed)
            out.flush()
            val input = DataInputStream(socket.getInputStream())
            val len = input.readUnsignedShort()
            if (len < 12) return null
            val resp = ByteArray(len)
            input.readFully(resp)
            return if (matches(resp, query)) resp else null
        } finally {
            socket.close()
        }
    }

    private fun matches(resp: ByteArray, query: ByteArray): Boolean =
        resp[0] == query[0] && resp[1] == query[1] && (resp[2].toInt() and 0x80) != 0
}
