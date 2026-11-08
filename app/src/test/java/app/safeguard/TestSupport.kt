package app.safeguard

import app.safeguard.dns.DnsMessage
import app.safeguard.dns.Upstream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

object TestDns {
    val CLIENT4: ByteArray = byteArrayOf(10, 0, 0, 2)
    val DNS4: ByteArray = byteArrayOf(198.toByte(), 18, 0, 2)
    val CLIENT6: ByteArray = InetAddress.getByName("fd00:5afe:6a4d::1").address
    val DNS6: ByteArray = InetAddress.getByName("fd00:5afe:6a4d::2").address

    fun query(id: Int, name: String, type: Int = 1): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(v: Int) {
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }
        u16(id); u16(0x0100); u16(1); u16(0); u16(0); u16(0)
        for (label in name.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.ISO_8859_1))
        }
        out.write(0)
        u16(type); u16(1)
        return out.toByteArray()
    }

    /** Fake upstream answer: echoes the question and adds one NULL-type RR with [rdataSize] bytes of data. */
    fun response(query: ByteArray, rdataSize: Int = 4): ByteArray {
        val q = DnsMessage.parse(query)!!
        val out = ByteArrayOutputStream()
        fun u16(v: Int) {
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }
        u16(q.id); u16(0x8180); u16(q.questions.size); u16(1); u16(0); u16(0)
        out.write(query, 12, q.questionEnd - 12)
        u16(0xC00C); u16(10); u16(1); u16(0); u16(60); u16(rdataSize)
        out.write(ByteArray(rdataSize) { 7 })
        return out.toByteArray()
    }

    fun ancount(msg: ByteArray): Int = DnsMessage.u16(msg, 6)
}

class FakeUpstream(private val delayMs: Long = 0, private val rdataSize: Int = 4) : Upstream {
    val calls = AtomicInteger()
    @Volatile var lastUseTcp = false

    override fun resolve(query: ByteArray, useTcp: Boolean): ByteArray? {
        calls.incrementAndGet()
        lastUseTcp = useTcp
        if (delayMs > 0) Thread.sleep(delayMs)
        return TestDns.response(query, rdataSize)
    }
}
