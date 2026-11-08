package app.safeguard.dns

import java.io.ByteArrayOutputStream

class DnsQuestion(val name: String, val type: Int, val qclass: Int)

class ParsedMessage(
    val id: Int,
    val flags: Int,
    val questions: List<DnsQuestion>,
    /** Offset right after the last question (the question section is bytes 12 until this). */
    val questionEnd: Int,
) {
    val opcode: Int get() = (flags shr 11) and 0xF
}

/** Minimal DNS wire-format parsing/building. No Android dependencies. */
object DnsMessage {
    const val RCODE_NOERROR = 0
    const val RCODE_FORMERR = 1
    const val RCODE_SERVFAIL = 2
    const val RCODE_NXDOMAIN = 3
    const val RCODE_NOTIMP = 4

    private const val FLAG_QR = 0x8000
    private const val FLAG_TC = 0x0200
    private const val FLAG_RD = 0x0100
    private const val FLAG_RA = 0x0080
    private const val OPCODE_MASK = 0x7800
    private const val MAX_QUESTIONS = 16
    private const val MAX_POINTER_JUMPS = 10
    private const val BLOCK_TTL = 30

    fun u16(b: ByteArray, o: Int): Int = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    fun rcode(msg: ByteArray): Int = u16(msg, 2) and 0xF

    private class NameAt(val name: String, val next: Int)

    /** Reads a (possibly compressed) name. Returns null for malformed data. Name is lowercase, no trailing dot. */
    private fun readName(msg: ByteArray, start: Int): NameAt? {
        val sb = StringBuilder()
        var pos = start
        var next = -1
        var jumps = 0
        var total = 0
        loop@ while (true) {
            if (pos < 0 || pos >= msg.size) return null
            val len = msg[pos].toInt() and 0xFF
            if (len == 0) {
                if (next < 0) next = pos + 1
                break@loop
            }
            val kind = len and 0xC0
            if (kind == 0xC0) {
                if (pos + 1 >= msg.size) return null
                val ptr = ((len and 0x3F) shl 8) or (msg[pos + 1].toInt() and 0xFF)
                if (next < 0) next = pos + 2
                jumps++
                if (jumps > MAX_POINTER_JUMPS) return null
                pos = ptr
            } else if (kind != 0) {
                return null // reserved label types
            } else {
                if (pos + 1 + len > msg.size) return null
                total += len + 1
                if (total > 255) return null
                if (sb.isNotEmpty()) sb.append('.')
                for (i in 0 until len) {
                    var c = msg[pos + 1 + i].toInt() and 0xFF
                    if (c in 0x41..0x5A) c += 32
                    sb.append(c.toChar())
                }
                pos += 1 + len
            }
        }
        return NameAt(sb.toString(), next)
    }

    /** Parses header + question section of a query or a response. */
    fun parse(msg: ByteArray): ParsedMessage? {
        if (msg.size < 12) return null
        val qd = u16(msg, 4)
        if (qd == 0 || qd > MAX_QUESTIONS) return null
        var off = 12
        val questions = ArrayList<DnsQuestion>(qd)
        for (i in 0 until qd) {
            val n = readName(msg, off) ?: return null
            if (n.next + 4 > msg.size) return null
            questions.add(DnsQuestion(n.name, u16(msg, n.next), u16(msg, n.next + 2)))
            off = n.next + 4
        }
        return ParsedMessage(u16(msg, 0), u16(msg, 2), questions, off)
    }

    /** Like [parse] but rejects messages that have the QR (response) bit set. */
    fun parseQuery(msg: ByteArray): ParsedMessage? {
        val p = parse(msg) ?: return null
        return if ((p.flags and FLAG_QR) != 0) null else p
    }

    /** Response with [rcode] echoing the question section. NXDOMAIN gets a synthetic SOA so resolvers cache it briefly. */
    fun buildResponse(query: ByteArray, q: ParsedMessage, rcode: Int, withSoa: Boolean): ByteArray {
        val out = ByteArrayOutputStream(q.questionEnd + 64)
        val flags = FLAG_QR or (q.flags and OPCODE_MASK) or (q.flags and FLAG_RD) or FLAG_RA or (rcode and 0xF)
        putU16(out, q.id)
        putU16(out, flags)
        putU16(out, q.questions.size)
        putU16(out, 0)
        putU16(out, if (withSoa) 1 else 0)
        putU16(out, 0)
        out.write(query, 12, q.questionEnd - 12)
        if (withSoa) writeSoa(out)
        return out.toByteArray()
    }

    /** FORMERR for an unparsable query, or null when it must be dropped (too short / is a response). */
    fun buildFormErr(query: ByteArray): ByteArray? {
        if (query.size < 4) return null
        val qflags = u16(query, 2)
        if ((qflags and FLAG_QR) != 0) return null
        val out = ByteArrayOutputStream(12)
        putU16(out, u16(query, 0))
        putU16(out, FLAG_QR or (qflags and OPCODE_MASK) or (qflags and FLAG_RD) or FLAG_RA or RCODE_FORMERR)
        for (i in 0 until 4) putU16(out, 0)
        return out.toByteArray()
    }

    /** If [resp] does not fit into [maxSize], returns header + question with TC=1 so the client retries over TCP. */
    fun truncateForUdp(resp: ByteArray, maxSize: Int): ByteArray {
        if (resp.size <= maxSize || resp.size < 12) return resp
        val p = parse(resp)
        val out = ByteArrayOutputStream(64)
        putU16(out, u16(resp, 0))
        putU16(out, u16(resp, 2) or FLAG_TC)
        putU16(out, p?.questions?.size ?: 0)
        putU16(out, 0)
        putU16(out, 0)
        putU16(out, 0)
        if (p != null) out.write(resp, 12, p.questionEnd - 12)
        return out.toByteArray()
    }

    private fun writeSoa(out: ByteArrayOutputStream) {
        out.write(0) // owner: root
        putU16(out, 6) // SOA
        putU16(out, 1) // IN
        putU32(out, BLOCK_TTL)
        val rdata = ByteArrayOutputStream()
        writeName(rdata, "safeguard.invalid")
        writeName(rdata, "noc.safeguard.invalid")
        putU32(rdata, 1)
        putU32(rdata, 3600)
        putU32(rdata, 600)
        putU32(rdata, 86400)
        putU32(rdata, BLOCK_TTL)
        val bytes = rdata.toByteArray()
        putU16(out, bytes.size)
        out.write(bytes, 0, bytes.size)
    }

    private fun writeName(out: ByteArrayOutputStream, name: String) {
        for (label in name.split('.')) {
            out.write(label.length)
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b, 0, b.size)
        }
        out.write(0)
    }

    private fun putU16(out: ByteArrayOutputStream, v: Int) {
        out.write((v shr 8) and 0xFF)
        out.write(v and 0xFF)
    }

    private fun putU32(out: ByteArrayOutputStream, v: Int) {
        putU16(out, (v shr 16) and 0xFFFF)
        putU16(out, v and 0xFFFF)
    }
}
