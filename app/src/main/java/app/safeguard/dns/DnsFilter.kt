package app.safeguard.dns

import app.safeguard.rules.RuleSet

fun interface DnsQueryHandler {
    /** Returns the response for a DNS query, or null to send nothing. */
    fun handle(query: ByteArray, overUdp: Boolean): ByteArray?
}

interface Upstream {
    /** Forwards the raw query to the real resolver. Returns the raw response or null on failure/timeout. */
    fun resolve(query: ByteArray, useTcp: Boolean): ByteArray?
}

/**
 * Core of the blocker: blocked names get NXDOMAIN, everything else is forwarded unchanged.
 * Rules are read through [rules] on every query so a rule swap applies immediately.
 */
class DnsFilter(
    private val rules: () -> RuleSet,
    private val upstream: Upstream,
    private val maxUdpResponse: Int = DEFAULT_MAX_UDP_RESPONSE,
) : DnsQueryHandler {

    override fun handle(query: ByteArray, overUdp: Boolean): ByteArray? {
        if (query.size < 12) return null
        val q = DnsMessage.parseQuery(query) ?: return DnsMessage.buildFormErr(query)
        if (q.opcode != 0) {
            return DnsMessage.buildResponse(query, q, DnsMessage.RCODE_NOTIMP, false)
        }
        val current = rules()
        for (question in q.questions) {
            if (current.isBlocked(question.name)) {
                return DnsMessage.buildResponse(query, q, DnsMessage.RCODE_NXDOMAIN, true)
            }
        }
        val response: ByteArray? = try {
            upstream.resolve(query, !overUdp)
        } catch (e: Exception) {
            null
        }
        if (response == null || response.size < 12) {
            return DnsMessage.buildResponse(query, q, DnsMessage.RCODE_SERVFAIL, false)
        }
        return if (overUdp) DnsMessage.truncateForUdp(response, maxUdpResponse) else response
    }

    companion object {
        /** TUN MTU 1500 minus IPv6 (40) and UDP (8) headers. */
        const val DEFAULT_MAX_UDP_RESPONSE = 1452
    }
}
