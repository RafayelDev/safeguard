package app.safeguard.rules

import java.util.Locale

/** Immutable set of blocked domains. A domain blocks itself and all its subdomains. */
class RuleSet(domains: Set<String>) {
    private val set: Set<String> = HashSet<String>(domains)

    val size: Int get() = set.size

    /** [qname] is a DNS name (any case, optional trailing dot). Matching happens only on label boundaries. */
    fun isBlocked(qname: String): Boolean {
        if (set.isEmpty()) return false
        var name = qname.lowercase(Locale.ROOT)
        if (name.endsWith(".")) name = name.substring(0, name.length - 1)
        if (name.isEmpty()) return false
        var start = 0
        while (true) {
            if (set.contains(name.substring(start))) return true
            val dot = name.indexOf('.', start)
            if (dot < 0) return false
            start = dot + 1
        }
    }

    companion object {
        val EMPTY = RuleSet(emptySet())
    }
}
