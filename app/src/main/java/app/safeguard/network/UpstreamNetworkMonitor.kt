package app.safeguard.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

class UpstreamSnapshot(val network: Network?, val dnsServers: List<InetAddress>)

/**
 * Tracks the best non-VPN network and its DNS servers. Those servers are what allowed queries
 * are forwarded to. If the network reports no DNS servers, public fallbacks are used.
 */
class UpstreamNetworkMonitor(
    context: Context,
    private val excluded: Set<InetAddress>,
    private val onChanged: (UpstreamSnapshot) -> Unit,
) {
    private class Entry(val network: Network) {
        var caps: NetworkCapabilities? = null
        var lp: LinkProperties? = null
    }

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val lock = Any()
    private val entries = LinkedHashMap<Network, Entry>()

    @Volatile
    var snapshot = UpstreamSnapshot(null, emptyList())
        private set

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            synchronized(lock) { entries.getOrPut(network) { Entry(network) } }
            recompute()
        }

        override fun onLost(network: Network) {
            synchronized(lock) { entries.remove(network) }
            recompute()
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            synchronized(lock) { entries.getOrPut(network) { Entry(network) }.caps = networkCapabilities }
            recompute()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            synchronized(lock) { entries.getOrPut(network) { Entry(network) }.lp = linkProperties }
            recompute()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, callback)
    }

    fun stop() {
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (e: IllegalArgumentException) {
        }
    }

    private fun score(e: Entry): Int {
        val c = e.caps ?: return 0
        var s = 0
        if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) s += 100
        if (c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            s += 30
        } else if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            s += 20
        } else if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            s += 10
        }
        return s
    }

    private fun recompute() {
        val best: Entry? = synchronized(lock) {
            entries.values
                .filter {
                    val c = it.caps
                    c != null &&
                        c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                }
                .maxByOrNull { score(it) }
        }
        val lp = best?.lp
        val servers: List<InetAddress> = when {
            best == null || lp == null -> emptyList()
            else -> {
                val list = lp.dnsServers.filter { it !in excluded }
                if (list.isEmpty()) FALLBACK else list
            }
        }
        val old = snapshot
        if (old.network == best?.network && old.dnsServers == servers) return
        val fresh = UpstreamSnapshot(best?.network, servers)
        snapshot = fresh
        onChanged(fresh)
    }

    private companion object {
        val FALLBACK: List<InetAddress> = listOf(
            InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)),
            InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)),
        )
    }
}

/** Protects sockets from the VPN and pins them to the chosen underlying network. */
class VpnSocketGuard(
    private val vpn: VpnService,
    private val networkProvider: () -> Network?,
) : SocketGuard {

    override fun guard(socket: DatagramSocket) {
        if (!vpn.protect(socket)) throw IOException("VpnService.protect failed")
        networkProvider()?.bindSocket(socket)
    }

    override fun guard(socket: Socket) {
        socket.getReuseAddress() // forces creation of the underlying fd before protect()
        if (!vpn.protect(socket)) throw IOException("VpnService.protect failed")
        networkProvider()?.bindSocket(socket)
    }
}
