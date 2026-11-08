package app.safeguard.service

import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import app.safeguard.R
import app.safeguard.dns.DnsFilter
import app.safeguard.network.UpstreamNetworkMonitor
import app.safeguard.network.UpstreamResolver
import app.safeguard.network.VpnSocketGuard
import app.safeguard.rules.RefreshResult
import app.safeguard.rules.RuleReloader
import app.safeguard.storage.BlocklistObserver
import app.safeguard.storage.NullBlocklistSource
import app.safeguard.storage.RuleCache
import app.safeguard.storage.SafBlocklistSource
import app.safeguard.storage.SafeguardPrefs
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * DNS-only VPN. The TUN interface routes only the fake DNS addresses (and well-known public
 * resolvers, to stop hard-coded DNS from bypassing the filter). All other traffic does not
 * enter the tunnel and is never inspected.
 */
class SafeguardVpnService : VpnService() {

    private val lock = Any()
    private var running = false
    private var engine: TunEngine? = null
    private var workers: ThreadPoolExecutor? = null
    private var reloader: RuleReloader? = null
    private var observer: BlocklistObserver? = null
    private var monitor: UpstreamNetworkMonitor? = null

    @Volatile
    private var scheduler: ScheduledExecutorService? = null
    private val refreshQueued = AtomicBoolean(false)
    private var lastStatusText: String? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = SafeguardPrefs(this)
        startForegroundSafely(
            Notifications.build(this, Notifications.CHANNEL_VPN, getString(R.string.status_starting), true),
        )
        if (intent?.action == ACTION_STOP) {
            prefs.enabled = false
            stopProtection()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        // Always-on VPN: the system starts the service with the VpnService action.
        if (intent?.action == SERVICE_INTERFACE) prefs.enabled = true
        if (!prefs.enabled) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        startProtection(prefs)
        return START_STICKY
    }

    override fun onRevoke() {
        // User disconnected us in system settings, or another VPN took over.
        stopProtection()
        SafeguardPrefs(this).enabled = false
        Notifications.postAttention(this, getString(R.string.attention_stopped))
        super.onRevoke()
    }

    override fun onDestroy() {
        stopProtection()
        super.onDestroy()
    }

    private fun startForegroundSafely(n: Notification) {
        try {
            startForeground(Notifications.ID_VPN, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } catch (e: Exception) {
            Log.w(TAG, "startForeground failed; VPN keeps running without it", e)
        }
    }

    private fun startProtection(prefs: SafeguardPrefs) {
        synchronized(lock) {
            if (running) return

            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(MTU)
                .setBlocking(true)
                .addAddress(TUN_V4, 32)
                .addDnsServer(DNS_V4)
                .addRoute(DNS_V4, 32)
                .addAddress(TUN_V6, 128)
                .addDnsServer(DNS_V6)
                .addRoute(DNS_V6, 128)
            for (a in HIJACKED_RESOLVERS) {
                builder.addRoute(a, if (a.contains(':')) 128 else 32)
            }

            val tun = try {
                builder.establish()
            } catch (e: Exception) {
                Log.e(TAG, "establish failed", e)
                null
            }
            if (tun == null) {
                // VPN permission was revoked (or never granted)
                prefs.enabled = false
                Notifications.postAttention(this, getString(R.string.attention_permission))
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            val uri = prefs.treeUri
            val source = if (uri != null) SafBlocklistSource(this, uri) else NullBlocklistSource
            val rl = RuleReloader(source, RuleCache(filesDir))
            rl.loadFromCache()
            reloader = rl

            val pool = ThreadPoolExecutor(WORKERS, WORKERS, 30, TimeUnit.SECONDS, LinkedBlockingQueue(512))
            pool.allowCoreThreadTimeOut(true)
            workers = pool

            val own = setOf(InetAddress.getByName(DNS_V4), InetAddress.getByName(DNS_V6))
            val mon = UpstreamNetworkMonitor(this, own) { snap ->
                setUnderlyingNetworks(snap.network?.let { arrayOf(it) })
            }
            monitor = mon
            val resolver = UpstreamResolver(
                { mon.snapshot.dnsServers.map { InetSocketAddress(it, 53) } },
                VpnSocketGuard(this) { mon.snapshot.network },
            )
            val filter = DnsFilter({ rl.rules }, resolver)

            val eng = TunEngine(tun, filter, pool) { onEngineTerminated() }
            engine = eng
            running = true
            lastStatusText = null
            mon.start()
            eng.start()

            val sch = Executors.newSingleThreadScheduledExecutor { r ->
                Thread(r, "sg-rules").apply { isDaemon = true }
            }
            scheduler = sch
            sch.scheduleWithFixedDelay({ refreshRules() }, 0, REFRESH_SECONDS, TimeUnit.SECONDS)
            sch.scheduleWithFixedDelay({ eng.sweep() }, 15, 15, TimeUnit.SECONDS)

            if (uri != null) {
                val obs = BlocklistObserver(this, uri) { requestRefresh() }
                obs.start()
                observer = obs
            }
        }
    }

    private fun stopProtection() {
        synchronized(lock) {
            running = false
            observer?.stop()
            observer = null
            monitor?.stop()
            monitor = null
            scheduler?.shutdownNow()
            scheduler = null
            engine?.stop()
            engine = null
            workers?.shutdownNow()
            workers = null
            reloader = null
        }
    }

    /** TUN read loop died although we did not stop it: restart after a short delay. */
    private fun onEngineTerminated() {
        mainHandler.postDelayed({
            val prefs = SafeguardPrefs(this)
            if (prefs.enabled) {
                stopProtection()
                startProtection(prefs)
            }
        }, 2000)
    }

    private fun requestRefresh() {
        if (!refreshQueued.compareAndSet(false, true)) return
        try {
            scheduler?.execute {
                refreshQueued.set(false)
                refreshRules()
            }
        } catch (e: RejectedExecutionException) {
            refreshQueued.set(false)
        }
    }

    private fun refreshRules() {
        val rl = reloader ?: return
        val result = try {
            rl.refresh()
        } catch (e: Throwable) {
            // keep the scheduler alive no matter what
            Log.w(TAG, "rule refresh failed", e)
            RefreshResult.UNREADABLE
        }
        val count = rl.rules.size
        var text = when (result) {
            RefreshResult.APPLIED, RefreshResult.UNCHANGED -> getString(R.string.status_active, count)
            RefreshResult.MISSING -> getString(R.string.status_missing, count)
            RefreshResult.UNREADABLE -> getString(R.string.status_unreadable, count)
            RefreshResult.CORRUPT -> getString(R.string.status_corrupt, count)
            RefreshResult.UNSTABLE -> return
        }
        if (Settings.Global.getString(contentResolver, "private_dns_mode") == "hostname") {
            text = getString(R.string.status_private_dns, text)
        }
        if (text == lastStatusText) return
        lastStatusText = text
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(Notifications.ID_VPN, Notifications.build(this, Notifications.CHANNEL_VPN, text, true))
    }

    companion object {
        const val ACTION_START = "app.safeguard.action.START"
        const val ACTION_STOP = "app.safeguard.action.STOP"

        private const val TAG = "SafeguardVpn"
        private const val MTU = 1500
        private const val WORKERS = 32
        private const val REFRESH_SECONDS = 5L

        // 198.18.0.0/15 (benchmark range) and a ULA prefix: unlikely to clash with a real LAN.
        private const val TUN_V4 = "198.18.0.1"
        private const val DNS_V4 = "198.18.0.2"
        private const val TUN_V6 = "fd00:5afe:6a4d::1"
        private const val DNS_V6 = "fd00:5afe:6a4d::2"

        private val HIJACKED_RESOLVERS = listOf(
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2620:fe::fe", "2620:fe::9",
        )
    }
}
