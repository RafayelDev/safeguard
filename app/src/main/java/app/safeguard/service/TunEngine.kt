package app.safeguard.service

import android.os.ParcelFileDescriptor
import app.safeguard.dns.DnsQueryHandler
import app.safeguard.dns.TunPacketProcessor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.Executor

/** Reads packets from the TUN fd on a dedicated thread and feeds them to [TunPacketProcessor]. */
class TunEngine(
    private val tun: ParcelFileDescriptor,
    handler: DnsQueryHandler,
    executor: Executor,
    private val onTerminated: () -> Unit,
) {
    private val input = FileInputStream(tun.fileDescriptor)
    private val output = FileOutputStream(tun.fileDescriptor)
    private val writeLock = Any()
    private val processor = TunPacketProcessor(handler, executor, { pkt ->
        synchronized(writeLock) { output.write(pkt) }
    })

    @Volatile
    private var stopped = false
    private var thread: Thread? = null

    fun start() {
        val t = Thread({ loop() }, "sg-tun")
        t.isDaemon = true
        thread = t
        t.start()
    }

    private fun loop() {
        val buf = ByteArray(MAX_PACKET)
        while (!stopped) {
            val n = try {
                input.read(buf)
            } catch (e: IOException) {
                break
            }
            if (n < 0) break
            if (n == 0) continue
            processor.onPacket(buf, n)
        }
        if (!stopped) onTerminated()
    }

    fun sweep() = processor.sweep()

    fun stop() {
        stopped = true
        try {
            tun.close() // also wakes up the blocked read()
        } catch (e: IOException) {
        }
        thread?.interrupt()
    }

    private companion object {
        const val MAX_PACKET = 32767
    }
}
