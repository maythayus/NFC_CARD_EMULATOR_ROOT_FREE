package com.Maythayus1Corp.nfccardemulatorrootfree

import android.util.Log

internal object AppLog {
    private const val TAG = "NFCCardEmu"

    @Volatile
    private var enabled: Boolean = true

    private val lock = Any()
    private val lines: ArrayDeque<String> = ArrayDeque()

    fun setEnabled(value: Boolean) {
        enabled = value
    }

    fun d(msg: String) = append("D", msg)
    fun i(msg: String) = append("I", msg)
    fun w(msg: String) = append("W", msg)
    fun e(msg: String) = append("E", msg)

    fun clear() {
        synchronized(lock) {
            lines.clear()
        }
    }

    fun snapshot(): List<String> {
        synchronized(lock) {
            return lines.toList()
        }
    }

    fun snapshotText(): String = snapshot().joinToString("\n")

    private fun append(level: String, msg: String) {
        if (!enabled) return

        val line = "${System.currentTimeMillis()} [$level] $msg"

        when (level) {
            "E" -> Log.e(TAG, msg)
            "W" -> Log.w(TAG, msg)
            "I" -> Log.i(TAG, msg)
            else -> Log.d(TAG, msg)
        }

        synchronized(lock) {
            lines.addLast(line)
            while (lines.size > 500) {
                lines.removeFirst()
            }
        }
    }
}
