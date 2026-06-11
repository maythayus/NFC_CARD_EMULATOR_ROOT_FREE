package com.Maythayus1Corp.nfccardemulatorrootfree

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Base64
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CardService : HostApduService() {
    private val rng = SecureRandom()

    private var protoSelected: Boolean = false
    private var lastChallenge: ByteArray? = null
    private var authOkUntilMs: Long = 0L

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        val cmd = commandApdu ?: return Hex.hexToBytes("6F00")
        val cmdHex = Hex.bytesToHex(cmd)

        AppLog.d("APDU <= $cmdHex")

        val active = CardStore.getActive(applicationContext)

        val protoResp = handleProtoApdu(active, cmd)
        if (protoResp != null) {
            AppLog.d("APDU => ${Hex.bytesToHex(protoResp)}")
            return protoResp
        }

        if (active != null) {
            val responseHex = active.apduMap[cmdHex] ?: active.apduMap[Hex.normalize(cmdHex)]
            if (!responseHex.isNullOrBlank()) {
                AppLog.d("APDU => mapped ${responseHex}")
                return Hex.hexToBytes(responseHex)
            }
        }

        if (active == null) {
            return byteArrayOf(0x00, 0x00, 0x00, 0x00)
        }

        val resp = handleVigikLikeApdu(active, cmd)
        AppLog.d("APDU => ${Hex.bytesToHex(resp)}")
        return resp
    }

    override fun onDeactivated(reason: Int) {
        protoSelected = false
        lastChallenge = null
        authOkUntilMs = 0L
    }

    private fun handleProtoApdu(active: CardProfile?, apdu: ByteArray): ByteArray? {
        if (apdu.size < 4) return sw("6F00")

        val cla = apdu[0].toInt() and 0xFF
        val ins = apdu[1].toInt() and 0xFF
        val p1 = apdu[2].toInt() and 0xFF
        val p2 = apdu[3].toInt() and 0xFF

        if (cla == 0x00 && ins == 0xA4 && p1 == 0x04 && p2 == 0x00 && apdu.size >= 6) {
            val lc = apdu[4].toInt() and 0xFF
            if (apdu.size < 5 + lc) return sw("6A80")
            val aid = apdu.copyOfRange(5, 5 + lc)
            if (Hex.bytesToHex(aid).equals(PROTO_AID, ignoreCase = true)) {
                protoSelected = true
                lastChallenge = null
                authOkUntilMs = 0L
                val uid = if (active != null) extractUid(active) else byteArrayOf(0x08, 0x00, 0x00, 0x00)
                val fci = buildFci(uid)
                return concat(fci, sw("9000"))
            }

            // Different AID selected: leave proprietary protocol mode.
            protoSelected = false
            lastChallenge = null
            authOkUntilMs = 0L
            return null
        }

        if (!protoSelected) return null

        // If proprietary protocol is selected but we receive a standard ISO CLA, don't intercept it.
        // This prevents breaking the existing VIGIK-like APDUs (00CA/00B2) after a proprietary session.
        if (cla == 0x00) return null

        if (cla == 0x80 && ins == 0x84 && p1 == 0x00 && p2 == 0x00) {
            val challenge = ByteArray(16)
            rng.nextBytes(challenge)
            lastChallenge = challenge
            return concat(challenge, sw("9000"))
        }

        if (cla == 0x80 && ins == 0x82 && p1 == 0x00 && p2 == 0x00 && apdu.size >= 5) {
            val lc = apdu[4].toInt() and 0xFF
            if (apdu.size < 5 + lc) return sw("6A80")
            val data = apdu.copyOfRange(5, 5 + lc)
            if (data.size < 12 + 1 + 16 + 16) return sw("6700")

            val iv = data.copyOfRange(0, 12)
            val encAndTag = data.copyOfRange(12, data.size)
            val challenge = lastChallenge ?: return sw("6985")

            val plain = try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val key = SecretKeySpec(Hex.hexToBytes(PROTO_KEY_HEX), "AES")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                cipher.doFinal(encAndTag)
            } catch (_: Throwable) {
                return sw("6300")
            }

            if (plain.size != 1 + 16) return sw("6A80")
            if ((plain[0].toInt() and 0xFF) != 0x01) return sw("6A80")
            val gotChallenge = plain.copyOfRange(1, 17)
            if (!equalsConstTime(gotChallenge, challenge)) return sw("6300")

            authOkUntilMs = System.currentTimeMillis() + 60_000L
            return sw("9000")
        }

        if (cla == 0x80 && ins == 0xB2) {
            if (System.currentTimeMillis() > authOkUntilMs) return sw("6982")

            val sector = p1
            val block = p2
            if (active == null) return sw("6A82")
            val data = readClassicBlock16(active, sector, block) ?: return sw("6A82")
            return concat(data, sw("9000"))
        }

        return sw("6A82")
    }

    private fun handleVigikLikeApdu(active: CardProfile, apdu: ByteArray): ByteArray {
        if (apdu.size < 4) return sw("6F00")

        val cla = apdu[0].toInt() and 0xFF
        val ins = apdu[1].toInt() and 0xFF
        val p1 = apdu[2].toInt() and 0xFF
        val p2 = apdu[3].toInt() and 0xFF

        // SELECT by AID
        if (cla == 0x00 && ins == 0xA4 && p1 == 0x04 && p2 == 0x00 && apdu.size >= 6) {
            val lc = apdu[4].toInt() and 0xFF
            if (apdu.size < 5 + lc) return sw("6A80")

            val uid = extractUid(active)
            val fci = buildFci(uid)
            return concat(fci, sw("9000"))
        }

        // GET UID
        if (cla == 0x00 && ins == 0xCA) {
            val uid = extractUid(active)
            return concat(uid, sw("9000"))
        }

        // READ "sector/block" used by tools/vigik_verify.py: 00 B2 <sector> <block> 10
        if (cla == 0x00 && ins == 0xB2) {
            val sector = p1
            val block = p2
            val data = readClassicBlock16(active, sector, block) ?: return sw("6A82")
            return concat(data, sw("9000"))
        }

        return sw("6A82")
    }

    private fun extractUid(active: CardProfile): ByteArray {
        // Prefer UID from VIGIK JSON ("uid": "84 6D 0B C9")
        val dump = active.dumpJson
        if (!dump.isNullOrBlank()) {
            try {
                val root = JSONObject(dump)
                val uidStr = root.optString("uid", "").trim()
                if (uidStr.isNotBlank()) {
                    val cleaned = uidStr.replace(" ", "")
                    if (cleaned.length >= 8) {
                        return Hex.hexToBytes(cleaned.take(8))
                    }
                }
            } catch (_: Throwable) {
            }

            // Proxmark3 mfcard JSON: {"Card":{"UID":"442E8637"}, "blocks":{...}}
            try {
                val root = JSONObject(dump)
                val cardObj = root.optJSONObject("Card")
                val uidStr = cardObj?.optString("UID", "")?.trim().orEmpty()
                if (uidStr.isNotBlank()) {
                    val cleaned = uidStr.replace(" ", "").replace(".", "")
                    if (cleaned.length >= 8) {
                        return Hex.hexToBytes(cleaned.take(8))
                    }
                }
            } catch (_: Throwable) {
            }

            // If it's a raw base64 dump wrapper, derive UID from block 0 bytes[0..3]
            try {
                val root = JSONObject(dump)
                if (root.optString("format", "") == "raw") {
                    val b64 = root.optString("base64", "")
                    if (b64.isNotBlank()) {
                        val all = Base64.decode(b64, Base64.DEFAULT)
                        if (all.size >= 4) {
                            return all.copyOfRange(0, 4)
                        }
                    }
                }
            } catch (_: Throwable) {
            }
        }
        // Fallback: 4 bytes
        return byteArrayOf(0x08, 0x00, 0x00, 0x00)
    }

    private fun readClassicBlock16(active: CardProfile, sector: Int, block: Int): ByteArray? {
        if (sector !in 0..15 || block !in 0..3) return null

        val dump = active.dumpJson ?: return null

        // Case 1: VIGIK JSON with sectors
        try {
            val root = JSONObject(dump)
            if (root.has("sectors")) {
                val sectorsObj = root.optJSONObject("sectors")
                val sObj = sectorsObj?.optJSONObject(sector.toString())
                val hex = sObj?.optString(block.toString(), null)
                if (!hex.isNullOrBlank()) {
                    val cleaned = hex.replace(" ", "")
                    val bytes = Hex.hexToBytes(cleaned)
                    if (bytes.size == 16) return bytes
                }
            }
        } catch (_: Throwable) {
        }

        // Case 2: raw wrapper {format:"raw", base64:"..."}
        try {
            val root = JSONObject(dump)
            if (root.optString("format", "") == "raw") {
                val b64 = root.optString("base64", "")
                if (b64.isNotBlank()) {
                    val all = Base64.decode(b64, Base64.DEFAULT)
                    val offset = (sector * 4 + block) * 16
                    if (all.size >= offset + 16) {
                        return all.copyOfRange(offset, offset + 16)
                    }
                }
            }
        } catch (_: Throwable) {
        }

        // Case 3: Proxmark3 mfcard JSON with blocks
        try {
            val root = JSONObject(dump)
            if (root.has("blocks")) {
                val blocksObj = root.optJSONObject("blocks")
                val index = sector * 4 + block
                val hex = blocksObj?.optString(index.toString(), null)
                if (!hex.isNullOrBlank()) {
                    val cleaned = hex.replace(" ", "")
                    val bytes = Hex.hexToBytes(cleaned)
                    if (bytes.size == 16) return bytes
                }
            }
        } catch (_: Throwable) {
        }

        return null
    }

    private fun buildFci(uid: ByteArray): ByteArray {
        // Minimal FCI with proprietary UID tag 0x84 (as the verifier expects)
        val uidTlv = concat(byteArrayOf(0x84.toByte(), uid.size.toByte()), uid)
        val a5 = concat(byteArrayOf(0xA5.toByte(), uidTlv.size.toByte()), uidTlv)
        val fci = concat(byteArrayOf(0x6F.toByte(), a5.size.toByte()), a5)
        return fci
    }

    private fun sw(hex: String): ByteArray = Hex.hexToBytes(hex)

    private fun concat(a: ByteArray, b: ByteArray): ByteArray {
        val out = ByteArray(a.size + b.size)
        System.arraycopy(a, 0, out, 0, a.size)
        System.arraycopy(b, 0, out, a.size, b.size)
        return out
    }

    private fun equalsConstTime(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var r = 0
        for (i in a.indices) {
            r = r or (a[i].toInt() xor b[i].toInt())
        }
        return r == 0
    }

    private companion object {
        private const val PROTO_AID = "F04E4643454D5531"
        private const val PROTO_KEY_HEX = "00112233445566778899AABBCCDDEEFF"
    }
}
