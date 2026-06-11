package com.Maythayus1Corp.nfccardemulatorrootfree

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

internal data class CardProfile(
    val id: String,
    val name: String,
    val aidHex: String,
    val apduMap: Map<String, String>,
    val dumpJson: String?,
)

internal object CardStore {
    private const val PREFS = "card_store"
    private const val KEY_ACTIVE_ID = "active_id"
    private const val KEY_CARDS_JSON = "cards_json"

    fun load(context: Context): Pair<String?, List<CardProfile>> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val activeId = prefs.getString(KEY_ACTIVE_ID, null)
        val json = prefs.getString(KEY_CARDS_JSON, null) ?: "[]"
        val cards = parseCards(json)
        return activeId to cards
    }

    fun save(context: Context, activeId: String?, cards: List<CardProfile>) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_ACTIVE_ID, activeId)
            .putString(KEY_CARDS_JSON, serializeCards(cards))
            .apply()
    }

    fun getActive(context: Context): CardProfile? {
        val (activeId, cards) = load(context)
        return cards.firstOrNull { it.id == activeId }
    }

    fun exportJson(context: Context): String {
        val (activeId, cards) = load(context)
        val root = JSONObject()
        root.put("activeId", activeId ?: JSONObject.NULL)
        val arr = JSONArray()
        for (c in cards) {
            arr.put(cardToJson(c))
        }
        root.put("cards", arr)
        return root.toString(2)
    }

    fun importJson(context: Context, json: String) {
        val root = JSONObject(json)
        val activeId = if (!root.has("activeId") || root.isNull("activeId")) null else root.getString("activeId")
        val cardsArray = root.optJSONArray("cards") ?: JSONArray()
        val cards = ArrayList<CardProfile>(cardsArray.length())
        for (i in 0 until cardsArray.length()) {
            val obj = cardsArray.optJSONObject(i) ?: continue
            cards.add(parseCard(obj))
        }
        save(context, activeId, cards)
    }

    private fun parseCards(json: String): List<CardProfile> {
        return try {
            val arr = JSONArray(json)
            val out = ArrayList<CardProfile>(arr.length())
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                out.add(parseCard(obj))
            }
            out
        } catch (_: Throwable) {
            emptyList()
        }
    }

    private fun serializeCards(cards: List<CardProfile>): String {
        val arr = JSONArray()
        for (c in cards) {
            arr.put(cardToJson(c))
        }
        return arr.toString()
    }

    private fun cardToJson(c: CardProfile): JSONObject {
        val o = JSONObject()
        o.put("id", c.id)
        o.put("name", c.name)
        o.put("aidHex", c.aidHex)
        val mapObj = JSONObject()
        for ((k, v) in c.apduMap) mapObj.put(k, v)
        o.put("apduMap", mapObj)
        o.put("dumpJson", c.dumpJson ?: JSONObject.NULL)
        return o
    }

    private fun parseCard(obj: JSONObject): CardProfile {
        val id = obj.optString("id")
        val name = obj.optString("name")
        val aidHex = obj.optString("aidHex")
        val apduObj = obj.optJSONObject("apduMap") ?: JSONObject()
        val apduMap = LinkedHashMap<String, String>()
        val keys = apduObj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            apduMap[k] = apduObj.optString(k)
        }
        val dumpJson = if (!obj.has("dumpJson") || obj.isNull("dumpJson")) null else obj.optString("dumpJson")
        return CardProfile(id = id, name = name, aidHex = aidHex, apduMap = apduMap, dumpJson = dumpJson)
    }
}

internal object Hex {
    fun normalize(hex: String): String {
        return hex.replace(" ", "").replace("\n", "").replace("\r", "").uppercase()
    }

    fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(((b.toInt() ushr 4) and 0xF).toString(16))
            sb.append((b.toInt() and 0xF).toString(16))
        }
        return sb.toString().uppercase()
    }

    fun hexToBytes(hex: String): ByteArray {
        val s = normalize(hex)
        if (s.isEmpty()) return ByteArray(0)
        val len = s.length
        val out = ByteArray((len + 1) / 2)
        var i = 0
        var j = 0
        if (len % 2 == 1) {
            out[j++] = (s[0].digitToInt(16)).toByte()
            i = 1
        }
        while (i < len) {
            val hi = s[i].digitToInt(16)
            val lo = s[i + 1].digitToInt(16)
            out[j++] = ((hi shl 4) or lo).toByte()
            i += 2
        }
        return if (j == out.size) out else out.copyOf(j)
    }
}
