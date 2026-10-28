package com.Maythayus1Corp.nfccardemulatorrootfree

import kotlin.math.min

/**
 * Analyse en lecture seule d'un fichier importé (dump de carte, trace APDU…).
 *
 * Fonctions pures, sans dépendance Android, pour qu'elles soient couvertes par des tests
 * unitaires : décodage du texte avec détection d'encodage, aperçu hexadécimal et
 * classification du type de fichier. Rien ici ne pilote l'émulation ; c'est uniquement
 * du diagnostic pour l'utilisateur.
 */
object DumpClassifier {

    /** Seuls les premiers octets servent à deviner l'encodage et à bâtir l'aperçu. */
    const val PREFIX_LIMIT = 4096

    private fun prefix(bytes: ByteArray): ByteArray = bytes.copyOfRange(0, min(bytes.size, PREFIX_LIMIT))

    /** Décode les octets en texte en devinant l'encodage (UTF-16 LE/BE sinon UTF-8). */
    fun decodeText(bytes: ByteArray): String {
        val head = prefix(bytes)
        val decoded = runCatching {
            when {
                likelyUtf16Le(head) -> bytes.toString(Charsets.UTF_16LE)
                likelyUtf16Be(head) -> bytes.toString(Charsets.UTF_16BE)
                else -> bytes.toString(Charsets.UTF_8)
            }
        }.getOrDefault("")
        return decoded.replace("\u0000", "")
    }

    /** Uniformise les fins de ligne pour une comparaison stable. */
    fun normalize(decodedText: String): String = decodedText.replace("\r\n", "\n")

    /** Aperçu hexadécimal des premiers octets, 16 octets par ligne. */
    fun hexPreview(bytes: ByteArray): String =
        Hex.bytesToHex(prefix(bytes))
            .chunked(2)
            .chunked(16)
            .joinToString("\n") { row -> row.joinToString(" ") }

    /** Vrai si le contenu ressemble à du texte lisible (ASCII imprimable, sans caractère de remplacement). */
    fun looksLikeText(normalizedText: String): Boolean =
        normalizedText.any { it.code in 32..126 } && normalizedText.count { it == '�' } == 0

    /**
     * Devine le type du dump à partir du texte, de l'aperçu hexadécimal, du nom de fichier
     * et de la taille. Classification de secours : un dump VIGIK JSON valide est déjà
     * reconnu en amont par le parsing JSON.
     */
    fun classifyKind(
        normalizedText: String,
        hexPreview: String,
        fileName: String?,
        sizeBytes: Int,
    ): String {
        val upper = normalizedText.uppercase()
        val hexUpper = hexPreview.replace(" ", "").replace("\n", "").uppercase()
        val fileNameUpper = (fileName ?: "").uppercase()
        val isLikelyClassic1kRaw = sizeBytes == 1024 || fileNameUpper.endsWith(".DUMP")
        val looksLikeApduTraceText = looksLikeText(normalizedText) && (
            upper.contains("->") ||
                upper.contains("APDU") ||
                upper.contains("SELECT AID") ||
                upper.contains("CLA=")
            )
        return when {
            // Aiguilles comparées en MAJUSCULES, comme `upper` (l'ancien code les laissait en
            // minuscules : la branche ne se déclenchait jamais).
            upper.contains("\"SECTORS\"") && upper.contains("\"KEYS\"") && upper.contains("\"UID\"") ->
                "MIFARE Classic / VIGIK JSON"
            isLikelyClassic1kRaw -> "MIFARE Classic 1K (raw dump)"
            hexUpper.contains("484558414354") -> "HEXACT / MIFARE Classic-like"
            looksLikeApduTraceText -> "APDU (ISO7816)"
            upper.contains("SECTOR") || upper.contains("BLOCK") ||
                upper.contains("KEY A") || upper.contains("KEY B") -> "MIFARE Classic-like"
            else -> "Unknown"
        }
    }

    private fun likelyUtf16Le(data: ByteArray): Boolean = zeroRatio(data, startOdd = true) > 0.6f

    private fun likelyUtf16Be(data: ByteArray): Boolean = zeroRatio(data, startOdd = false) > 0.6f

    /** Proportion d'octets nuls sur les positions paires (BE) ou impaires (LE) : typique de l'UTF-16 ASCII. */
    private fun zeroRatio(data: ByteArray, startOdd: Boolean): Float {
        if (data.size < 4) return 0f
        val n = min(data.size, 512)
        var zeros = 0
        var checked = 0
        var i = if (startOdd) 1 else 0
        while (i < n) {
            if (data[i] == 0.toByte()) zeros++
            checked++
            i += 2
        }
        return if (checked == 0) 0f else zeros.toFloat() / checked.toFloat()
    }
}
