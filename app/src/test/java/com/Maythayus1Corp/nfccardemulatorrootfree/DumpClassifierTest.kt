package com.Maythayus1Corp.nfccardemulatorrootfree

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DumpClassifierTest {

    @Test
    fun decodesPlainUtf8() {
        val text = DumpClassifier.decodeText("uid=ABCD".toByteArray(Charsets.UTF_8))
        assertEquals("uid=ABCD", text)
    }

    @Test
    fun decodesUtf16LeAndStripsNulls() {
        // "KEY A" en UTF-16LE : un octet nul sur deux.
        val bytes = "KEY A".toByteArray(Charsets.UTF_16LE)
        val text = DumpClassifier.decodeText(bytes)
        assertEquals("KEY A", text)
        assertFalse(text.contains('\u0000'))
    }

    @Test
    fun looksLikeTextRejectsBinary() {
        val binary = String(CharArray(10) { '�' })
        assertFalse(DumpClassifier.looksLikeText(binary))
        assertTrue(DumpClassifier.looksLikeText("SECTOR 0 BLOCK 1"))
    }

    @Test
    fun classifiesVigikJsonWhateverTheCase() {
        // Regression : les aiguilles etaient comparees en minuscules a un texte mis en
        // majuscules, donc cette branche ne se declenchait jamais.
        val json = """{"uid":"11223344","sectors":{...},"keys":[...]}"""
        val kind = DumpClassifier.classifyKind(json, DumpClassifier.hexPreview(json.toByteArray()), "badge.json", json.length)
        assertEquals("MIFARE Classic / VIGIK JSON", kind)
    }

    @Test
    fun classifiesRaw1kDumpBySize() {
        val bytes = ByteArray(1024)
        val kind = DumpClassifier.classifyKind(
            DumpClassifier.normalize(DumpClassifier.decodeText(bytes)),
            DumpClassifier.hexPreview(bytes),
            "card.bin",
            bytes.size,
        )
        assertEquals("MIFARE Classic 1K (raw dump)", kind)
    }

    @Test
    fun classifiesRaw1kDumpByExtension() {
        val kind = DumpClassifier.classifyKind("", "", "mycard.DUMP", 512)
        assertEquals("MIFARE Classic 1K (raw dump)", kind)
    }

    @Test
    fun classifiesApduTrace() {
        val trace = "00A4040007 SELECT AID -> 9000\nCLA=00 INS=B0"
        val kind = DumpClassifier.classifyKind(trace, "", "trace.log", trace.length)
        assertEquals("APDU (ISO7816)", kind)
    }

    @Test
    fun classifiesMifareLikeFromKeywords() {
        val content = "Sector 0\nKey A: FFFFFFFFFFFF\nBlock 1"
        val kind = DumpClassifier.classifyKind(content, "", "dump.txt", content.length)
        assertEquals("MIFARE Classic-like", kind)
    }

    @Test
    fun unknownWhenNothingMatches() {
        val kind = DumpClassifier.classifyKind("random notes", "", "notes.txt", 12)
        assertEquals("Unknown", kind)
    }
}
