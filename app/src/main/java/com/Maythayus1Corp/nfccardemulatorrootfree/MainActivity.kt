package com.Maythayus1Corp.nfccardemulatorrootfree

import android.content.Intent
import android.net.Uri
import android.nfc.NfcAdapter
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Base64
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.BorderStroke
import com.Maythayus1Corp.nfccardemulatorrootfree.ui.theme.NFCCARDEMULATORROOTFREETheme
import java.util.UUID
import kotlin.math.min

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val prefs = getSharedPreferences("app_prefs", MODE_PRIVATE)
        val shouldShowSupportDialog = !prefs.getBoolean("support_dialog_dismissed", false)

        setContent {
            NFCCARDEMULATORROOTFREETheme {
                SupportDialog(
                    initialShow = shouldShowSupportDialog,
                    onDismiss = {
                        prefs.edit().putBoolean("support_dialog_dismissed", true).apply()
                    }
                )
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    HomeScreen(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

@Composable
private fun SupportDialog(
    initialShow: Boolean,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val latestOnDismiss = rememberUpdatedState(onDismiss)
    val showDialogState = remember { mutableStateOf(initialShow) }

    LaunchedEffect(initialShow) {
        showDialogState.value = initialShow
    }

    if (!showDialogState.value) return

    AlertDialog(
        onDismissRequest = {
            showDialogState.value = false
            latestOnDismiss.value()
        },
        title = {
            Text(text = "Soutenir le projet")
        },
        text = {
            Text(text = "Si l’application te plaît, tu peux soutenir en t’abonnant à ma chaîne YouTube et en visitant mon SoundCloud.")
        },
        confirmButton = {
            TextButton(
                onClick = {
                    context.startActivity(
                        Intent(
                            Intent.ACTION_VIEW,
                            Uri.parse("https://www.youtube.com/@maythayus1?sub_confirmation=1")
                        )
                    )
                }
            ) {
                Text(text = "YouTube")
            }
        },
        dismissButton = {
            TextButton(
                onClick = {
                    context.startActivity(
                        Intent(
                            Intent.ACTION_VIEW,
                            Uri.parse("https://soundcloud.com/user-807863479-448305626")
                        )
                    )
                }
            ) {
                Text(text = "SoundCloud")
            }
        }
    )
}

@Composable
private fun HomeScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val adapter = remember { NfcAdapter.getDefaultAdapter(context) }
    val isNfcSupported = adapter != null
    val isNfcEnabled = adapter?.isEnabled == true

    var activeId by remember { mutableStateOf<String?>(null) }
    var cards by remember { mutableStateOf<List<CardProfile>>(emptyList()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var logTick by remember { mutableStateOf(0) }

    fun persist(newActiveId: String?, newCards: List<CardProfile>) {
        AppLog.i("persist(activeId=${newActiveId ?: "null"}, cards=${newCards.size})")
        activeId = newActiveId
        cards = newCards
        CardStore.save(context, newActiveId, newCards)
        logTick++
    }

    LaunchedEffect(Unit) {
        AppLog.i("HomeScreen start")
        val (loadedActiveId, loadedCards) = CardStore.load(context)
        AppLog.i("CardStore loaded activeId=${loadedActiveId ?: "null"} cards=${loadedCards.size}")
        if (loadedCards.isEmpty()) {
            val defaultCard = CardProfile(
                id = UUID.randomUUID().toString(),
                name = "Default Card",
                aidHex = "F0010203040506",
                apduMap = emptyMap(),
                dumpJson = null,
            )
            persist(defaultCard.id, listOf(defaultCard))
        } else {
            activeId = loadedActiveId ?: loadedCards.firstOrNull()?.id
            cards = loadedCards
            CardStore.save(context, activeId, loadedCards)
            logTick++
        }
    }

    val activeCard = cards.firstOrNull { it.id == activeId }

    var dumpName by remember { mutableStateOf<String?>(null) }
    var dumpSizeBytes by remember { mutableStateOf<Long?>(null) }
    var dumpPreview by remember { mutableStateOf<String?>(null) }
    var dumpKind by remember { mutableStateOf<String?>(null) }
    var importedDumpJson by remember { mutableStateOf<String?>(null) }

    val openDumpLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult

            try {
                AppLog.i("IMPORT DUMP uri=$uri")
                val cr = context.contentResolver

                cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
                    ?.use { cursor ->
                        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (cursor.moveToFirst()) {
                            dumpName = if (nameIndex >= 0) cursor.getString(nameIndex) else uri.lastPathSegment
                            dumpSizeBytes = if (sizeIndex >= 0) cursor.getLong(sizeIndex) else null
                        }
                    }

                val bytes = cr.openInputStream(uri)?.use { it.readBytes() } ?: byteArrayOf()
                AppLog.i("IMPORT DUMP bytes=${bytes.size}")
                val prefix = bytes.copyOfRange(0, min(bytes.size, 4096))

                fun likelyUtf16Le(data: ByteArray): Boolean {
                    if (data.size < 4) return false
                    var zerosOnOdd = 0
                    var checked = 0
                    val n = min(data.size, 512)
                    var i = 1
                    while (i < n) {
                        if (data[i] == 0.toByte()) zerosOnOdd++
                        checked++
                        i += 2
                    }
                    return checked > 0 && zerosOnOdd.toFloat() / checked.toFloat() > 0.6f
                }

                fun likelyUtf16Be(data: ByteArray): Boolean {
                    if (data.size < 4) return false
                    var zerosOnEven = 0
                    var checked = 0
                    val n = min(data.size, 512)
                    var i = 0
                    while (i < n) {
                        if (data[i] == 0.toByte()) zerosOnEven++
                        checked++
                        i += 2
                    }
                    return checked > 0 && zerosOnEven.toFloat() / checked.toFloat() > 0.6f
                }

                val decodedText = try {
                    when {
                        likelyUtf16Le(prefix) -> bytes.toString(Charsets.UTF_16LE)
                        likelyUtf16Be(prefix) -> bytes.toString(Charsets.UTF_16BE)
                        else -> bytes.toString(Charsets.UTF_8)
                    }
                } catch (_: Throwable) {
                    ""
                }

                val text = decodedText.replace("\u0000", "")
                val normalized = text.replace("\r\n", "\n")

                val trimmed = normalized.trim()
                val isJsonObject = trimmed.startsWith("{")
                if (isJsonObject) {
                    try {
                        val root = org.json.JSONObject(trimmed)
                        val uid = root.optString("uid", "").trim()
                        if (uid.isNotBlank() && root.has("sectors")) {
                            AppLog.i("Detected VIGIK JSON uid=$uid")
                            dumpKind = "MIFARE Classic / VIGIK JSON"
                            dumpPreview = trimmed.take(1500)
                            importedDumpJson = trimmed

                            if (cards.isEmpty()) {
                                val newCard = CardProfile(
                                    id = UUID.randomUUID().toString(),
                                    name = "Badge $uid",
                                    aidHex = "F0010203040506",
                                    apduMap = emptyMap(),
                                    dumpJson = trimmed,
                                )
                                val newCards = cards + newCard
                                persist(newCard.id, newCards)
                                Toast.makeText(context, "Card restored from dump", Toast.LENGTH_SHORT).show()
                                AppLog.i("Auto-restored card from VIGIK JSON id=${newCard.id}")
                            } else if (!activeId.isNullOrBlank()) {
                                val id = activeId
                                val newCards = cards.map { c ->
                                    if (c.id == id) c.copy(dumpJson = trimmed) else c
                                }
                                persist(id, newCards)
                                Toast.makeText(context, "Dump attached to active card", Toast.LENGTH_SHORT).show()
                                AppLog.i("Auto-attached VIGIK JSON to active card id=$id")
                            }
                            return@rememberLauncherForActivityResult
                        }

                        // Generic JSON: keep JSON as-is (do not wrap as raw base64)
                        dumpKind = "JSON (unsupported)"
                        dumpPreview = trimmed.take(1500)
                        importedDumpJson = trimmed
                        Toast.makeText(context, "Imported JSON (not a VIGIK dump)", Toast.LENGTH_SHORT).show()
                        return@rememberLauncherForActivityResult
                    } catch (t: Throwable) {
                        AppLog.w("JSON parse failed: ${t.javaClass.simpleName}: ${t.message}")
                    }
                }

                val hexPreview = Hex.bytesToHex(prefix)
                    .chunked(2)
                    .chunked(16)
                    .joinToString("\n") { row -> row.joinToString(" ") }

                val looksLikeText = (
                    normalized.any { it.code in 32..126 } &&
                    normalized.count { it == '\uFFFD' } == 0
                )

                dumpPreview = if (looksLikeText) {
                    normalized.take(1000)
                } else {
                    "(binary file)\n$hexPreview".take(1500)
                }

                val upper = normalized.uppercase()
                val hexUpper = hexPreview.replace(" ", "").replace("\n", "").uppercase()
                val fileNameUpper = (dumpName ?: "").uppercase()
                val isLikelyClassic1kRaw = (bytes.size == 1024) || fileNameUpper.endsWith(".DUMP")
                val looksLikeApduTraceText = looksLikeText && (
                    upper.contains("->") ||
                        upper.contains("APDU") ||
                        upper.contains("SELECT AID") ||
                        upper.contains("CLA=")
                )
                dumpKind = when {
                    upper.contains("\"sectors\"") && upper.contains("\"keys\"") && upper.contains("\"uid\"") -> "MIFARE Classic / VIGIK JSON"
                    isLikelyClassic1kRaw -> "MIFARE Classic 1K (raw dump)"
                    hexUpper.contains("484558414354") -> "HEXACT / MIFARE Classic-like"
                    looksLikeApduTraceText -> "APDU (ISO7816)"
                    upper.contains("SECTOR") || upper.contains("BLOCK") || upper.contains("KEY A") || upper.contains("KEY B") -> "MIFARE Classic-like"
                    else -> "Unknown"
                }
                AppLog.i("Dump classified kind=${dumpKind ?: "null"} name=${dumpName ?: "null"}")

                importedDumpJson = org.json.JSONObject().apply {
                    put("format", "raw")
                    put("fileName", dumpName ?: org.json.JSONObject.NULL)
                    put("kind", dumpKind ?: org.json.JSONObject.NULL)
                    put("base64", Base64.encodeToString(bytes, Base64.NO_WRAP))
                }.toString()

                if (cards.isEmpty()) {
                    val name = dumpName?.takeIf { it.isNotBlank() } ?: "Imported dump"
                    val newCard = CardProfile(
                        id = UUID.randomUUID().toString(),
                        name = name,
                        aidHex = "F0010203040506",
                        apduMap = emptyMap(),
                        dumpJson = importedDumpJson,
                    )
                    val newCards = cards + newCard
                    persist(newCard.id, newCards)
                    Toast.makeText(context, "Card restored from dump", Toast.LENGTH_SHORT).show()
                    AppLog.i("Auto-restored card from raw dump id=${newCard.id}")
                }
            } catch (t: Throwable) {
                AppLog.e("IMPORT DUMP error: ${t.javaClass.simpleName}: ${t.message}")
                dumpName = null
                dumpSizeBytes = null
                dumpPreview = null
                dumpKind = "Error reading file"
                importedDumpJson = null
            }
        }
    )

    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json"),
        onResult = { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult
            try {
                val json = CardStore.exportJson(context)
                context.contentResolver.openOutputStream(uri)?.use { os ->
                    os.write(json.toByteArray())
                }
            } catch (_: Throwable) {
            }
        }
    )

    val exportLogLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
        onResult = { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult
            try {
                val text = AppLog.snapshotText()
                context.contentResolver.openOutputStream(uri)?.use { os ->
                    os.write(text.toByteArray())
                }
                Toast.makeText(context, "Log exported", Toast.LENGTH_SHORT).show()
            } catch (_: Throwable) {
                Toast.makeText(context, "Log export failed", Toast.LENGTH_SHORT).show()
            }
        }
    )

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult
            try {
                val json = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                    ?: return@rememberLauncherForActivityResult
                CardStore.importJson(context, json)
                val (loadedActiveId, loadedCards) = CardStore.load(context)
                activeId = loadedActiveId
                cards = loadedCards
            } catch (_: Throwable) {
            }
        }
    )

    val neon = Color(0xFF00E5FF)
    val neonDim = Color(0x6600E5FF)
    val bgTop = Color(0xFF050915)
    val bgBottom = Color(0xFF02040A)

    fun Modifier.hudGrid(): Modifier = this.drawBehind {
        val spacing = 36.dp.toPx()
        val stroke = 1.dp.toPx()
        val gridColor = Color(0x1A00E5FF)

        var x = 0f
        while (x <= size.width) {
            drawLine(
                color = gridColor,
                start = Offset(x, 0f),
                end = Offset(x, size.height),
                strokeWidth = stroke
            )
            x += spacing
        }

        var y = 0f
        while (y <= size.height) {
            drawLine(
                color = gridColor,
                start = Offset(0f, y),
                end = Offset(size.width, y),
                strokeWidth = stroke
            )
            y += spacing
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(bgTop, bgBottom)
                )
            )
            .hudGrid()
            .padding(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 24.dp)
        ) {
            Text(
                text = "NFC CARD EMULATOR",
                style = MaterialTheme.typography.headlineMedium,
                color = neon,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "HCE / HOST-BASED EMULATION",
                style = MaterialTheme.typography.labelMedium,
                color = neonDim,
                modifier = Modifier.padding(top = 2.dp)
            )

            Spacer(modifier = Modifier.height(16.dp))

            HudChip(
                label = "NFC",
                value = if (isNfcSupported) "SUPPORTED" else "NO",
                ok = isNfcSupported,
                neon = neon,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(10.dp))
            HudChip(
                label = "STATE",
                value = if (!isNfcSupported) "N/A" else if (isNfcEnabled) "ON" else "OFF",
                ok = isNfcSupported && isNfcEnabled,
                neon = neon,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(14.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0x990B1024)),
                border = BorderStroke(1.dp, Color(0x3300E5FF)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                        ,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "EMULATION PROFILE",
                            style = MaterialTheme.typography.labelLarge,
                            color = neonDim
                        )
                        Text(
                            text = "v1",
                            style = MaterialTheme.typography.labelLarge,
                            color = neon
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    HudKeyValue(keyText = "Active card", valueText = activeCard?.name ?: "(none)", neon = neon)
                    Spacer(modifier = Modifier.height(8.dp))
                    HudKeyValue(keyText = "AID", valueText = activeCard?.aidHex ?: "(none)", neon = neon)
                    Spacer(modifier = Modifier.height(8.dp))
                    HudKeyValue(keyText = "APDU rules", valueText = "${activeCard?.apduMap?.size ?: 0}", neon = neon)
                    Spacer(modifier = Modifier.height(8.dp))
                    HudKeyValue(keyText = "Dump", valueText = if (activeCard?.dumpJson.isNullOrBlank()) "(none)" else "attached", neon = neon)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0x990B1024)),
                border = BorderStroke(1.dp, Color(0x3300E5FF)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "CARDS",
                        style = MaterialTheme.typography.labelLarge,
                        color = neonDim
                    )
                    Spacer(modifier = Modifier.height(10.dp))

                    if (cards.isEmpty()) {
                        Text(
                            text = "No cards",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xCCFFFFFF)
                        )
                    } else {
                        for (c in cards) {
                            val isActive = c.id == activeId
                            Card(
                                colors = CardDefaults.cardColors(containerColor = if (isActive) Color(0x1A00E5FF) else Color(0x660B1024)),
                                border = BorderStroke(1.dp, if (isActive) Color(0x6600E5FF) else Color(0x3326304D)),
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 10.dp)
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically
                                        ,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            text = c.name,
                                            style = MaterialTheme.typography.titleSmall,
                                            color = if (isActive) neon else Color(0xCCFFFFFF),
                                            fontWeight = FontWeight.SemiBold
                                        )
                                        Text(
                                            text = if (isActive) "ACTIVE" else "",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = neonDim
                                        )
                                    }
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text(
                                        text = "AID: ${c.aidHex}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = Color(0xB3FFFFFF)
                                    )

                                    Spacer(modifier = Modifier.height(10.dp))
                                    Button(
                                        onClick = {
                                            AppLog.i("USE card id=${c.id}")
                                            persist(c.id, cards)
                                        },
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(text = "USE")
                                    }
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Button(
                                        onClick = {
                                            AppLog.w("DELETE card id=${c.id}")
                                            val newCards = cards.filterNot { it.id == c.id }
                                            val newActive = if (activeId == c.id) newCards.firstOrNull()?.id else activeId
                                            persist(newActive, newCards)
                                        },
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(text = "DELETE")
                                    }
                                }
                            }
                        }
                    }

                    Button(
                        onClick = { showAddDialog = true },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "ADD")
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = { exportLauncher.launch("cards-backup.json") },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "BACKUP")
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = { importLauncher.launch(arrayOf("application/json", "*/*")) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "RESTORE")
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Button(
                onClick = {
                    openDumpLauncher.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = "IMPORT DUMP")
            }

            if (dumpKind != null) {
                Spacer(modifier = Modifier.height(14.dp))
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0x990B1024)),
                    border = BorderStroke(1.dp, Color(0x3300E5FF)),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "DUMP",
                            style = MaterialTheme.typography.labelLarge,
                            color = neonDim
                        )
                        Spacer(modifier = Modifier.height(10.dp))

                        HudKeyValue(
                            keyText = "Type",
                            valueText = dumpKind ?: "",
                            neon = neon
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        HudKeyValue(
                            keyText = "File",
                            valueText = dumpName ?: "(unknown)",
                            neon = neon
                        )

                        Spacer(modifier = Modifier.height(10.dp))
                        Button(
                            onClick = {
                                val dump = importedDumpJson
                                val id = activeId
                                if (dump.isNullOrBlank() || id.isNullOrBlank()) {
                                    Toast.makeText(context, "Select a card and import a dump first", Toast.LENGTH_SHORT).show()
                                    AppLog.w("ATTACH failed dumpEmpty=${dump.isNullOrBlank()} activeId=${id ?: "null"}")
                                    return@Button
                                }
                                val newCards = cards.map { c ->
                                    if (c.id == id) c.copy(dumpJson = dump) else c
                                }
                                persist(id, newCards)
                                Toast.makeText(context, "Dump attached to active card", Toast.LENGTH_SHORT).show()
                                AppLog.i("Dump attached to card id=$id")
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(text = "ATTACH TO ACTIVE CARD")
                        }

                        Spacer(modifier = Modifier.height(10.dp))
                        Button(
                            onClick = {
                                val dump = importedDumpJson
                                if (dump.isNullOrBlank()) {
                                    Toast.makeText(context, "Import a dump first", Toast.LENGTH_SHORT).show()
                                    AppLog.w("CREATE CARD failed: dump is blank")
                                    return@Button
                                }

                                val name = when {
                                    dumpKind?.contains("VIGIK", ignoreCase = true) == true -> {
                                        try {
                                            val uid = org.json.JSONObject(dump).optString("uid", "").trim()
                                            if (uid.isBlank()) "Imported badge" else "Badge $uid"
                                        } catch (_: Throwable) {
                                            "Imported dump"
                                        }
                                    }
                                    else -> "Imported dump"
                                }

                                val newCard = CardProfile(
                                    id = UUID.randomUUID().toString(),
                                    name = name,
                                    aidHex = "F0010203040506",
                                    apduMap = emptyMap(),
                                    dumpJson = dump,
                                )
                                val newCards = cards + newCard
                                persist(newCard.id, newCards)
                                Toast.makeText(context, "New card created from dump", Toast.LENGTH_SHORT).show()
                                AppLog.i("Created card from dump id=${newCard.id}")
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(text = "CREATE CARD FROM DUMP")
                        }

                        if (dumpSizeBytes != null) {
                            Spacer(modifier = Modifier.height(8.dp))
                            HudKeyValue(
                                keyText = "Size",
                                valueText = "${dumpSizeBytes} bytes",
                                neon = neon
                            )
                        }

                        if (!dumpPreview.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = "PREVIEW",
                                style = MaterialTheme.typography.labelMedium,
                                color = neonDim
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = dumpPreview ?: "",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xCCFFFFFF)
                            )
                        }
                    }
                }
            }

            if (isNfcSupported && !isNfcEnabled) {
                Spacer(modifier = Modifier.height(14.dp))
                Button(
                    onClick = {
                        context.startActivity(Intent(android.provider.Settings.ACTION_NFC_SETTINGS))
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = "OPEN NFC SETTINGS")
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = "TIP: Pour émuler un badge via HCE, il faut un mapping APDU → réponse.",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0x99FFFFFF)
            )

            Spacer(modifier = Modifier.height(14.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0x990B1024)),
                border = BorderStroke(1.dp, Color(0x3300E5FF)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "LOG",
                        style = MaterialTheme.typography.labelLarge,
                        color = neonDim
                    )

                    val logTickValue = logTick
                    val lines = AppLog.snapshot()

                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            cm.setPrimaryClip(ClipData.newPlainText("NFCCardEmu logs", AppLog.snapshotText()))
                            Toast.makeText(context, "Logs copied", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "COPY")
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            exportLogLauncher.launch("nfccardemu-log.txt")
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "EXPORT")
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            AppLog.clear()
                            logTick++
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "CLEAR")
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = lines.takeLast(120).joinToString("\n"),
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xCCFFFFFF)
                    )
                }
            }
        }
    }

    if (showAddDialog) {
        AddCardDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { name, aidHex ->
                val newCard = CardProfile(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    aidHex = Hex.normalize(aidHex),
                    apduMap = emptyMap(),
                    dumpJson = null,
                )
                val newCards = cards + newCard
                persist(newCard.id, newCards)
                showAddDialog = false
            }
        )
    }
}

@Composable
private fun AddCardDialog(
    onDismiss: () -> Unit,
    onAdd: (name: String, aidHex: String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var aid by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(text = "Add a new card") },
        text = {
            Column {
                TextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(text = "Card name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(10.dp))
                TextField(
                    value = aid,
                    onValueChange = { aid = it },
                    label = { Text(text = "AID (hex)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val n = name.trim()
                    val a = aid.trim()
                    if (n.isNotEmpty() && a.isNotEmpty()) {
                        onAdd(n, a)
                    }
                }
            ) {
                Text(text = "OK")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(text = "Cancel")
            }
        }
    )
}

@Composable
private fun HudChip(
    modifier: Modifier = Modifier,
    label: String,
    value: String,
    ok: Boolean,
    neon: Color,
) {
    val bg = if (ok) Color(0x1A00E5FF) else Color(0x1AFF2D55)
    val stroke = if (ok) Color(0x6600E5FF) else Color(0x66FF2D55)

    Card(
        colors = CardDefaults.cardColors(containerColor = bg),
        border = BorderStroke(1.dp, stroke),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier.height(56.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = Color(0x99FFFFFF)
            )
            Text(
                text = value,
                style = MaterialTheme.typography.titleSmall,
                color = if (ok) neon else Color(0xFFFF2D55),
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
private fun HudKeyValue(
    keyText: String,
    valueText: String,
    neon: Color,
) {
    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "$keyText:",
            style = MaterialTheme.typography.bodyMedium,
            color = Color(0xB3FFFFFF)
        )
        Spacer(modifier = Modifier.width(10.dp))
        Text(
            text = valueText,
            style = MaterialTheme.typography.bodyMedium,
            color = neon,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    NFCCARDEMULATORROOTFREETheme {
        HomeScreen()
    }
}