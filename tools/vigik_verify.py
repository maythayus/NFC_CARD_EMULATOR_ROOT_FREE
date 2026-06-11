#!/usr/bin/env python3
"""
VIGIK Verify — Comparaison badge physique vs émulation HCE
Utilise le lecteur ACR122U via PC/SC (pyscard)

Usage:
  python vigik_verify.py read       Lire un badge VIGIK physique (MIFARE Classic)
  python vigik_verify.py hce        Tester l'émulation HCE du téléphone
  python vigik_verify.py compare    Lire badge + tester HCE + comparer bloc par bloc
  python vigik_verify.py dump FILE  Comparer un fichier .hex avec l'émulation HCE

Prérequis:
  pip install pyscard colorama
"""

import sys
import json
import time
from datetime import datetime

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import CardConnectionException, NoCardException
except ImportError:
    print("ERREUR: pyscard non installé.")
    print("  pip install pyscard")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""


# ─── MIFARE Classic keys ────────────────────────────────────────────────────

KNOWN_KEYS = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("484558414354"),  # HEXACT
    bytes.fromhex("A22AE129C013"),
    bytes.fromhex("49FAE4E3849F"),
    bytes.fromhex("38FCF33072E0"),
    bytes.fromhex("8AD5517B4B18"),
    bytes.fromhex("509359F131B1"),
    bytes.fromhex("6C78928E1317"),
    bytes.fromhex("AA0720018738"),
    bytes.fromhex("A6CAC2886412"),
    bytes.fromhex("62D0C424ED8E"),
    bytes.fromhex("E64A986A5D94"),
    bytes.fromhex("8FA1D601D0A2"),
    bytes.fromhex("89347350BD36"),
    bytes.fromhex("66D2B7DC39EF"),
    bytes.fromhex("6BC1E1AE547D"),
    bytes.fromhex("22729A9BD40F"),
    bytes.fromhex("707B11FC1481"),
    bytes.fromhex("4B791BEA7BCC"),
    bytes.fromhex("8A19D40CF2B8"),
    bytes.fromhex("1A982C7E459A"),
    bytes.fromhex("AABBCCDDEEFF"),
    bytes.fromhex("010203040506"),
    bytes.fromhex("B0B1B2B3B4B5"),
]

# ACR122U pseudo-APDU commands
CMD_GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
CMD_GET_ATS = [0xFF, 0xCA, 0x01, 0x00, 0x00]


def hex_str(data):
    return " ".join(f"{b:02X}" for b in data)


def bytes_to_hex(data):
    return " ".join(f"{b:02X}" for b in data)


# ─── ACR122U helpers ────────────────────────────────────────────────────────

def connect_reader(msg="Posez le badge/téléphone sur le lecteur..."):
    """Detect ACR122U and wait for card/phone."""
    available = readers()
    if not available:
        print(f"{Fore.RED}Aucun lecteur NFC détecté.{Style.RESET_ALL}")
        return None, None

    print(f"{Fore.CYAN}Lecteurs:{Style.RESET_ALL}")
    for r in available:
        print(f"  • {r}")

    reader = None
    for r in available:
        name = str(r).upper()
        if "ACR122" in name or "ACS" in name or "ACR1252" in name:
            reader = r
            break
    if reader is None:
        reader = available[0]

    print(f"\n{Fore.GREEN}→ {reader}{Style.RESET_ALL}")
    print(msg)

    for attempt in range(60):
        try:
            conn = reader.createConnection()
            conn.connect(CardConnection.T1_protocol)
            print(f"{Fore.GREEN}✓ Détecté (T=1){Style.RESET_ALL}\n")
            return reader, conn
        except:
            pass
        try:
            conn = reader.createConnection()
            conn.connect(CardConnection.T0_protocol)
            print(f"{Fore.GREEN}✓ Détecté (T=0){Style.RESET_ALL}\n")
            return reader, conn
        except:
            pass
        time.sleep(0.5)
        if attempt % 10 == 0 and attempt > 0:
            print(f"  Attente... ({attempt//2}s)")

    print(f"{Fore.RED}Timeout.{Style.RESET_ALL}")
    return reader, None


def send_apdu(conn, apdu, label=""):
    """Send APDU, return (data, sw1, sw2)."""
    try:
        data, sw1, sw2 = conn.transmit(apdu)
    except Exception as e:
        print(f"  {Fore.RED}ERR: {e}{Style.RESET_ALL}")
        return [], 0x6F, 0x00
    sw = f"{sw1:02X}{sw2:02X}"
    color = Fore.GREEN if sw1 == 0x90 else Fore.RED
    if label:
        print(f"  {label}: {color}[{sw}]{Style.RESET_ALL} {hex_str(data[:16])}{'...' if len(data)>16 else ''}")
    return data, sw1, sw2


def get_uid(conn):
    """Get UID via ACR122U pseudo-APDU."""
    data, sw1, sw2 = send_apdu(conn, CMD_GET_UID, "GET UID")
    if sw1 == 0x90:
        return bytes(data)
    return None


def load_key(conn, key_bytes, key_slot=0):
    """Load key into ACR122U volatile memory."""
    apdu = [0xFF, 0x82, 0x00, key_slot, 0x06] + list(key_bytes)
    try:
        data, sw1, sw2 = conn.transmit(apdu)
        return sw1 == 0x90
    except Exception:
        return False


def auth_block(conn, block_num, key_type='A', key_slot=0):
    """Authenticate a block. key_type = 'A' (0x60) or 'B' (0x61)."""
    kt = 0x60 if key_type == 'A' else 0x61
    apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_num, kt, key_slot]
    try:
        data, sw1, sw2 = conn.transmit(apdu)
        return sw1 == 0x90
    except Exception:
        return False


def read_block(conn, block_num):
    """Read 16 bytes from a block."""
    apdu = [0xFF, 0xB0, 0x00, block_num, 0x10]
    try:
        data, sw1, sw2 = conn.transmit(apdu)
        if sw1 == 0x90 and len(data) == 16:
            return bytes(data)
    except Exception:
        pass
    return None


def try_auth_sector(conn, sector):
    """Try all known keys on a sector, return (key_a, key_b)."""
    trailer_block = sector * 4 + 3
    found_a = None
    found_b = None

    for key in KNOWN_KEYS:
        if found_a and found_b:
            break
        try:
            if not found_a:
                if load_key(conn, key, 0):
                    if auth_block(conn, trailer_block, 'A', 0):
                        found_a = key
            if not found_b:
                if load_key(conn, key, 0):
                    if auth_block(conn, trailer_block, 'B', 0):
                        found_b = key
        except Exception:
            continue

    return found_a, found_b


def read_sector(conn, sector, key, key_type='A'):
    """Auth + read all 4 blocks of a sector."""
    trailer_block = sector * 4 + 3
    blocks = [None] * 4

    if not load_key(conn, key, 0):
        return blocks
    if not auth_block(conn, sector * 4, key_type, 0):
        # Try re-auth on trailer
        if not auth_block(conn, trailer_block, key_type, 0):
            return blocks

    for b in range(4):
        block_num = sector * 4 + b
        blocks[b] = read_block(conn, block_num)
    return blocks


# ─── READ physical VIGIK badge ─────────────────────────────────────────────

def read_vigik_badge(conn):
    """Read all sectors of a MIFARE Classic badge via ACR122U."""
    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  LECTURE BADGE VIGIK (MIFARE Classic)")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    uid = get_uid(conn)
    if uid is None:
        print(f"{Fore.RED}Impossible de lire l'UID.{Style.RESET_ALL}")
        return None

    print(f"  {Fore.GREEN}UID: {bytes_to_hex(uid)}{Style.RESET_ALL}")

    result = {
        "uid": bytes_to_hex(uid),
        "sectors": {},
        "keys": {},
        "timestamp": datetime.now().isoformat(),
    }

    total_read = 0

    for sector in range(16):
        key_a, key_b = try_auth_sector(conn, sector)
        ka_hex = bytes_to_hex(key_a) if key_a else "---"
        kb_hex = bytes_to_hex(key_b) if key_b else "---"
        result["keys"][str(sector)] = {"A": ka_hex, "B": kb_hex}

        key = key_a or key_b
        kt = 'A' if key_a else 'B'
        if key is None:
            print(f"  S{sector:02d}: {Fore.RED}✗ aucune clé trouvée{Style.RESET_ALL}")
            continue

        blocks = read_sector(conn, sector, key, kt)
        sector_data = {}
        ok = True
        for b in range(4):
            if blocks[b] is not None:
                sector_data[str(b)] = bytes_to_hex(blocks[b])
            else:
                sector_data[str(b)] = None
                ok = False
        result["sectors"][str(sector)] = sector_data

        if ok:
            total_read += 1
            b0 = sector_data.get("0", "") or ""
            preview = b0[:23] + "..." if len(b0) > 23 else b0
            print(f"  S{sector:02d}: {Fore.GREEN}✓{Style.RESET_ALL} A={ka_hex}  B={kb_hex}  B0={preview}")
        else:
            print(f"  S{sector:02d}: {Fore.YELLOW}~ partiel{Style.RESET_ALL}")

    result["sectors_read"] = total_read
    print(f"\n  {Fore.GREEN}Secteurs lus: {total_read}/16{Style.RESET_ALL}")
    return result


# ─── TEST HCE emulation ────────────────────────────────────────────────────

def test_hce_vigik(conn, reader=None):
    """Test VIGIK HCE emulator via ISO-DEP APDUs."""
    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  TEST ÉMULATION HCE VIGIK")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    result = {
        "timestamp": datetime.now().isoformat(),
        "uid": None,
        "sectors": {},
        "tests_passed": 0,
        "tests_failed": 0,
    }

    # Small delay to let HCE stabilize after NFC connection
    time.sleep(0.5)

    # 1. SELECT AID — try all registered AIDs with retries
    AIDS = [
        ("VIGIK",        [0xF0, 0x44, 0x56, 0x49, 0x47, 0x49]),       # F04456494749
        ("NOR",          [0xF0, 0x01, 0x4E, 0x4F, 0x52]),             # F0014E4F52
        ("Access Ctrl",  [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00]),  # D276000085010100
    ]
    print(f"{Fore.MAGENTA}[1] SELECT AID (avec retries){Style.RESET_ALL}")
    selected = False

    for attempt in range(5):  # Up to 5 attempts
        if attempt > 0:
            print(f"  {Fore.YELLOW}Retry {attempt}/4 — reconnexion...{Style.RESET_ALL}")
            time.sleep(1.5)
            # Reconnect
            if reader:
                try:
                    conn.disconnect()
                except:
                    pass
                try:
                    conn = reader.createConnection()
                    conn.connect(CardConnection.T1_protocol)
                    print(f"  {Fore.GREEN}✓ Reconnecté{Style.RESET_ALL}")
                    time.sleep(0.5)
                except Exception as e:
                    print(f"  {Fore.RED}Reconnexion échouée: {e}{Style.RESET_ALL}")
                    continue

        for aid_name, aid in AIDS:
            select_apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]
            try:
                data, sw1, sw2 = send_apdu(conn, select_apdu, f"SELECT {aid_name}")
            except Exception as e:
                print(f"  {Fore.RED}ERR: {e}{Style.RESET_ALL}")
                break  # Connection lost, need to reconnect
            if sw1 == 0x90:
                result["tests_passed"] += 1
                selected = True
                print(f"  {Fore.GREEN}✓ SELECT OK ({aid_name}) — FCI: {hex_str(data)}{Style.RESET_ALL}")
                for i in range(len(data) - 1):
                    if data[i] == 0x84:
                        ln = data[i + 1]
                        result["uid"] = hex_str(data[i + 2:i + 2 + ln])
                        print(f"  {Fore.GREEN}  UID émulé: {result['uid']}{Style.RESET_ALL}")
                        break
                break
            elif sw1 == 0x69 and sw2 == 0x85:
                print(f"  {Fore.YELLOW}⚠ AID {aid_name} reconnu mais émulation inactive (6985){Style.RESET_ALL}")
            elif sw1 == 0x6F:
                break  # Connection error, need to reconnect
            else:
                print(f"  {Fore.WHITE}  {aid_name}: {sw1:02X}{sw2:02X}{Style.RESET_ALL}")

        if selected:
            break

    if not selected:
        result["tests_failed"] += 1
        print(f"\n  {Fore.RED}✗ AUCUN AID ACCEPTÉ (après 5 tentatives){Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Vérifications:{Style.RESET_ALL}")
        print(f"    1. VigikTool installé et ouvert sur le téléphone ?")
        print(f"    2. Avez-vous scanné un badge puis appuyé 'Émuler via HCE' ?")
        print(f"    3. Le NFC est activé ?")
        print(f"    4. Le téléphone est bien posé sur le lecteur ACR122U ?")
        print(f"    5. Gardez le téléphone IMMOBILE sur le lecteur.")
        return result

    # 2. GET UID
    print(f"\n{Fore.MAGENTA}[2] GET DATA (UID){Style.RESET_ALL}")
    try:
        uid_apdu = [0x00, 0xCA, 0x00, 0x00, 0x00]
        data, sw1, sw2 = send_apdu(conn, uid_apdu, "GET UID")
        if sw1 == 0x90:
            result["tests_passed"] += 1
            result["uid_raw"] = hex_str(data)
            print(f"  {Fore.GREEN}✓ UID: {hex_str(data)}{Style.RESET_ALL}")
        else:
            result["tests_failed"] += 1
            print(f"  {Fore.RED}✗ GET UID: {sw1:02X}{sw2:02X}{Style.RESET_ALL}")
    except Exception as e:
        result["tests_failed"] += 1
        print(f"  {Fore.RED}ERR: {e}{Style.RESET_ALL}")

    # 3. READ all sectors via READ RECORD (B2)
    print(f"\n{Fore.MAGENTA}[3] READ SECTORS (INS=B2){Style.RESET_ALL}")
    for sector in range(16):
        sector_data = {}
        sector_ok = True
        for block in range(4):
            apdu = [0x00, 0xB2, sector, block, 0x10]
            try:
                data, sw1, sw2 = conn.transmit(apdu)
                if sw1 == 0x90 and len(data) >= 16:
                    sector_data[str(block)] = hex_str(data[:16])
                else:
                    sector_data[str(block)] = None
                    sector_ok = False
            except Exception:
                sector_data[str(block)] = None
                sector_ok = False
        result["sectors"][str(sector)] = sector_data
        if sector_ok:
            result["tests_passed"] += 1
            d = sector_data.get("0", "")
            print(f"  S{sector:02d}: {Fore.GREEN}✓{Style.RESET_ALL}  {d[:23]}..." if d else f"  S{sector:02d}: {Fore.GREEN}✓{Style.RESET_ALL}")
        else:
            result["tests_failed"] += 1
            print(f"  S{sector:02d}: {Fore.RED}✗{Style.RESET_ALL}")

    print(f"\n  Tests: {Fore.GREEN}{result['tests_passed']} OK{Style.RESET_ALL}, "
          f"{Fore.RED}{result['tests_failed']} FAIL{Style.RESET_ALL}")
    return result


# ─── COMPARE ────────────────────────────────────────────────────────────────

def compare_badge_hce(badge_data, hce_data):
    """Compare badge dump vs HCE sector by sector, block by block."""
    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  COMPARAISON BADGE vs ÉMULATION HCE")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    total = 0
    match = 0
    diff = 0
    skip = 0

    # UID check
    badge_uid = badge_data.get("uid", "")
    hce_uid = hce_data.get("uid") or hce_data.get("uid_raw", "")
    if badge_uid and hce_uid:
        if badge_uid.replace(" ", "").upper() == hce_uid.replace(" ", "").upper():
            print(f"  UID: {Fore.GREEN}✓ IDENTIQUE ({badge_uid}){Style.RESET_ALL}")
        else:
            print(f"  UID: {Fore.RED}✗ DIFFÉRENT{Style.RESET_ALL}")
            print(f"       Badge: {badge_uid}")
            print(f"       HCE:   {hce_uid}")

    print(f"\n  {'Sector':<8} {'Blk':<5} {'Résultat':<12} {'Détail'}")
    print(f"  {'─'*60}")

    for sector in range(16):
        s_badge = badge_data.get("sectors", {}).get(str(sector))
        s_hce = hce_data.get("sectors", {}).get(str(sector))

        if s_badge is None and s_hce is None:
            print(f"  S{sector:02d}     {'*':<5} {Fore.YELLOW}skip{Style.RESET_ALL}         non lu des deux côtés")
            skip += 4
            continue

        for block in range(4):
            total += 1
            b_badge = s_badge.get(str(block)) if s_badge else None
            b_hce = s_hce.get(str(block)) if s_hce else None

            blk_num = sector * 4 + block
            label = f"S{sector:02d}     B{block}"

            if b_badge is None or b_hce is None:
                print(f"  {label:<13} {Fore.YELLOW}skip{Style.RESET_ALL}         {'badge' if b_badge is None else 'HCE'} non lu")
                skip += 1
                continue

            # Normalize for comparison
            b1 = b_badge.replace(" ", "").upper()
            b2 = b_hce.replace(" ", "").upper()

            if block == 3:
                # Sector trailer layout: KeyA[6] + Access[3] + UserByte[1] + KeyB[6]
                # MIFARE Classic NEVER returns real Key A or Key B when reading trailer
                # → only compare access bits (bytes 6-9)
                # → for Key B, compare with the key found during authentication
                access_badge = b1[12:20]  # bytes 6-9 (access + user byte)
                access_hce = b2[12:20]

                # Get the real Key B from auth phase (stored in badge_data["keys"])
                badge_keys = badge_data.get("keys", {}).get(str(sector), {})
                real_keyb = badge_keys.get("B", "---").replace(" ", "").upper()
                keyb_hce = b2[20:32]  # bytes 10-15 from HCE dump

                access_ok = (access_badge == access_hce)
                # Compare HCE Key B with the actual Key B found by auth (not the masked 000000)
                keyb_ok = (real_keyb == "---" or real_keyb == keyb_hce)
                # If HCE Key B is all zeros, it's a dump without keys injected — not a real diff
                keyb_hce_zeros = (keyb_hce == "000000000000")

                if access_ok and keyb_ok:
                    match += 1
                    print(f"  {label:<13} {Fore.GREEN}✓ match{Style.RESET_ALL}      [TRAILER] access OK, KeyB OK")
                elif access_ok and keyb_hce_zeros:
                    match += 1
                    print(f"  {label:<13} {Fore.YELLOW}~ match{Style.RESET_ALL}      [TRAILER] access OK, KeyB absent du dump HCE")
                else:
                    diff += 1
                    print(f"  {label:<13} {Fore.RED}✗ DIFF{Style.RESET_ALL}       [TRAILER]")
                    if not access_ok:
                        print(f"               Access: badge={access_badge} hce={access_hce}")
                    if not keyb_ok and not keyb_hce_zeros:
                        print(f"               KeyB:   auth={real_keyb} hce={keyb_hce}")
            else:
                if b1 == b2:
                    match += 1
                    print(f"  {label:<13} {Fore.GREEN}✓ match{Style.RESET_ALL}      {b_badge[:23]}...")
                else:
                    diff += 1
                    print(f"  {label:<13} {Fore.RED}✗ DIFF{Style.RESET_ALL}")
                    print(f"               Badge: {b_badge}")
                    print(f"               HCE:   {b_hce}")
                    # Show differing bytes
                    diffs = []
                    for i in range(0, min(len(b1), len(b2)), 2):
                        if b1[i:i+2] != b2[i:i+2]:
                            diffs.append(i // 2)
                    if diffs:
                        print(f"               Octets diff: {diffs}")

    # Summary
    print(f"\n  {'─'*60}")
    pct = (match / total * 100) if total > 0 else 0
    color = Fore.GREEN if diff == 0 else (Fore.YELLOW if pct >= 90 else Fore.RED)
    print(f"  {color}RÉSULTAT: {match}/{total} blocs identiques ({pct:.1f}%){Style.RESET_ALL}")
    if diff > 0:
        print(f"  {Fore.RED}{diff} bloc(s) différent(s){Style.RESET_ALL}")
    if skip > 0:
        print(f"  {Fore.YELLOW}{skip} bloc(s) ignoré(s) (non lus){Style.RESET_ALL}")
    if diff == 0 and match > 0:
        print(f"\n  {Fore.GREEN}★ L'émulation est IDENTIQUE au badge physique !{Style.RESET_ALL}")
    elif diff == 0 and match == 0:
        print(f"\n  {Fore.RED}✗ AUCUNE DONNÉE COMPARABLE — l'HCE n'a pas répondu.{Style.RESET_ALL}")
    elif diff <= 2:
        print(f"\n  {Fore.YELLOW}⚠ Quasi identique — les différences sont probablement dans les trailers (clés masquées).{Style.RESET_ALL}")

    return {"total": total, "match": match, "diff": diff, "skip": skip}


# ─── Load dump file ─────────────────────────────────────────────────────────

def load_dump_file(filepath):
    """Load a .hex dump file into the same format as read_vigik_badge output."""
    lines = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            clean = line.replace(" ", "")
            if len(clean) == 32 and all(c in '0123456789ABCDEFabcdef' for c in clean):
                lines.append(clean.upper())

    if len(lines) < 64:
        print(f"{Fore.RED}Fichier invalide: {len(lines)} lignes de données (besoin 64){Style.RESET_ALL}")
        return None

    result = {"uid": "", "sectors": {}, "keys": {}}
    for i in range(64):
        sector = i // 4
        block = i % 4
        if str(sector) not in result["sectors"]:
            result["sectors"][str(sector)] = {}
        # Format as spaced hex
        hex_spaced = " ".join(lines[i][j:j+2] for j in range(0, 32, 2))
        result["sectors"][str(sector)][str(block)] = hex_spaced

    # UID from block 0
    b0 = lines[0]
    result["uid"] = " ".join(b0[j:j+2] for j in range(0, 8, 2))
    return result


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"""
{Style.BRIGHT}VIGIK Verify — Comparaison badge vs émulation HCE{Style.RESET_ALL}

Usage:
  python vigik_verify.py read         Lire un badge VIGIK (MIFARE Classic)
  python vigik_verify.py hce          Tester l'émulation HCE du téléphone
  python vigik_verify.py compare      Lire badge puis HCE et comparer
  python vigik_verify.py dump FILE    Comparer fichier .hex avec HCE
  python vigik_verify.py diag         Diagnostic complet (ATR, AIDs, APDU)
  python vigik_verify.py crypto1      Test si le téléphone émule MIFARE Classic
""")
        return

    mode = sys.argv[1].lower()

    if mode == "read":
        print(f"\n{Fore.CYAN}Posez le BADGE VIGIK sur le lecteur ACR122U...{Style.RESET_ALL}\n")
        _, conn = connect_reader()
        if conn:
            data = read_vigik_badge(conn)
            conn.disconnect()
            if data:
                fname = f"vigik_badge_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(fname, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"\n{Fore.GREEN}Sauvegardé: {fname}{Style.RESET_ALL}")

    elif mode == "hce":
        print(f"\n{Fore.CYAN}Posez le TÉLÉPHONE (HCE actif) sur le lecteur ACR122U...{Style.RESET_ALL}\n")
        reader, conn = connect_reader()
        if conn:
            data = test_hce_vigik(conn, reader)
            conn.disconnect()
            if data:
                fname = f"vigik_hce_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(fname, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"\n{Fore.GREEN}Sauvegardé: {fname}{Style.RESET_ALL}")

    elif mode == "compare":
        # Step 1: Read badge
        print(f"\n{Fore.CYAN}[ÉTAPE 1/2] Posez le BADGE VIGIK sur le lecteur...{Style.RESET_ALL}\n")
        _, conn1 = connect_reader("Posez le BADGE sur le lecteur...")
        if not conn1:
            return
        badge = read_vigik_badge(conn1)
        conn1.disconnect()
        if not badge:
            return

        # Step 2: Test HCE
        print(f"\n{Fore.CYAN}[ÉTAPE 2/2] Retirez le badge.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  ⚠ IMPORTANT: Vérifiez que:{Style.RESET_ALL}")
        print(f"    • L'écran du téléphone est ALLUMÉ et DÉVERROUILLÉ")
        print(f"    • VigikTool est OUVERT au premier plan")
        print(f"    • L'émulation HCE est ACTIVE")
        input(f"\n  {Fore.WHITE}Appuyez sur ENTRÉE quand le téléphone est prêt...{Style.RESET_ALL}")
        print()
        reader2, conn2 = connect_reader("Posez le TÉLÉPHONE sur le lecteur...")
        if not conn2:
            return
        hce = test_hce_vigik(conn2, reader2)
        conn2.disconnect()

        # Compare
        result = compare_badge_hce(badge, hce)

        # Save
        fname = f"vigik_compare_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, 'w') as f:
            json.dump({"badge": badge, "hce": hce, "comparison": result}, f, indent=2)
        print(f"\n{Fore.GREEN}Résultats: {fname}{Style.RESET_ALL}")

    elif mode == "dump":
        if len(sys.argv) < 3:
            print(f"{Fore.RED}Usage: python vigik_verify.py dump FICHIER.hex{Style.RESET_ALL}")
            return

        filepath = sys.argv[2]
        print(f"\n{Fore.CYAN}Chargement du dump: {filepath}{Style.RESET_ALL}")
        badge = load_dump_file(filepath)
        if not badge:
            return
        print(f"  UID: {badge['uid']}")
        print(f"  Secteurs: {len(badge['sectors'])}")

        print(f"\n{Fore.CYAN}Posez le TÉLÉPHONE (HCE actif) sur le lecteur...{Style.RESET_ALL}\n")
        reader, conn = connect_reader("Posez le TÉLÉPHONE sur le lecteur...")
        if not conn:
            return
        hce = test_hce_vigik(conn, reader)
        conn.disconnect()

        result = compare_badge_hce(badge, hce)

        fname = f"vigik_compare_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, 'w') as f:
            json.dump({"dump_file": filepath, "badge": badge, "hce": hce, "comparison": result}, f, indent=2)
        print(f"\n{Fore.GREEN}Résultats: {fname}{Style.RESET_ALL}")

    elif mode == "crypto1":
        print(f"\n{Style.BRIGHT}{'='*60}")
        print(f"  TEST DÉTECTION — Badge vs Téléphone")
        print(f"{'='*60}{Style.RESET_ALL}")

        # ── ÉTAPE 1 : Scanner le badge ──
        print(f"\n{Fore.CYAN}[ÉTAPE 1/2] Posez le BADGE VIGIK sur le lecteur...{Style.RESET_ALL}\n")
        _, conn1 = connect_reader("Posez le BADGE sur le lecteur...")
        if not conn1:
            return

        badge_atr = conn1.getATR()
        badge_atr_hex = " ".join(f"{b:02X}" for b in badge_atr)
        badge_uid_data, bsw1, bsw2 = send_apdu(conn1, [0xFF, 0xCA, 0x00, 0x00, 0x00], "GET UID badge")
        badge_uid = " ".join(f"{b:02X}" for b in badge_uid_data) if bsw1 == 0x90 else "?"

        badge_atr_str = "".join(f"{b:02X}" for b in badge_atr)
        badge_crypto1 = False
        badge_type = "Inconnu"
        if "000306030001" in badge_atr_str:
            badge_type = "MIFARE Classic 1K"
            badge_crypto1 = True
        elif "000306030002" in badge_atr_str:
            badge_type = "MIFARE Classic 4K"
            badge_crypto1 = True
        elif "000306030003" in badge_atr_str:
            badge_type = "DESFire"

        conn1.disconnect()

        print(f"\n  {Style.BRIGHT}Profil BADGE:{Style.RESET_ALL}")
        print(f"  UID:     {badge_uid}")
        print(f"  ATR:     {badge_atr_hex}")
        print(f"  Type:    {badge_type}")
        print(f"  Crypto1: {'Oui' if badge_crypto1 else 'Non'}")

        # ── ÉTAPE 2 : Scanner le téléphone ──
        print(f"\n{Fore.CYAN}[ÉTAPE 2/2] Retirez le badge, posez le TÉLÉPHONE...{Style.RESET_ALL}")
        input(f"  Appuyez sur ENTRÉE quand le téléphone est prêt...")
        print()
        _, conn2 = connect_reader("Posez le TÉLÉPHONE sur le lecteur...")
        if not conn2:
            return

        phone_atr = conn2.getATR()
        phone_atr_hex = " ".join(f"{b:02X}" for b in phone_atr)
        phone_uid_data, psw1, psw2 = send_apdu(conn2, [0xFF, 0xCA, 0x00, 0x00, 0x00], "GET UID phone")
        phone_uid = " ".join(f"{b:02X}" for b in phone_uid_data) if psw1 == 0x90 else "?"

        phone_atr_str = "".join(f"{b:02X}" for b in phone_atr)
        phone_crypto1 = False
        phone_type = "Inconnu"
        if "000306030001" in phone_atr_str:
            phone_type = "MIFARE Classic 1K"
            phone_crypto1 = True
        elif "000306030002" in phone_atr_str:
            phone_type = "MIFARE Classic 4K"
            phone_crypto1 = True
        elif len(phone_atr) <= 10:
            phone_type = "ISO-DEP (HCE)"

        conn2.disconnect()

        print(f"\n  {Style.BRIGHT}Profil TÉLÉPHONE:{Style.RESET_ALL}")
        print(f"  UID:     {phone_uid}")
        print(f"  ATR:     {phone_atr_hex}")
        print(f"  Type:    {phone_type}")
        print(f"  Crypto1: {'Oui' if phone_crypto1 else 'Non'}")

        # ── COMPARAISON ──
        print(f"\n{'='*60}")
        print(f"  COMPARAISON DÉTECTION")
        print(f"{'='*60}")

        checks = []
        # ATR
        atr_match = (badge_atr == phone_atr)
        checks.append(atr_match)
        status = f"{Fore.GREEN}✓ IDENTIQUE" if atr_match else f"{Fore.RED}✗ DIFFÉRENT"
        print(f"\n  ATR:     {status}{Style.RESET_ALL}")
        if not atr_match:
            print(f"           Badge: {badge_atr_hex}")
            print(f"           Phone: {phone_atr_hex}")

        # Type
        type_match = (badge_type == phone_type)
        checks.append(type_match)
        status = f"{Fore.GREEN}✓ IDENTIQUE" if type_match else f"{Fore.RED}✗ DIFFÉRENT"
        print(f"  Type:    {status}{Style.RESET_ALL}")
        if not type_match:
            print(f"           Badge: {badge_type}")
            print(f"           Phone: {phone_type}")

        # Crypto1
        crypto_match = (badge_crypto1 == phone_crypto1)
        checks.append(crypto_match)
        status = f"{Fore.GREEN}✓ IDENTIQUE" if crypto_match else f"{Fore.RED}✗ DIFFÉRENT"
        print(f"  Crypto1: {status}{Style.RESET_ALL}")
        if not crypto_match:
            print(f"           Badge: {'Oui' if badge_crypto1 else 'Non'}")
            print(f"           Phone: {'Oui' if phone_crypto1 else 'Non'}")

        # VERDICT
        all_match = all(checks)
        print(f"\n{'='*60}")
        if all_match:
            print(f"  {Fore.GREEN}{Style.BRIGHT}★ SUCCÈS — Détection 100% IDENTIQUE au badge !{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}→ Le téléphone est vu exactement comme le badge original{Style.RESET_ALL}")
        else:
            matched = sum(checks)
            print(f"  {Fore.RED}{Style.BRIGHT}✗ ÉCHEC — Détection DIFFÉRENTE ({matched}/{len(checks)} critères){Style.RESET_ALL}")
            print(f"  {Fore.RED}→ Le lecteur du portail verra une différence{Style.RESET_ALL}")
            if not crypto_match and badge_crypto1 and not phone_crypto1:
                print(f"  {Fore.YELLOW}→ Le badge utilise crypto1, le téléphone non (limitation HCE){Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}→ Solutions: sticker CUID, bague NFC, ou téléphone NXP rooté{Style.RESET_ALL}")
        print()

    elif mode == "diag":
        diag_mode()

    else:
        print(f"{Fore.RED}Mode inconnu: {mode}{Style.RESET_ALL}")
        main.__doc__ and print(main.__doc__)


# ─── DIAGNOSTIC MODE ────────────────────────────────────────────────────────

def diag_mode():
    """Full diagnostic: ATR, protocol, raw APDU traces, multiple connection methods."""
    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  DIAGNOSTIC COMPLET — ACR122U + Téléphone HCE")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    available = readers()
    if not available:
        print(f"{Fore.RED}ERREUR: Aucun lecteur PC/SC détecté.{Style.RESET_ALL}")
        print(f"  → Vérifiez que l'ACR122U est branché en USB.")
        return

    print(f"{Fore.CYAN}[1] LECTEURS PC/SC{Style.RESET_ALL}")
    for i, r in enumerate(available):
        print(f"  [{i}] {r}")

    reader = available[0]
    print(f"\n  → Utilisation de: {reader}")

    print(f"\n{Fore.CYAN}[2] ATTENTE CARTE / TÉLÉPHONE...{Style.RESET_ALL}")
    print(f"  Posez le TÉLÉPHONE (HCE actif) sur le lecteur.\n")

    conn = None
    protocol_used = None

    # Try T=1 first (ISO-DEP / HCE), then T=0, then any
    for attempt in range(60):
        for proto_name, proto in [("T=1", CardConnection.T1_protocol),
                                   ("T=0", CardConnection.T0_protocol)]:
            try:
                c = reader.createConnection()
                c.connect(proto)
                conn = c
                protocol_used = proto_name
                break
            except Exception as e:
                if attempt == 0:
                    print(f"  {proto_name}: {Fore.WHITE}{e}{Style.RESET_ALL}")
        if conn:
            break
        time.sleep(0.5)
        if attempt % 10 == 0 and attempt > 0:
            print(f"  Attente... ({attempt//2}s)")

    if not conn:
        print(f"{Fore.RED}Timeout — rien détecté.{Style.RESET_ALL}")
        return

    print(f"  {Fore.GREEN}✓ Connecté via {protocol_used}{Style.RESET_ALL}")

    # ATR
    print(f"\n{Fore.CYAN}[3] ATR (Answer To Reset){Style.RESET_ALL}")
    try:
        atr = conn.getATR()
        atr_hex = " ".join(f"{b:02X}" for b in atr)
        print(f"  ATR: {Fore.YELLOW}{atr_hex}{Style.RESET_ALL}")
        print(f"  Longueur: {len(atr)} octets")

        # Parse ATR for useful info
        if len(atr) >= 4:
            t0 = atr[1]
            print(f"  T0: {t0:02X} (historical bytes: {t0 & 0x0F})")

        # Check if this looks like a phone (ISO 14443-4)
        atr_str = atr_hex.replace(" ", "")
        if "8040" in atr_str or "80" in atr_str[2:4]:
            print(f"  {Fore.GREEN}→ Profil ISO 14443-4 (ISO-DEP) — typique d'un téléphone HCE{Style.RESET_ALL}")
        if len(atr) > 10:
            # ATS bytes
            print(f"  ATS/historiques: {' '.join(f'{b:02X}' for b in atr[3:])}")
    except Exception as e:
        print(f"  {Fore.RED}Erreur ATR: {e}{Style.RESET_ALL}")

    # UID via ACR122U pseudo-APDU
    print(f"\n{Fore.CYAN}[4] GET UID (FF CA 00 00 00){Style.RESET_ALL}")
    raw_send(conn, [0xFF, 0xCA, 0x00, 0x00, 0x00], "GET UID")

    # ATS via ACR122U
    print(f"\n{Fore.CYAN}[5] GET ATS (FF CA 01 00 00){Style.RESET_ALL}")
    raw_send(conn, [0xFF, 0xCA, 0x01, 0x00, 0x00], "GET ATS")

    # Test SELECT with all AIDs
    print(f"\n{Fore.CYAN}[6] SELECT AID — test tous les AIDs{Style.RESET_ALL}")
    aids_to_test = [
        ("VIGIK (F04456494749)",        "F04456494749"),
        ("NOR (F0014E4F52)",            "F0014E4F52"),
        ("Access (D276000085010100)",   "D276000085010100"),
        ("Calypso 1TIC.ICA",           "315449432E494341"),
        ("NDEF Type 4",                "D2760000850101"),
        ("Visa",                       "A0000000031010"),
        ("Mastercard",                 "A0000000041010"),
    ]

    for name, aid_hex in aids_to_test:
        aid_bytes = [int(aid_hex[i:i+2], 16) for i in range(0, len(aid_hex), 2)]
        select = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + aid_bytes + [0x00]
        print(f"\n  ── {name} ──")
        data, sw1, sw2 = raw_send(conn, select, f"SELECT {name}")
        if sw1 == 0x90:
            print(f"  {Fore.GREEN}★ AID ACCEPTÉ ! L'HCE répond.{Style.RESET_ALL}")
            # Try reading blocks
            print(f"\n{Fore.CYAN}[7] TEST LECTURE via cet AID{Style.RESET_ALL}")
            # GET DATA (UID)
            raw_send(conn, [0x00, 0xCA, 0x00, 0x00, 0x00], "GET DATA P1=00 P2=00")
            # READ RECORD sector 0 block 0
            raw_send(conn, [0x00, 0xB2, 0x00, 0x00, 0x10], "READ RECORD S0 B0")
            # READ RECORD sector 0 block 1
            raw_send(conn, [0x00, 0xB2, 0x00, 0x01, 0x10], "READ RECORD S0 B1")
            # READ BINARY
            raw_send(conn, [0x00, 0xB0, 0x00, 0x00, 0x10], "READ BINARY offset=0")
            raw_send(conn, [0x00, 0xB0, 0x00, 0x10, 0x10], "READ BINARY offset=16")
            break
        elif sw1 == 0x69 and sw2 == 0x85:
            print(f"  {Fore.YELLOW}⚠ AID reconnu mais SERVICE INACTIF (6985){Style.RESET_ALL}")
            print(f"  → Le service HCE est enregistré mais l'émulation n'est pas activée")
            print(f"  → Ouvrez VigikTool, scannez un badge, appuyez 'Émuler'")
        elif sw1 == 0x6A and sw2 == 0x82:
            print(f"  {Fore.WHITE}  AID non trouvé (6A82) — service pas enregistré pour cet AID{Style.RESET_ALL}")
        # Check if connection is still alive
        try:
            conn.getATR()
        except Exception:
            print(f"  {Fore.RED}⚠ Connexion perdue après SELECT — téléphone retiré ?{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}Reconnexion...{Style.RESET_ALL}")
            try:
                conn = reader.createConnection()
                conn.connect(CardConnection.T1_protocol)
                print(f"  {Fore.GREEN}✓ Reconnecté{Style.RESET_ALL}")
            except Exception as e2:
                print(f"  {Fore.RED}Impossible de reconnecter: {e2}{Style.RESET_ALL}")
                print(f"  → Le téléphone a peut-être quitté le champ NFC.")
                break

    # Raw APDU test
    print(f"\n{Fore.CYAN}[8] TEST APDU BRUTS{Style.RESET_ALL}")
    # Try a simple APDU that any ISO 14443-4 card should handle
    raw_send(conn, [0x00, 0xA4, 0x04, 0x00, 0x00], "SELECT sans AID (vide)")
    raw_send(conn, [0x00, 0xB0, 0x00, 0x00, 0x10], "READ BINARY brut")

    try:
        conn.disconnect()
    except:
        pass

    print(f"\n{Style.BRIGHT}{'='*60}")
    print(f"  FIN DU DIAGNOSTIC")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}Envoyez ce log complet pour analyse.{Style.RESET_ALL}\n")


def raw_send(conn, apdu, label=""):
    """Send APDU with full hex trace, return (data, sw1, sw2)."""
    apdu_hex = " ".join(f"{b:02X}" for b in apdu)
    print(f"    >>> {Fore.CYAN}{apdu_hex}{Style.RESET_ALL}")
    try:
        data, sw1, sw2 = conn.transmit(apdu)
        sw_hex = f"{sw1:02X} {sw2:02X}"
        data_hex = " ".join(f"{b:02X}" for b in data) if data else "(vide)"
        color = Fore.GREEN if sw1 == 0x90 else (Fore.YELLOW if sw1 == 0x69 else Fore.RED)
        print(f"    <<< {data_hex} {color}[{sw_hex}]{Style.RESET_ALL}  ({label})")
        if data and sw1 == 0x90:
            # ASCII interpretation
            ascii_str = "".join(chr(b) if 32 <= b < 127 else '.' for b in data)
            print(f"    ASCII: {ascii_str}")
        return data, sw1, sw2
    except Exception as e:
        print(f"    {Fore.RED}!!! EXCEPTION: {e}{Style.RESET_ALL}")
        return [], 0x6F, 0x00


if __name__ == "__main__":
    main()
