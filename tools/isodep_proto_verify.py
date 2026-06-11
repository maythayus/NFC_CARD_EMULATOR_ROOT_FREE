#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

try:
    from smartcard.System import readers
    from smartcard.Exceptions import CardConnectionException, NoCardException
except ImportError:
    print("ERREUR: pyscard non installé.\n  pip install pyscard")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERREUR: pycryptodome non installé.\n  pip install pycryptodome")
    sys.exit(1)


AID_HEX = "F04E4643454D5531"  # NFCEMU1
KEY_HEX_DEFAULT = "00112233445566778899AABBCCDDEEFF"


def hx(s: str) -> bytes:
    s = "".join(s.split()).replace(":", "").replace("-", "")
    if len(s) % 2:
        raise ValueError("hex length must be even")
    return bytes.fromhex(s)


def b2h(b: bytes) -> str:
    return b.hex().upper()


def transmit(conn, apdu: bytes):
    apdu_list = list(apdu)
    data, sw1, sw2 = conn.transmit(apdu_list)
    resp = bytes(data) + bytes([sw1, sw2])
    return resp


def connect_with_retries(reader, retries: int = 5):
    last_err = None
    for _ in range(retries):
        try:
            conn = reader.createConnection()
            conn.connect()
            return conn
        except (NoCardException, CardConnectionException) as e:
            last_err = e
    raise last_err


def transmit_with_retries(reader, conn, apdu: bytes, retries: int = 5):
    last_err = None
    for _ in range(retries):
        try:
            return transmit(conn, apdu)
        except (NoCardException, CardConnectionException) as e:
            last_err = e
            try:
                conn = connect_with_retries(reader, retries=2)
            except Exception:
                pass
    raise last_err


def apdu_select_aid(aid_hex: str) -> bytes:
    aid = hx(aid_hex)
    if len(aid) > 255:
        raise ValueError("AID too long")
    return bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid


def apdu_get_challenge() -> bytes:
    # CLA=0x80 INS=0x84 P1=0x00 P2=0x00
    return bytes([0x80, 0x84, 0x00, 0x00, 0x00])


def apdu_auth(iv: bytes, enc_and_tag: bytes) -> bytes:
    data = iv + enc_and_tag
    if len(data) > 255:
        raise ValueError("AUTH data too long")
    return bytes([0x80, 0x82, 0x00, 0x00, len(data)]) + data


def apdu_read(sector: int, block: int) -> bytes:
    # CLA=0x80 INS=0xB2 P1=sector P2=block
    # Le byte final est optionnel; ici on met Le=0x10 pour une lecture 16 bytes.
    return bytes([0x80, 0xB2, sector & 0xFF, block & 0xFF, 0x10])


def aes_gcm_encrypt(key: bytes, iv12: bytes, plain: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv12, mac_len=16)
    ct, tag = cipher.encrypt_and_digest(plain)
    return ct + tag


def main():
    key_hex = os.environ.get("NFCEMU_PROTO_KEY_HEX", KEY_HEX_DEFAULT)
    key = hx(key_hex)
    if len(key) not in (16, 24, 32):
        print("ERREUR: clé AES invalide (doit être 16/24/32 bytes).")
        return 2

    rs = readers()
    if not rs:
        print("ERREUR: aucun lecteur PC/SC détecté")
        return 2

    print("Lecteurs:")
    for i, r in enumerate(rs):
        print(f"  [{i}] {r}")

    r = rs[0]
    print(f"\nUtilisation du lecteur: {r}")

    try:
        conn = connect_with_retries(r, retries=10)
    except (NoCardException, CardConnectionException) as e:
        print(f"ERREUR connexion carte/téléphone: {e}")
        print("Astuce: active NFC, ouvre l'app, déverrouille, puis colle le téléphone sur l'ACR122U.")
        return 2

    # 1) SELECT
    sel = apdu_select_aid(AID_HEX)
    print(f"=> SELECT {AID_HEX}: {b2h(sel)}")
    try:
        resp = transmit_with_retries(r, conn, sel, retries=5)
    except (NoCardException, CardConnectionException) as e:
        print(f"ERREUR SELECT: {e}")
        return 1
    print(f"<= {b2h(resp)}")
    if resp[-2:] != b"\x90\x00":
        print("ECHEC: SELECT")
        return 1

    # 2) GET_CHALLENGE
    gc = apdu_get_challenge()
    print(f"\n=> GET_CHALLENGE: {b2h(gc)}")
    try:
        resp = transmit_with_retries(r, conn, gc, retries=5)
    except (NoCardException, CardConnectionException) as e:
        print(f"ERREUR GET_CHALLENGE: {e}")
        return 1
    print(f"<= {b2h(resp)}")
    if resp[-2:] != b"\x90\x00" or len(resp) < 2 + 16:
        print("ECHEC: GET_CHALLENGE")
        return 1
    challenge = resp[:-2]
    if len(challenge) != 16:
        print(f"ECHEC: challenge size {len(challenge)}")
        return 1

    # 3) AUTH (AES-GCM)
    # Plain attendu côté téléphone: 0x01 || challenge(16)
    plain = bytes([0x01]) + challenge
    iv = os.urandom(12)
    enc_and_tag = aes_gcm_encrypt(key, iv, plain)
    au = apdu_auth(iv, enc_and_tag)

    print(f"\n=> AUTH: iv={b2h(iv)} plain={b2h(plain)}")
    print(f"=> AUTH APDU: {b2h(au)}")
    try:
        resp = transmit_with_retries(r, conn, au, retries=5)
    except (NoCardException, CardConnectionException) as e:
        print(f"ERREUR AUTH: {e}")
        return 1
    print(f"<= {b2h(resp)}")
    if resp[-2:] != b"\x90\x00":
        print("ECHEC: AUTH")
        return 1

    # 4) READ test
    sector = 0
    block = 0
    rd = apdu_read(sector, block)
    print(f"\n=> READ sector={sector} block={block}: {b2h(rd)}")
    try:
        resp = transmit_with_retries(r, conn, rd, retries=5)
    except (NoCardException, CardConnectionException) as e:
        print(f"ERREUR READ: {e}")
        return 1
    print(f"<= {b2h(resp)}")
    if resp[-2:] != b"\x90\x00":
        print("ECHEC: READ")
        return 1
    data = resp[:-2]
    print(f"DATA(16) = {b2h(data)}")

    print("\nOK: protocole ISO-DEP propriétaire AES-GCM fonctionnel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
