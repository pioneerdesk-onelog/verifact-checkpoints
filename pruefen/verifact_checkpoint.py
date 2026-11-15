"""Unabhängige Gegenprobe für signierte Verifact-Checkpoints (ML-DSA-65 + Ed25519, Hybrid).

Warum hier: Verifact signiert in Go mit cloudflare/circl. Eine zweite, unabhängige Implementierung
(dilithium-py, dieselbe Bibliothek wie der SmartScan-Ledger) zeigt, dass die Signaturen nach FIPS 204
und nicht nur „circl-kompatibel“ sind. Format (festgelegt 15.11.2026): signiert werden die rohen
UTF-8-Bytes eines festen Textblocks, kein JSON. Geschrieben von der SmartScan-Session (dsm),
übernommen mit Erweiterung `repo` (Roots aus ids/ nachrechnen).

Aufrufe:
  uv run python scripts/gegenprobe/verifact_checkpoint.py selbsttest
  uv run python scripts/gegenprobe/verifact_checkpoint.py vektor <seed_hex> <nachricht_datei> <pk_hex> <sig_b64>
  uv run python scripts/gegenprobe/verifact_checkpoint.py pruefe <checkpoints.jsonl> <mldsa65.pk> [<ed25519.pk>]
  python pruefen/verifact_checkpoint.py repo .      # alles: Signaturen + jeden Root aus ids/ nachrechnen
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

CTX = b"verifact|checkpoint|v1"
FELDER = ("root", "mandant", "claims", "events", "vocab", "sources", "zeit")
_ZEIT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def textblock(d: dict) -> bytes:
    """Baut den signierten Textblock aus den Feldern neu auf; prüft dabei das Format streng."""
    if not re.fullmatch(r"[0-9a-f]{64}", str(d["root"])):
        raise ValueError("root ist kein 64-stelliges Hex in Kleinbuchstaben")
    for k in ("claims", "events", "vocab", "sources"):
        if not isinstance(d[k], int) or d[k] < 0:
            raise ValueError(f"{k} ist keine nicht-negative Ganzzahl")
    if not _ZEIT.match(str(d["zeit"])):
        raise ValueError("zeit ist nicht RFC 3339 UTC mit Sekunden und Z")
    if any(c.isspace() for c in str(d["mandant"])):
        raise ValueError("mandant enthält Leerraum")
    zeilen = ["verifact-checkpoint-v1"] + [f"{k}={d[k]}" for k in FELDER]
    return ("\n".join(zeilen) + "\n").encode("utf-8")


def pruefe_mldsa(pk: bytes, msg: bytes, sig: bytes) -> bool:
    return ML_DSA_65.verify(pk, msg, sig, ctx=CTX)


def pruefe_ed25519(pk_raw: bytes, msg: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def selbsttest() -> int:
    """Stufe 1–3 gegen sich selbst (ersetzt nicht den Kreuztest mit circl-Testvektoren)."""
    seed = bytes(range(32))  # nur Test, nie produktiv
    pk, sk = ML_DSA_65.key_derive(seed)
    pk2, _ = ML_DSA_65.key_derive(seed)
    d = {"root": "ab" * 32, "mandant": "pioneerdesk.pro", "claims": 1, "events": 2, "vocab": 3,
         "sources": 4, "zeit": "2026-11-17T06:00:00Z"}
    msg = textblock(d)
    s1 = ML_DSA_65.sign(sk, msg, ctx=CTX, deterministic=True)
    s2 = ML_DSA_65.sign(sk, msg, ctx=CTX, deterministic=True)
    checks = {
        "Stufe 1: gleicher Seed → gleicher Public Key": pk == pk2,
        "Stufe 2: deterministisch → bitgleiche Signatur": s1 == s2,
        "Signatur gültig": pruefe_mldsa(pk, msg, s1),
        "Stufe 3a: verfälschte Nachricht abgelehnt": not pruefe_mldsa(pk, msg.replace(b"claims=1", b"claims=2"), s1),
        "Stufe 3b: anderer ctx abgelehnt": not ML_DSA_65.verify(pk, msg, s1, ctx=b"smartscan|ledger|v1"),
        "Textblock endet mit \\n, ohne Leerzeichen": msg.endswith(b"\n") and b" " not in msg,
    }
    for name, ok in checks.items():
        print(("✓ " if ok else "✗ ") + name)
    return 0 if all(checks.values()) else 1


def vektor(seed_hex: str, nachricht: str, pk_hex: str, sig_b64: str) -> int:
    """Kreuztest mit einem circl-Testvektor: Public Key und Signatur müssen bitgleich sein."""
    pk, sk = ML_DSA_65.key_derive(bytes.fromhex(seed_hex))
    msg = Path(nachricht).read_bytes()
    sig_ref = base64.b64decode(sig_b64)
    sig = ML_DSA_65.sign(sk, msg, ctx=CTX, deterministic=True)
    checks = {
        "Stufe 1: Public Key bitgleich mit circl": pk.hex() == pk_hex.lower(),
        "Stufe 2: Signatur bitgleich mit circl": sig == sig_ref,
        "circl-Signatur hier gültig": pruefe_mldsa(bytes.fromhex(pk_hex), msg, sig_ref),
        "Stufe 3: andere ctx abgelehnt": not ML_DSA_65.verify(pk, msg, sig_ref, ctx=b""),
    }
    for name, ok in checks.items():
        print(("✓ " if ok else "✗ ") + name)
    return 0 if all(checks.values()) else 1


def pruefe(jsonl: str, mldsa_pk_datei: str, ed_pk_datei: str | None = None) -> int:
    """Prüft jede Zeile von checkpoints.jsonl: Textblock neu bauen, PK-Hash, beide Signaturen."""
    pk = Path(mldsa_pk_datei).read_bytes()
    pk_hash = hashlib.sha256(pk).hexdigest()
    ed_pk = Path(ed_pk_datei).read_bytes() if ed_pk_datei else None
    fehler = 0
    for n, zeile in enumerate(Path(jsonl).read_text(encoding="utf-8").splitlines(), 1):
        if not zeile.strip():
            continue
        d = json.loads(zeile)
        try:
            msg = textblock(d)
        except (KeyError, ValueError) as e:
            print(f"✗ Zeile {n}: Format – {e}")
            fehler += 1
            continue
        ok_pk = d.get("mldsa65_pk_sha256") == pk_hash
        ok_ml = pruefe_mldsa(pk, msg, base64.b64decode(d["sig_mldsa65"]))
        ok_ed = pruefe_ed25519(ed_pk, msg, base64.b64decode(d["sig_ed25519"])) if ed_pk else None
        alles = ok_pk and ok_ml and ok_ed is not False
        fehler += not alles
        print(f"{'✓' if alles else '✗'} Zeile {n} {d['zeit']} root={d['root'][:12]}… "
              f"pk={'ok' if ok_pk else 'FALSCH'} ml-dsa={'ok' if ok_ml else 'FALSCH'} "
              f"ed25519={'nicht geprüft' if ok_ed is None else ('ok' if ok_ed else 'FALSCH')}")
    return 1 if fehler else 0


def repo(ordner: str) -> int:
    """Prüft das ganze Repo: Signaturen jeder Zeile UND den Root jeder Zeile aus ids/.

    ids/<zeit>.gz enthält die Änderungen seit dem vorigen Checkpoint ("+c:<id>" neu,
    "-c:<id>" entfernt). Der Reihe nach angewandt ergibt sich die ID-Menge; ihr Root ist
    SHA-256 über die sortierten Zeilen, jede gefolgt von einem Null-Byte.
    """
    import gzip

    o = Path(ordner)
    rc = pruefe(str(o / "checkpoints.jsonl"), str(o / "keys" / "mldsa65.pk"), str(o / "keys" / "ed25519.pk"))
    menge: set[str] = set()
    fehler = 0
    for n, zeile in enumerate((o / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        if not zeile.strip():
            continue
        d = json.loads(zeile)
        for z in gzip.decompress((o / d["ids"]).read_bytes()).decode("utf-8").splitlines():
            if not z:
                continue
            k = z[1:]
            if z[0] == "+" and k not in menge:
                menge.add(k)
            elif z[0] == "-" and k in menge:
                menge.remove(k)
            else:
                print(f"✗ Zeile {n}: widersprüchliche Änderung {z[:20]}…")
                fehler += 1
        h = hashlib.sha256()
        for k in sorted(menge):
            h.update(k.encode("utf-8") + b"\0")
        ok = h.hexdigest() == d["root"]
        fehler += not ok
        print(f"{'✓' if ok else '✗'} Zeile {n} {d['zeit']}: Root aus {len(menge)} IDs {'nachgerechnet' if ok else 'STIMMT NICHT'}")
    return 1 if (rc or fehler) else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["selbsttest"]:
        sys.exit(selbsttest())
    if a[:1] == ["vektor"] and len(a) == 5:
        sys.exit(vektor(*a[1:]))
    if a[:1] == ["pruefe"] and len(a) in (3, 4):
        sys.exit(pruefe(*a[1:]))
    if a[:1] == ["repo"] and len(a) == 2:
        sys.exit(repo(a[1]))
    print(__doc__)
    sys.exit(2)
