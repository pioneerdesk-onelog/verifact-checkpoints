# Verifact-Checkpoints

Öffentliche, post-quantum signierte Stände des [Verifact](https://verifact.network)-Ledgers.

**Was das ist:** Einmal am Tag wird über alle Einträge des öffentlichen Verifact-Rechtskorpus
(Gesetze, Urteile, Verwaltungsvorschriften; Mandant `pioneerdesk.pro`) ein SHA-256-Root gebildet.
Dieser Root wird mit **ML-DSA-65** (FIPS 204, post-quantum) und zusätzlich mit **Ed25519** signiert,
hier veröffentlicht und per [OpenTimestamps](https://opentimestamps.org) in der Bitcoin-Blockchain verankert.

**Was das bedeutet:** Wird ein schon veröffentlichter Stand später verändert (ein Eintrag gelöscht,
verändert oder heimlich nachgeschoben), lässt sich das von außen nachweisen. Dieser Schutz gilt auch
dann noch, wenn Ed25519 eines Tages von Quantencomputern gebrochen wird.

**Was das nicht ist:**
- Die einzelnen Einträge im Ledger sind weiterhin mit Ed25519 signiert. Post-quantum signiert ist
  der **Stand** (der Root), nicht jeder Eintrag einzeln.
- Geschützt ist nur, was bereits als Checkpoint veröffentlicht ist. Der erste Checkpoint ist vom 15.11.2026.
- Kundendaten sind nicht enthalten, nur die IDs des öffentlichen Rechtskorpus. Einträge (`c:`),
  Prüfereignisse (`e:`) und Vokabular (`v:`) sind SHA-256-Hashes. Quellen (`s:`) sind
  dagegen lesbar: Adressen der amtlichen Fundstellen (gesetze-im-internet.de, rechtsprechung-im-internet.de,
  eur-lex.europa.eu, gesetze-bayern.de, verwaltungsvorschriften-im-internet.de, physics.nist.gov) und
  Literaturkürzel.

## Inhalt

| Pfad | Inhalt |
|---|---|
| `checkpoints.jsonl` | eine Zeile je Checkpoint: Root, Zähler, Zeit, beide Signaturen, Verweis auf `ids/` |
| `ids/<zeit>.gz` | Änderungen der ID-Menge seit dem vorigen Checkpoint (`+c:<id>` neu, `-c:<id>` entfernt); die erste Datei enthält den ganzen Bestand |
| `ots/<zeit>.jsonl` + `.ots` | die Checkpoint-Zeile und ihr OpenTimestamps-Beleg |
| `keys/mldsa65.pk`, `keys/ed25519.pk` | öffentliche Schlüssel, rohe Bytes (1952 bzw. 32 Byte) |
| `pruefen/verifact_checkpoint.py` | unabhängige Prüfung in Python (dilithium-py, cryptography) |
| `testvektor/` | Testvektor mit **Test-Schlüsseln** (Seeds 00..1f / 20..3f) für eigene Implementierungen |

Fingerabdruck des ML-DSA-65-Schlüssels (SHA-256 der rohen Bytes) steht in jeder Zeile als
`mldsa65_pk_sha256` und hier: siehe unten „Schlüssel“.

## Selbst prüfen

```bash
git clone https://github.com/pioneerdesk-onelog/verifact-checkpoints && cd verifact-checkpoints
python3 -m venv .venv && . .venv/bin/activate && pip install -r pruefen/requirements.txt
python pruefen/verifact_checkpoint.py repo .
```

Das Skript prüft für jede Zeile beide Signaturen und rechnet den Root aus `ids/` selbst nach.

Den Zeitstempel prüft man mit dem OpenTimestamps-Client (`pip install opentimestamps-client`,
`ots verify ots/<zeit>.jsonl.ots`, braucht einen Bitcoin-Knoten) oder auf https://opentimestamps.org.
Er belegt, dass die Checkpoint-Zeile spätestens zu diesem Zeitpunkt existiert hat. Die Bestätigung
in Bitcoin dauert nach dem Stempeln einige Stunden; bis dahin gilt der Beleg als ausstehend.

## Format

Signiert werden die rohen UTF-8-Bytes dieses Textblocks (kein JSON). Jede Zeile endet mit `\n`,
es gibt keine Leerzeichen:

```
verifact-checkpoint-v1
root=<64 hex, klein>
mandant=<mandant>
claims=<int>
events=<int>
vocab=<int>
sources=<int>
zeit=<RFC 3339 UTC, Sekunden, Z>
```

- ML-DSA-65, reine Variante (kein HashML-DSA), Kontext `verifact|checkpoint|v1`, deterministisch.
- Ed25519 (RFC 8032, ohne Kontext) über dieselben Bytes.
- Root: SHA-256 über die **sortierten** Zeilen der ID-Menge (`c:` Einträge, `e:` Prüfereignisse,
  `v:` Vokabular, `s:` Quellen), jede gefolgt von einem Null-Byte.

Zwei unabhängige Implementierungen erzeugen dieselben Bytes: Go (cloudflare/circl) beim Signieren und
Python (dilithium-py) beim Prüfen. Mit dem Testvektor sind Public Key und Signatur bitgleich.

## Schlüssel

| Schlüssel | Wert |
|---|---|
| ML-DSA-65, SHA-256 der rohen Bytes von `keys/mldsa65.pk` | `8b9498635b865df32db385d2882d6dc3aefae70553777bca2a2765981f3e1aba` |
| Ed25519 (`keys/ed25519.pk`, hex) | `db08a28694e306e71e9909883de124401511715c9b0142d33a69e46796c1d964` |

Erster Checkpoint: 15.11.2026 18:59:14 UTC, Root `29f2bb48c59f9b0aa5e566837ebd3dcae39b46c6409d571661648fad40b8cc3f`,
859.434 Einträge, 2.062.895 IDs insgesamt. Danach läuft täglich um 05:30 UTC ein neuer Checkpoint.

---

Betrieben von der Pioneerdesk GmbH. Fragen: security@verifact.network
