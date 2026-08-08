# CTF Toolkit — Crypto / Forensics / OT

Scripts + reference material to push to a repo and pull up mid-competition.
Pairs with `ctf-helpbook.md` (the mindset/theory doc) — this repo is the
"actually run this" companion.

## Contents

| File | Covers |
|---|---|
| `rsa_toolkit.py` | Wiener's attack, common modulus attack, Hastad broadcast (CRT), Fermat factoring, batch-GCD across many moduli, direct decrypt from p/q |
| `xor_toolkit.py` | Single-byte XOR brute force, repeating-key keysize detection + crack, crib dragging for multi-time-pad scenarios |
| `pcap_toolkit.py` | DNS exfiltration extraction, ICMP covert channel extraction, USB HID keystroke reconstruction, file-signature identification, naive TCP reassembly |
| `modbus_toolkit.py` | Pure-Python Modbus TCP frame parser (no scapy.contrib dependency needed), register/address/coil-to-ASCII conversion |
| `memory_forensics.md` | Volatility3 command reference and full attack-chain investigation workflow (LOLBins → C2 → persistence → privilege escalation → BOF/UAC-bypass → process spoofing) |

## Dependencies to request/verify before the round

```bash
pip install pycryptodome gmpy2 sympy scapy --break-system-packages
```

Binaries: `vol3` (Volatility3), `wireshark`/`tshark`, `upx`, `exiftool`,
`binwalk`, DIE (Detect It Easy / `diec`), `openssl`, `sage`. If UPX/DIE aren't
preinstalled, ask organizers in advance — per your rules, technical setup
requests go through them, not through AI during the round.

## How to actually use this mid-competition

1. **Identify the category from the file/data you're given** (see the trigger
   table in `ctf-helpbook.md`).
2. **Pick the matching script.** Don't read the whole file — jump to the
   function name that matches your symptom (e.g. "e is huge" → `wiener_attack`).
3. **Import and run from a Python REPL**, don't try to write a fresh script
   from scratch under time pressure:
   ```python
   from rsa_toolkit import wiener_attack, decrypt_with_pq
   d = wiener_attack(e, n)
   ```
4. If a script's output is ambiguous (e.g. XOR keysize guess gives multiple
   candidates), try each candidate's decode preview rather than assuming the
   top-scored one is right — these heuristics are guides, not oracles.

## What this repo intentionally does NOT include

- Steganography tooling (excluded per your request — no steg challenges expected)
- A generic "exploit anything" framework — these are pattern-matched to
  documented CTF attack classes, not general-purpose attack tools
- Anything that assumes network access to the target during the round —
  everything here operates on files/pcaps/dumps you already have locally
