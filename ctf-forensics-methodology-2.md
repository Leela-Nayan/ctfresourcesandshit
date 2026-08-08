# CTF Forensics Methodology: Memory, Disk & Network

A step-by-step playbook for approaching digital forensics challenges in CTFs.

---

## 0. General Approach (do this first, regardless of category)

1. **Identify the artifact type**
   - `file <filename>` — confirms it's actually a memory dump / disk image / pcap and not mislabeled
   - `md5sum` / `sha256sum` — verify against any hash provided in the challenge
2. **Baseline triage on the raw file**
   - `strings -a <file> | grep -iE "flag|ctf\{|htb\{"` — flags are sometimes just sitting in plaintext
   - `binwalk <file>` — check for embedded/appended files (zip, images, etc.)
   - `exiftool <file>` — metadata often contains hints or credentials
3. **Know the flag format** the CTF specifies (e.g. `flag{...}`, `CTF{...}`) and grep for that regex throughout every stage.
4. **Take notes as you go** — commands run, hashes, timestamps, findings. You'll need this for the write-up and it saves you from repeating work.

---

## 1. Memory Forensics (RAM images)

**Tools:** Volatility 3 (or 2), Rekall, strings, bulk_extractor

**Process:**
1. **Identify the profile/OS**
   - Vol3: `vol3 -f mem.img windows.info`
   - Vol2: `vol.py -f mem.img imageinfo`
2. **Enumerate processes**
   - `pslist` / `pstree` (declared list) vs `psscan` (scans pool tags — reveals hidden/unlinked processes)
   - Compare the two outputs; a mismatch often flags process hollowing/hiding
3. **Network activity**
   - `netscan` / `connscan` — look for suspicious external IPs or unusual ports
4. **Command-line & console history**
   - `cmdline`, `consoles`, `cmdscan`
5. **Registry (Windows)**
   - `hivelist` then `printkey` on relevant keys (run keys, USB history, etc.)
6. **Code injection / malware indicators**
   - `malfind` — flags suspicious memory regions (RWX pages, no backing file)
   - `dlllist` / `ldrmodules` for unlinked DLLs
7. **Dump and inspect**
   - `procdump` / `memdump` on suspicious PIDs, then treat the dump like a normal binary (`strings`, disassembler)
   - `filescan` to find file objects in memory, `dumpfiles` to extract them
8. **Application-specific data**
   - `notepad`, `clipboard`, `iehistory`, or browser plugins — flags are often planted in an open app
9. **Final sweep**
   - `strings mem.img | grep -i flag` across the whole image after targeted analysis

---

## 2. Disk Forensics (disk/partition images)

**Tools:** Autopsy, The Sleuth Kit (TSK), FTK Imager, binwalk, foremost/scalpel, photorec, exiftool, testdisk

**Process:**
1. **Inspect partition layout**
   - `fdisk -l image.dd` or `mmls image.dd`
2. **Mount read-only or use TSK directly** (avoid mutating evidence)
   - `mount -o ro,loop,offset=<bytes> image.dd /mnt/evidence`
3. **Build a filesystem timeline**
   - `fls -r -m / image.dd > bodyfile` then `mactime -b bodyfile > timeline.csv`
   - Look for files created/modified around a suspicious timestamp
4. **Recover deleted files**
   - `fls -rd image.dd` lists deleted entries
   - `icat` to pull deleted-but-recoverable file content by inode
5. **Carve unallocated space / slack**
   - `foremost -i image.dd -o out/` or `scalpel` / `photorec` for file-signature carving
6. **Keyword search everything**
   - `grep -r -a "flag{" /mnt/evidence` and against the raw image itself (files can be renamed/hidden)
7. **Check for hidden data channels**
   - NTFS Alternate Data Streams: `icat image.dd <inode>:<stream_name>`
   - Hidden partitions, unusual gaps in `mmls` output
8. **Metadata & artifacts**
   - `exiftool` on recovered images/docs
   - Windows artifacts: Recycle Bin, `$MFT`, prefetch, registry hives, thumbs.db
   - Browser history/downloads if relevant to the scenario
9. **Steganography check** on any recovered images/audio (see cross-cutting tools below)

---

## 3. Network Forensics (PCAP)

**Tools:** Wireshark, tshark, NetworkMiner, Zeek/Bro, tcpflow, CyberChef

**Process:**
1. **Get the big picture**
   - Wireshark: Statistics → Protocol Hierarchy (what protocols are present)
   - Statistics → Conversations (who's talking to whom, volume)
2. **Follow suspicious streams**
   - Right-click a packet → Follow → TCP/UDP/HTTP Stream — reconstructs full sessions, often reveals plaintext creds or commands
3. **Extract transferred files**
   - File → Export Objects → HTTP/SMB/FTP-DATA/etc. — pulls out any files sent over the wire
4. **DNS analysis**
   - Filter: `dns` — look for oddly long/frequent subdomains (possible DNS tunneling/exfil)
5. **Credentials & cleartext protocols**
   - Filters: `http.request`, `ftp`, `telnet` — these protocols carry plaintext auth
6. **Spot anomalies**
   - Unusual ports, protocols mismatched to port (e.g. HTTP traffic on port 4444), beaconing intervals
7. **Decode payloads**
   - Copy hex/base64 blobs into CyberChef and try common recipes (Base64, Hex, XOR, Gzip)
8. **Command-line for large captures**
   - `tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri`
   - `tcpflow -r file.pcap` to dump all reconstructed streams to files for grepping

---

## 4. Log Analysis (Windows Event Logs, Linux logs, USB artifacts, web/app logs)

**Tools:** Event Viewer, python-evtx / evtxdump, Chainsaw, Zircolite, Timeline Explorer, grep/awk/sed, jq (JSON logs), journalctl

**Process:**
1. **Identify log format** — `.evtx` (Windows Event Log), syslog/plaintext, JSON, CSV, or a database (e.g. `.db`, SQLite). Use `file` and check the extension/header.
2. **Convert to something greppable if needed**
   - `.evtx` → `python3 -m Evtx.Evtx --xml-only file.evtx > out.xml` or use `evtxdump`
   - Or skip conversion and hunt directly with **Chainsaw** or **Zircolite** (Sigma-rule based — fast for known attack patterns)
3. **Build a timeline** — sort all events by timestamp; note the log's timezone (evtx is usually UTC) so it lines up with other artifacts (disk/memory/network).
4. **Filter to the events that matter for the scenario.** Common high-value Windows Event IDs:
   - `4624` / `4625` — successful / failed logon
   - `4688` — process creation (command line, if auditing enabled)
   - `4104` — PowerShell script block execution
   - `7045` — new service installed
   - `1102` — audit log cleared (a red flag itself)
   - Linux equivalents: `/var/log/auth.log` (SSH/sudo activity), `/var/log/syslog`, `journalctl -xe`, failed `sudo` attempts
5. **USB device history specifically:**
   - **Windows registry:** `SYSTEM\CurrentControlSet\Enum\USBSTOR` and `...\Enum\USB` — device IDs, first/last connect times
   - **SetupAPI log:** `C:\Windows\inf\setupapi.dev.log` — timestamped install events per device
   - **Amcache.hve / ShimCache** — corroborates when a device was seen or executed from
   - **Linux:** `dmesg | grep -i usb`, `journalctl -k | grep -i usb`, or `/var/log/syslog` entries for `usb-storage`/`sd` device attach events
6. **Correlate across logs** — e.g. USB insertion timestamp → file copy event → process execution shortly after, often the intended "story" of the challenge.
7. **Web/application logs** (if in scope) — `access.log`/`error.log`: look for unusual user agents, suspicious request paths, SQLi/LFI patterns, base64 or encoded strings in query parameters.
8. **Final sweep** — grep the flag pattern across every converted/raw log file, same as other categories.

---

## Cross-Cutting Tools & Tricks

| Purpose | Tools |
|---|---|
| File identification | `file`, `binwalk`, `xxd`/hex editor |
| String/keyword search | `strings -a`, `grep -a -r` |
| Encoding/decoding | CyberChef (Base64, Hex, XOR, Gzip, ROT13 chains) |
| Steganography (images) | `steghide`, `zsteg`, `stegsolve`, `exiftool` |
| Steganography (audio) | Audacity / Sonic Visualizer (check spectrogram) |
| Archive/container extraction | `binwalk -e`, `7z`, `unzip` |
| Flag pattern | regex like `\w+\{[^}]+\}` — grep this at every stage |

## When the Category Isn't Labeled

1. `file` the artifact to determine which discipline applies.
2. Run the baseline triage from Section 0 regardless of type.
3. Drop into the matching playbook (Memory / Disk / Network / Logs) above.
4. If the artifact contains another artifact (e.g. a pcap with a file transfer that's itself a disk image), nest the process — extract, then re-run triage on the extracted file.
