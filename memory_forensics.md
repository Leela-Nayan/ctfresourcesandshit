# Memory Forensics — Volatility3 Command Reference

Workflow order matters. Always identify OS first — every other plugin depends on it.

## 0. Setup / OS identification

```bash
vol3 -f memory.raw windows.info
# or for older-style profile detection:
vol3 -f memory.raw -r csv windows.pstree > pstree.csv
```

## 1. Process tree — find the attack chain

```bash
vol3 -f memory.raw -r csv windows.pstree > pstree.csv
```
Look for a parent/child chain that doesn't belong — e.g. `mshta.exe` spawning
`certutil.exe` spawning an unnamed/renamed exe. This is the classic **LOLBins**
pattern (Living Off the Land Binaries): attacker abuses trusted, signed
Windows binaries (`mshta.exe`, `certutil.exe`, `rundll32.exe`, `regsvr32.exe`,
`powershell.exe`) instead of dropping obvious malware, to blend in.

**What to flag as suspicious in a pstree:**
- Office apps / mshta / wscript spawning cmd, powershell, or certutil
- certutil used with `-urlcache` (its normal job is certificate management, not downloading files — `-urlcache -split -f <url>` is a very common LOLBin download trick)
- Process names that sound legitimate but aren't real Windows services (`systemupdate.exe`, `serviceprovider.exe`)
- Any process whose parent doesn't make sense (e.g. `svchost.exe` spawned directly by a browser)

## 2. Map a process to the file it's executing

```bash
vol3 -f memory.raw -o dumps windows.dumpfiles --virtaddr <ADDR>
```
Use `windows.filescan` first to find the virtual address of a file of interest
(e.g. an `.hta` a process is pointing to), then dump it with the above.

```bash
vol3 -f memory.raw windows.filescan | grep -i "\.hta\|\.exe\|\.dll"
```

## 3. Network connections — find the C2

```bash
vol3 -f memory.raw windows.netscan
```
Look for outbound connections to non-standard ports, or IPs that also served
an HTTP download earlier in the pstree (attacker often hosts both the dropper
HTTP server and the C2 listener on the same box, different ports).

**After finding a suspicious binary, check it on VirusTotal (hash lookup) to
identify the malware family** — this often tells you which C2 framework is in
play (Havoc, Cobalt Strike, Sliver, Metasploit, etc.), which tells you what
plugin/command set to expect (e.g. Havoc's `demon` implant has a well-documented
open-source structure you can pull and read).

## 4. Dumping and unpacking suspicious executables

```bash
vol3 -f memory.raw -o dumps windows.dumpfiles --pid <PID>
```

Check packing first:
```bash
# Detect It Easy (DIE) - GUI or CLI
diec suspicious.exe
```

If UPX-packed:
```bash
upx -d -o unpacked.exe suspicious.exe
```

If it's a PyInstaller-compiled binary (check via `strings` for `pyi-` markers
or PyInstaller boilerplate):
```bash
python3 pyinstxtractor.py unpacked.exe
# then find the relevant .pyc inside the extracted folder
# decompile with pylingual, decompyle3, or pychaos (fallback if pylingual is down)
```

## 5. Users / persistence

```bash
vol3 -f memory.raw windows.hashdump
```
Look for accounts that shouldn't exist. A newly-added local admin account is
a classic persistence mechanism.

```bash
vol3 -f memory.raw windows.registry.printkey --key "ControlSet001\Control\Terminal Server"
```
Common persistence/impact registry keys to check:
- `...\Control\Terminal Server` → `fDenyTSConnections` (0 = RDP enabled — check if attacker flipped this from the default 1)
- `...\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` → classic autorun persistence
- `...\Winlogon\Shell` or `Userinit` → shell hijack persistence

Cross-reference the **registry key's last-write timestamp** against the
**process start time** from pstree to attribute which process made the change.

## 6. Privilege / elevation evidence

```bash
vol3 -f memory.raw windows.getsids --pid <PID>
```
Look for `Administrators` + `High Mandatory Level` in the SID list — this
indicates the process ran with a high-integrity elevated token, not a normal
medium-integrity user token. Windows UAC-split-token behavior means a normal
admin user still runs most things at medium integrity by default; something
at high integrity implies either a UAC prompt was approved, or **UAC was
bypassed**.

## 7. UAC bypass evidence (Beacon Object Files / COM elevation abuse)

```bash
vol3 -f memory.raw windows.dlllist --pid <PID>
```
Watch for a process loading DLLs it has no legitimate reason to load —
classic UAC-bypass DLLs include:
- `cmlua.dll` / `cmstplua.dll` (CMSTPLUA COM elevation — `ICMLuaUtil` interface, auto-elevated)
- `fodhelper.dll`-related registry hijacks (fodhelper.exe bypass)
- `sdclt.dll` (sdclt.exe bypass)

```bash
vol3 -f memory.raw windows.vadinfo --pid <PID>
```
High commit-charge VAD regions are worth dumping and disassembling — a region
with a COFF header (bytes like `64 86` for x64) but **no PE signature** is a
strong indicator of a **Beacon Object File (BOF)** loaded directly into memory
rather than an on-disk executable.

**BOF elevation pattern to recognize in disassembly/decompilation:**
1. `CLSIDFromString` — converts a GUID string to internal CLSID
2. `CoCreateInstanceAsAdmin` — passes that CLSID with an "Elevation:Administrator!new:" moniker
3. `StringFromGUID2` — formats CLSID back to text for the moniker string
4. `OLE32CoGetObject` (or `CoGetObject`) — actually requests the elevated COM interface
5. Elevated interface (e.g. `ICMLuaUtil::ShellExec`) is then called to launch a payload with high integrity

This whole chain = **COM elevation moniker abuse**, a well-documented UAC
bypass technique. Reference: search "ICMLuaUtil UAC bypass" / "CMSTPLUA COM
elevation abuse" for background if you land on this pattern.

## 8. Process spoofing evidence (PEB manipulation)

Look for `RtlInitUnicodeString` calls in a suspicious BOF/shellcode region —
if it's setting up `ImagePathName` and `CommandLine` fields, the malware may
be spoofing its PEB (Process Environment Block) to impersonate a legitimate
process name (e.g. making itself look like `explorer.exe` in process listings)
— a classic **process spoofing / masquerading** technique.

## Quick trigger table — memory forensics

| You see... | Think... | Do... |
|---|---|---|
| Odd parent→child chain (mshta/wscript → cmd/certutil → unknown exe) | LOLBins-based dropper | pstree, trace each hop, dump the dropped file |
| certutil with `-urlcache` | File download disguised as cert operation | Extract the URL, note the download destination |
| Suspicious outbound connection to non-standard port | C2 beacon | netscan, hash the binary, check VirusTotal |
| Renamed/legit-sounding exe (systemupdate.exe, serviceprovider.exe) | Malware masquerading as system tool | Dump, check packer (DIE), unpack, decompile |
| New local admin user in hashdump | Persistence via account creation | Correlate creation time with process execution |
| Registry key changed from Windows default | Persistence or defense evasion | printkey, check last-write time vs pstree |
| High Mandatory Level SID on a process | Elevated/admin execution | Investigate how — approved UAC or bypass |
| Process loading cmlua.dll/cmstplua.dll unexpectedly | COM-based UAC bypass | dlllist, vadinfo, dump+disassemble suspicious VAD |
| VAD region with COFF header, no PE signature | Beacon Object File (BOF) in memory | Dump region, disassemble in IDA/Ghidra |
| RtlInitUnicodeString modifying ImagePathName/CommandLine | PEB spoofing / masquerading | Get callsite addresses from disassembly |
