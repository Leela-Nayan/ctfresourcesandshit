# CTF Reverse Engineering Methodology

A step-by-step playbook for approaching binary reversing challenges in CTFs.

---

## 1. Initial Triage

Before opening a disassembler, gather cheap information:

- `file binary` — architecture, 32/64-bit, statically/dynamically linked, stripped or not
- `checksec binary` — canary, NX, PIE, RELRO (useful even for pure-reversing challenges; tells you what protections you're up against)
- `strings binary | grep -i flag` — the flag or a meaningful string is sometimes right there
- `ltrace ./binary` / `strace ./binary` — quick view of library calls / syscalls without deep analysis
- Run the binary once, normally, to see what it actually does (input prompts, output, exit behavior)

---

## 2. Static Analysis

**Tools:** Ghidra, IDA Free/Pro, radare2/rizin, Binary Ninja, Cutter

1. Load the binary, jump to `main` (or the entry point if stripped), and read the decompiled pseudo-C rather than raw assembly where possible.
2. **Follow string cross-references** — e.g. find "Access granted" / "Wrong password" and trace backward to the function that prints them. This is usually the fastest way to locate the exact check you need to beat.
3. **Identify the core logic.** Most crackmes reduce to one of a few patterns:
   - Direct string comparison (`strcmp`) against a hardcoded value
   - A byte-by-byte comparison loop
   - A reversible transform (XOR key, rolling XOR, custom "encryption", bit rotation) applied to your input, then compared to a hardcoded result
4. Note any called library functions that hint at the algorithm (`memcpy`, `srand`/`rand`, crypto library calls, etc.) — these narrow down what you're reversing quickly.

---

## 3. Dynamic Analysis

**Tools:** gdb (+ pwndbg / GEF / peda), x64dbg (Windows), Frida

1. Set a breakpoint at the comparison/branch that decides success vs. failure.
2. Step through and watch register/memory values to recover the expected input or key directly, rather than reasoning about it purely statically.
3. If the flag is only printed on a "success" path, you can often **patch a conditional jump or a register value at runtime** to force that path and read the flag — you don't always need to derive the "real" correct input.
4. For binaries that are painful to static-analyze (heavy obfuscation, JIT'd code, mobile apps), use **Frida** to hook functions and log arguments/return values at runtime instead.

---

## 4. Handling Anti-Analysis Measures

- **Packed binary** (e.g. UPX) → `upx -d binary` to unpack before doing anything else
- **Anti-debug checks** (`ptrace(PTRACE_TRACEME)`, `IsDebuggerPresent`, timing checks) → patch out the check in the disassembler, or intercept the call (e.g. `LD_PRELOAD` a stub on Linux)
- **Obfuscated / flattened control flow** → prefer decompiler pseudo-code over raw disassembly, and look for existing deobfuscation scripts/plugins for the specific obfuscator if you can identify it
- **Self-modifying code** → dump memory at runtime after it has unpacked/decrypted itself, then analyze the dump instead of the on-disk binary

---

## 5. Solve the Logic, Don't Trace It By Hand

Once you understand the algorithm, **reimplement it in Python** and invert it (or brute-force a small remaining keyspace) rather than manually tracing through values for a large input. This is faster and far less error-prone than doing it by hand in the debugger, and it doubles as your proof-of-work for a write-up.

---

## 6. Recognize the Challenge Sub-Type Early

The sub-type changes your whole approach, so identify it as soon as possible:

| Sub-type | What it is | Approach |
|---|---|---|
| **Crackme** | Validates a fixed input | Find the check, satisfy or bypass it |
| **Keygen** | Generates/validates license-style keys | Reverse the validation algorithm, then write a generator |
| **VM / bytecode obfuscation** | Binary implements a custom interpreter | Reverse the interpreter's opcode handling first — the "real" logic won't make sense until you do |
| **Managed/interpreted language** | .NET, Java/Android, Python bytecode, etc. | Decompile instead of disassembling: dnSpy/ILSpy (.NET), jadx/CFR/javap (Java/Android), uncompyle6/decompyle3/pycdc (Python) |
| **Firmware / embedded** | Often ARM/MIPS, may need extraction first | `binwalk -e` to pull the filesystem out, then reverse target binaries individually |

---

## 7. Extract & Verify

- Confirm the recovered flag matches the challenge's required format.
- If the flag was *derived* rather than printed directly, double-check your recovered input/key actually reproduces the expected output — it's easy to be off by one transformation step.

---

## Quick Reference: Common Commands

```
file binary                     # identify architecture/type
checksec binary                 # security mitigations
strings -a binary | grep flag   # cheap flag search
ltrace ./binary                 # library call trace
strace ./binary                 # syscall trace
upx -d binary                   # unpack UPX
objdump -d binary               # raw disassembly
gdb ./binary                    # dynamic analysis
```
