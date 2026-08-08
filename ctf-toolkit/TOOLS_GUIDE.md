# pwn & rev tools guide

quick ref for all the tools - what they do, when to use em, commands u need

---

## tool decision flowchart

```
Got a binary?
│
├- What is it?
│   -> file ./chall
│
├- What protections?
│   -> checksec ./chall
│
├- Static Analysis (understand the code)
│   ├- Quick look    -> strings, objdump, readelf
│   ├- Deep analysis -> Ghidra or IDA
│   └- .NET/Java/Go  -> dnSpy, JD-GUI, GoReSym
│
├- Dynamic Analysis (run and observe)
│   ├- Library calls  -> ltrace
│   ├- System calls   -> strace
│   ├- Debugging      -> GDB + pwndbg
│   └- Tracing        -> r2 / frida
│
├- Exploitation (pwn)
│   ├- Scripting      -> pwntools (Python)
│   ├- ROP gadgets    -> ROPgadget / ropper
│   ├- Libc lookup    -> libc-database / libc.rip
│   ├- One-gadgets    -> one_gadget
│   ├- Seccomp rules  -> seccomp-tools
│   └- Patching       -> patchelf
│
└- Solving (rev)
    ├- Symbolic exec  -> angr
    ├- Constraints    -> Z3
    └- Crypto         -> CyberChef / pycryptodome
```

---

## static analysis tools

### `file` — Identify Binary Type
when: ALWAYS first. Tells you architecture, linking, type.
```bash
file ./chall
```
output tells u:
| Output | Meaning |
|--------|---------|
| `ELF 64-bit LSB executable` | Linux x86_64, not PIE |
| `ELF 64-bit LSB pie executable` | Linux x86_64, PIE enabled |
| `ELF 32-bit` | 32-bit Linux binary |
| `PE32 executable` | Windows .exe |
| `Mach-O` | macOS binary |
| `Java archive` | .jar file |
| `Python` | .pyc bytecode |
| `statically linked` | No external libs (harder, but all code is in binary) |
| `dynamically linked` | Uses libc/ld-linux (can leak libc addresses) |
| `stripped` | No debug symbols (harder to read in GDB) |
| `not stripped` | Has symbols (function names visible!) |

---

### `checksec` — Security Protections
when: ALWAYS for pwn. Determines your attack strategy.
```bash
checksec ./chall
# or: pwn checksec ./chall
```
what each protection means:

| Protection | Enabled | Disabled | Impact |
|-----------|---------|----------|--------|
| **RELRO** | `Full RELRO` -> GOT read-only | `Partial/No RELRO` -> GOT writable | Full = can't overwrite GOT. Partial = GOT overwrite works |
| **Stack Canary** | `Canary found` | `No canary` | Found = need leak or brute-force canary first |
| **NX** | `NX enabled` | `NX disabled` | Enabled = no shellcode on stack (use ROP). Disabled = shellcode! |
| **PIE** | `PIE enabled` | `No PIE` | Enabled = all addresses randomized (need PIE leak). No PIE = fixed addresses |
| **ASLR** | (OS level) | `echo 0 > /proc/sys/...` | Stack/libc/heap randomized. Need leaks |

strategy from checksec:
```
No canary + No PIE + NX     -> ret2libc, ret2win, ROP
No canary + No PIE + No NX  -> ret2shellcode (easiest!)
Canary + No PIE + NX        -> leak canary first, then ROP
Full RELRO + PIE + Canary   -> heap exploit or format string
```

---

### `strings` — Extract Readable Strings
when: Quick recon. Find passwords, flag formats, error messages, function names.
```bash
strings ./chall                              # all strings
strings -n 8 ./chall                         # min length 8
strings ./chall | grep -iE "flag|pass|key|secret|correct|wrong"
strings ./chall | grep "inctf{"             # direct flag search
strings -e l ./chall                         # UTF-16LE (Windows wide strings)
```

---

### `readelf` — ELF Structure
when: Need section addresses, symbol table, GOT/PLT info.
```bash
readelf -h ./chall          # ELF header (entry point, arch)
readelf -S ./chall          # sections (.text, .data, .bss, .got, .plt)
readelf -s ./chall          # symbol table (function names + addresses!)
readelf -r ./chall          # relocations (GOT entries)
readelf -l ./chall          # program headers (segments, permissions)
readelf -d ./chall          # dynamic section (needed libraries)
```

key sections:
| Section | What's there | Why you care |
|---------|-------------|--------------|
| `.text` | Code | Where instructions live |
| `.plt` | PLT stubs | Call external functions (puts@PLT, system@PLT) |
| `.got` / `.got.plt` | GOT entries | Overwrite these for GOT hijack |
| `.bss` | Uninitialized data | Writable + known address = good for shellcode/strings |
| `.rodata` | Read-only data | Strings like "/bin/sh", flag format |
| `.data` | Initialized globals | Writable, known address |

---

### `objdump` — Disassemble
when: Quick disassembly without a full tool. Find specific functions.
```bash
objdump -d ./chall | less                    # full disassembly (AT&T syntax)
objdump -M intel -d ./chall | less           # Intel syntax (easier to read)
objdump -d ./chall | grep -A 20 "<main>:"    # just main function
objdump -d ./chall | grep "@plt"             # PLT entries (imports)
objdump -R ./chall                            # GOT relocations (addresses!)
objdump -t ./chall                            # symbol table
objdump -s -j .rodata ./chall                # hex dump of .rodata section
```

---

### Ghidra — Full Decompiler (FREE)
when: Deep reversing. Decompiles to C-like pseudocode. The main rev tool.

key shortcuts:
| Key | Action |
|-----|--------|
| `G` | Go to address |
| `L` | Rename variable/function |
| `T` | Retype variable |
| `;` | Add comment |
| `Ctrl+Shift+E` | References TO this address |
| `X` | Cross-references (who calls this?) |
| `Space` | Toggle listing/decompiler view |
| `Middle-click` | Follow reference |

workflow:
1. File -> Import -> select binary -> Analyze (accept defaults)
2. Go to `main` in Symbol Tree (left panel)
3. Read the decompiler output (right panel)
4. Rename variables (`L`) to understand logic
5. Look for: strcmp, memcmp, XOR loops, crypto patterns
6. Right-click -> References -> Find references to see who uses a function

---

### IDA Free / IDA Pro — Disassembler + Decompiler
when: Alternative to Ghidra. IDA Pro (paid) has best decompiler. IDA Free works for basic analysis.

key shortcuts:
| Key | Action |
|-----|--------|
| `G` | Go to address |
| `N` | Rename |
| `Y` | Change type |
| `X` | Cross-references |
| `H` | Toggle hex/decimal |
| `Space` | Toggle text/graph view |
| `F5` | Decompile (Hex-Rays, Pro only) |
| `/` | Add comment |
| `Tab` | Switch between disassembly ↔ pseudocode |

---

## dynamic analysis tools

### `ltrace` — Library Call Tracer
when: REV FIRST STEP. Catches strcmp, memcmp, puts — often reveals the answer directly!

```bash
ltrace ./chall                               # trace library calls
ltrace -s 200 ./chall                        # show 200 chars of string args
ltrace -e strcmp+memcmp ./chall               # only string comparisons
ltrace -e '*crypt*+*aes*+*sha*' ./chall      # crypto functions
```

what to look for:
```
strcmp("your_input", "s3cr3t_p4ss") = -1      <- THERE'S THE PASSWORD!
memcmp(0x7ffd..., 0x556..., 32)              <- comparing 32 bytes
puts("Wrong!")                                <- failure path
```



---

### `strace` — System Call Tracer
when: See what files are opened, what network connections are made, what syscalls fail.

```bash
strace ./chall                               # all syscalls
strace -e trace=file ./chall                 # file operations only
strace -e trace=network ./chall              # network operations
strace -e trace=read,write -s 200 ./chall    # see read/write data
strace -e trace=open,openat ./chall          # what files it opens
strace -f ./chall                            # follow forks
```

what to look for:
```
openat(AT_FDCWD, "/flag.txt", O_RDONLY) = 3  <- reads flag file
read(3, "inctf{...}", 100)                   <- flag content!
connect(3, {sa_family=AF_INET, sin_port=1337}) <- network connection
```

---

### GDB + pwndbg — Debugger (THE MAIN TOOL)
when: ALWAYS for pwn. Set breakpoints, inspect memory, find offsets, test exploits.



#### Starting GDB
```bash
gdb ./chall                   # start
gdb -q ./chall                # quiet mode (no banner)
gdb --args ./chall arg1 arg2  # with arguments
```

#### Essential Commands
```bash
# --- RUNNING ------------------------------
r                         # run
r < input.txt             # run with file as stdin
r <<< $(python3 -c "print('A'*100)")  # run with inline input
c                         # continue after breakpoint
ni                        # next instruction (step over calls)
si                        # step into (follow calls)
finish                    # run until current function returns

# --- BREAKPOINTS --------------------------
b main                    # break at main
b *0x401234               # break at address
b *main+42                # break at offset in main
b *(0x555555554000+0x1234) # PIE: base + offset
info b                    # list breakpoints
d 1                       # delete breakpoint #1
disable 1                 # disable without deleting

# --- INSPECTING ---------------------------
info reg                  # all registers
p $rax                    # print register
p/x $rax                  # print in hex
x/20gx $rsp              # dump 20 qwords from stack
x/s $rdi                 # print string at rdi
x/10i $rip               # disassemble 10 instructions from RIP
x/20bx 0x404060          # 20 bytes at address

# --- PWNDBG SPECIFIC (the good stuff!) ---
telescope $rsp 30         # smart stack dump (shows pointers, strings)
vmmap                     # memory map (find libc base, stack, heap)
vmmap libc                # just libc mapping
got                       # GOT table entries
plt                       # PLT entries
checksec                  # protections
heap                      # heap overview
bins                      # all bin states
tcachebins                # tcache entries
fastbins                  # fastbin entries
unsortedbin               # unsorted bin
vis_heap_chunks           # VISUAL heap layout (amazing!)
canary                    # show stack canary value
piebase                   # show PIE base address
search -s "flag{"         # search for string in memory
search -x 41414141        # search for hex pattern
cyclic 200                # generate pattern
cyclic -l 0x6161616166    # find offset from crash value

# --- MODIFYING ----------------------------
set $rax = 0              # modify register
set {long}0x404060 = 0x42 # write to memory
set *(int*)0x404060 = 0   # write int to address
```

#### GDB for Finding Buffer Overflow Offset
```bash
# Step 1: Generate pattern
cyclic 200
# Step 2: Run binary with pattern, it crashes
# Step 3: Check what's at RSP (or where it crashed)
cyclic -l $rsp            # pwndbg tells you the offset!
# Or: cyclic -l 0x6161616161616166
```

#### GDB for Format String Offset
```bash
# Run binary, send: AAAA%p%p%p%p%p%p%p%p%p%p
# Look for 0x41414141 in output -> that position is your offset
```

#### GDB for Heap Debugging
```bash
b malloc                  # break on every malloc
b free                    # break on every free
b realloc
# After break:
heap                      # heap state
vis_heap_chunks           # visual heap
bins                      # where freed chunks go
```

---

### `r2` (radare2) — CLI Analysis Suite
when: Quick analysis without GUI. Good for scripting, one-liners.

```bash
r2 ./chall                # open in interactive mode
r2 -A ./chall             # open + auto-analyze

# Inside r2:
aaa                       # analyze all
afl                       # list functions
pdf @ main                # disassemble main
iz                        # strings in data sections
izz                       # strings in entire binary
s main                    # seek to main
V                         # visual mode
VV                        # graph mode (like IDA graph)
```

---

## exploitation tools (pwn)

### pwntools (Python) — THE Exploit Framework
when: ALWAYS for pwn. Write exploits, craft payloads, connect to targets.



```python
from pwn import *

# --- CONNECTION ----------------------------
p = process('./chall')                    # local
p = remote('host', 1337)                  # remote
p = process('./chall'); gdb.attach(p)     # local + GDB

# --- SEND/RECEIVE -------------------------
p.sendline(b'hello')                      # send + newline
p.send(b'hello')                          # send without newline
p.sendlineafter(b'> ', b'1')             # wait for prompt, then send
p.sendafter(b': ', payload)              # send after, no newline

p.recvline()                              # receive one line
p.recvuntil(b'flag{')                    # receive until pattern
p.recv(100)                               # receive 100 bytes
p.recvall(timeout=5)                     # receive everything

# --- PACKING ------------------------------
p64(0xdeadbeef)                           # pack 64-bit address -> bytes
p32(0xdeadbeef)                           # pack 32-bit
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00') # unpack 64-bit bytes -> int
u64(leak.ljust(8, b'\x00'))              # pad leak and unpack

# --- ELF ANALYSIS -------------------------
elf = ELF('./chall')
elf.sym['main']                           # address of main
elf.plt['puts']                           # PLT address of puts
elf.got['puts']                           # GOT address of puts
elf.bss()                                 # BSS address
next(elf.search(b'/bin/sh'))             # find string in binary

# --- LIBC ---------------------------------
libc = ELF('./libc.so.6')
libc.address = leak - libc.sym['puts']    # set libc base from leak
libc.sym['system']                        # system() address
next(libc.search(b'/bin/sh\x00'))        # "/bin/sh" in libc

# --- ROP ----------------------------------
rop = ROP(elf)
rop.find_gadget(['pop rdi', 'ret'])[0]   # find gadget
rop.find_gadget(['ret'])[0]              # ret gadget (stack alignment)
rop.call('puts', [elf.got['puts']])      # auto-build call
print(rop.dump())                         # show ROP chain

# --- FORMAT STRING ------------------------
fmtstr_payload(offset, {addr: value})     # auto-write payload
FmtStr(exec_fmt_func, offset=6)          # interactive fmt exploit

# --- SHELLCODE ----------------------------
context.arch = 'amd64'
asm(shellcraft.sh())                      # execve("/bin/sh") shellcode
asm(shellcraft.cat('/flag.txt'))          # ORW shellcode

# --- CYCLIC -------------------------------
cyclic(200)                               # generate pattern
cyclic_find(0x61616166)                   # find offset

# --- SROP ---------------------------------
frame = SigreturnFrame()
frame.rax = 59                            # execve
frame.rdi = binsh_addr
frame.rip = syscall_addr
bytes(frame)                              # sigreturn frame bytes
```

---

### ROPgadget / ropper — Find ROP Gadgets
when: Building ROP chains. Find `pop rdi; ret`, `syscall`, etc.

```bash
# ROPgadget (recommended)
ROPgadget --binary ./chall                            # all gadgets
ROPgadget --binary ./chall | grep "pop rdi"           # specific gadget
ROPgadget --binary ./chall | grep "pop rsi"
ROPgadget --binary ./chall | grep "pop rdx"
ROPgadget --binary ./chall | grep "syscall"
ROPgadget --binary ./chall | grep ": ret$"            # just 'ret'
ROPgadget --binary ./chall | grep "leave ; ret"       # stack pivot
ROPgadget --binary ./chall | grep "jmp rsp"           # jmp to shellcode
ROPgadget --binary ./libc.so.6 | grep "pop rdi"      # gadgets in libc

# ropper (alternative)
ropper --file ./chall --search "pop rdi"
ropper --file ./chall --search "syscall"
```

common gadgets:
| Gadget | What for |
|--------|----------|
| `pop rdi; ret` | Set 1st argument (rdi) |
| `pop rsi; pop r15; ret` | Set 2nd argument (rsi) |
| `pop rdx; ret` | Set 3rd argument (rdx) |
| `pop rax; ret` | Set syscall number |
| `syscall; ret` | Invoke syscall |
| `ret` | Stack alignment (16-byte for system()) |
| `leave; ret` | Stack pivot |
| `jmp rsp` / `call rsp` | Jump to shellcode after return address |

---

### one_gadget — Magic Libc Gadgets
when: Need a single address in libc that gives you a shell. Much simpler than full ROP.

```bash
one_gadget ./libc.so.6
```

usage:
```python
one_gadget = libc_base + 0x50a47
# Write this address to __malloc_hook, __free_hook, GOT entry, or return address
```

note: constraints must be satisfied, if one doesnt work try the next

---

### seccomp-tools — Analyze Seccomp Rules
when: Binary has seccomp/sandbox. Need to know which syscalls are allowed.

```bash
seccomp-tools dump ./chall
```

**If execve is blocked:** Use ORW (open/read/write) -> `seccomp_bypass.py` template

---

### patchelf — Fix Binary Linking
when: Challenge provides libc.so.6 and ld-linux. Patch binary to use them.

```bash
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./chall
patchelf --set-rpath . ./chall
ldd ./chall    # verify it's using local libc
```

so your local exploit uses same libc as remote. offsets gotta match

---

### libc-database / libc.rip — Identify Libc Version
when: Leaked a libc address, need to find which libc version to calculate offsets.

online: https://libc.rip

or use libc_finder.py from the toolkit
```bash
python3 libc_finder.py puts 0x7f1234567890
```

---

## reversing-specific tools

### angr — Symbolic Execution
when: Complex rev with many checks. Let the computer find the path to "Correct!".

```python
import angr
p = angr.Project('./chall', auto_load_libs=False)
s = p.factory.entry_state()
sm = p.factory.simulation_manager(s)
sm.explore(find=0x401234, avoid=[0x401256])
if sm.found:
    print(sm.found[0].posix.dumps(0))
```

when to use angr vs z3:
| Use angr | Use Z3 |
|----------|--------|
| Full binary, complex control flow | Extracted constraints from decompiler |
| Don't want to understand algorithm | Can read and extract the math |
| Multiple functions, many branches | Single check function |
| Takes longer (minutes) | Fast (seconds) |

---

### Z3 — Constraint Solver
when: Extracted the check logic from Ghidra/IDA, need to solve equations.

```python
from z3 import *
s = Solver()
flag = [BitVec(f'b{i}', 8) for i in range(32)]
for b in flag:
    s.add(b >= 0x20, b <= 0x7e)
# Paste constraints from decompiler:
s.add(flag[0] * 3 + flag[1] == 295)
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[b].as_long()) for b in flag))
```

---

### Python Decompilers — .pyc Files
when: Challenge is a compiled Python (.pyc) file.

```bash
# uncompyle6 (Python 2.7 - 3.8)
uncompyle6 challenge.pyc > challenge.py

# pycdc (Python 3.9+)
./pycdc challenge.pyc

# Manual bytecode (last resort)
python3 -c "import dis, marshal; f=open('challenge.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"
```

---

### CyberChef — Swiss Army Knife for Encoding/Crypto
when: Need to decode base64, hex, XOR, ROT13, or chain operations.

url: https://gchq.github.io/CyberChef/

---

## quick tool selection table

### for pwn:

| Situation | Tool | Command |
|-----------|------|---------|
| What is this binary? | `file` | `file ./chall` |
| What protections? | `checksec` | `checksec ./chall` |
| Find strings | `strings` | `strings ./chall \| grep flag` |
| Find buffer size | GDB + pwndbg | `cyclic 200` -> crash -> `cyclic -l $rsp` |
| Find ROP gadgets | ROPgadget | `ROPgadget --binary ./chall \| grep "pop rdi"` |
| Write exploit | pwntools | `from pwn import *` |
| Debug exploit | GDB + pwntools | `gdb.attach(p)` |
| Identify libc | libc.rip | `libc_finder.py puts 0x7f...` |
| One-shot shell | one_gadget | `one_gadget ./libc.so.6` |
| Check seccomp | seccomp-tools | `seccomp-tools dump ./chall` |
| Use challenge libc | patchelf | `patchelf --set-interpreter ./ld ./chall` |
| Heap analysis | GDB pwndbg | `heap`, `bins`, `vis_heap_chunks` |
| View GOT/PLT | GDB or readelf | `got` in pwndbg, `readelf -r ./chall` |

### for rev:

| Situation | Tool | Command |
|-----------|------|---------|
| What type? | `file` | `file ./chall` |
| Quick strings | `strings` | `strings -n 6 ./chall` |
| See strcmp args | `ltrace` | `ltrace -s 200 ./chall` |
| Full decompile | Ghidra | Open -> Analyze -> read pseudocode |
| Packed binary? | entropy_check | `python3 entropy_check.py ./chall` |
| UPX packed | `upx -d` | `upx -d ./chall` |
| .NET binary | dnSpy | Open .exe -> browse C# source |
| Java .jar | JD-GUI / jadx | `jadx -d output/ ./chall.jar` |
| Python .pyc | uncompyle6 | `uncompyle6 chall.pyc` |
| Go binary | GoReSym + Ghidra | `GoReSym -d ./chall` |
| Math constraints | Z3 | Paste constraints, solve |
| Complex paths | angr | `sm.explore(find=X, avoid=Y)` |
| XOR encrypted | xor_decrypt.py | `python3 xor_decrypt.py data.enc` |
| Anti-debug | GDB bypass | `catch syscall ptrace; set $rax=0` |
| Patch a check | Binary patch | NOP the conditional jump |

---

## ⏱ Time-Saving Tips for 8-Hour CTF

1. **ltrace FIRST for rev** — may solve it in 10 seconds
2. **checksec FIRST for pwn** — determines your entire strategy
3. **Don't write from scratch** — copy a template, fill in specifics
4. **Use pwntools ROP()** — don't manually find gadgets unless needed
5. **Try one_gadget before full ROP** — much simpler if constraints are met
6. **angr for "too complex" rev** — don't waste time reversing if angr can solve it
7. **Flag locations to check:** `/flag`, `/flag.txt`, `/home/ctf/flag.txt`, env `$FLAG`
