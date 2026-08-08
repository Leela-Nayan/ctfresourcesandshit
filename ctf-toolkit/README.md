# ctf toolkit

inctf nationals 2026 - cheatsheets, templates, scripts for all domains

clone this, copy a template, fill in challenge specifics, run.

## domains

| domain | cheatsheet | scripts/templates |
|--------|-----------|-------------------|
| pwn | [pwn/cheatsheet.md](pwn/cheatsheet.md) | [pwn/templates/](pwn/templates/) (16 exploits) + [pwn/utils/](pwn/utils/) |
| rev | [rev/cheatsheet.md](rev/cheatsheet.md) | [rev/templates/](rev/templates/) (11 solvers) + [rev/utils/](rev/utils/) |
| forensics | [forensics/cheatsheet.md](forensics/cheatsheet.md) | steg, image, network, audio, carving |
| crypto | [crypto/cheatsheet.md](crypto/cheatsheet.md) | classical, rsa, aes, xor, dh |
| web | [web/cheatsheet.md](web/cheatsheet.md) | sqli, xss, ssrf, jwt, ssti |
| hardware | [hardware/cheatsheet.md](hardware/cheatsheet.md) | uart, spi, i2c, jtag, embedded linux |
| automotive/ot | [automotive-ot/cheatsheet.md](automotive-ot/cheatsheet.md) | can bus, vin, modbus, ics |
| mobile | [mobile/cheatsheet.md](mobile/cheatsheet.md) | apk reversing, frida, adb |
| osint | [osint/cheatsheet.md](osint/cheatsheet.md) | username, domain, image, geo |
| tools guide | [TOOLS_GUIDE.md](TOOLS_GUIDE.md) | every tool - what, when, how |
| online resources | [ONLINE_RESOURCES.md](ONLINE_RESOURCES.md) | bookmarks for the ctf |

---

## pwn templates - `pwn/templates/`

| script | when to use |
|--------|-------------|
| [exploit_template.py](pwn/templates/exploit_template.py) | start here - generic skeleton w/ local/remote/gdb |
| [bof_ret2win.py](pwn/templates/bof_ret2win.py) | simple overflow -> jump to win func |
| [bof_ret2libc.py](pwn/templates/bof_ret2libc.py) | leak libc via puts -> system("/bin/sh") |
| [bof_rop_chain.py](pwn/templates/bof_rop_chain.py) | full rop: auto-rop, execve, mprotect, ret2csu |
| [bof_ret2shellcode.py](pwn/templates/bof_ret2shellcode.py) | nx off -> shellcode on stack/bss/jmp_rsp |
| [fmt_string_leak.py](pwn/templates/fmt_string_leak.py) | format string -> auto-leak & classify addrs |
| [fmt_string_write.py](pwn/templates/fmt_string_write.py) | format string -> got overwrite, arb write |
| [heap_tcache_poison.py](pwn/templates/heap_tcache_poison.py) | tcache poisoning (glibc >=2.27, safe-linking >=2.32) |
| [heap_fastbin_dup.py](pwn/templates/heap_fastbin_dup.py) | fastbin double-free |
| [heap_house_of_force.py](pwn/templates/heap_house_of_force.py) | top chunk overflow -> arb alloc |
| [heap_uaf.py](pwn/templates/heap_uaf.py) | use-after-free -> leak, fptr hijack, tcache |
| [sigreturn_srop.py](pwn/templates/sigreturn_srop.py) | srop: sigreturn frame -> execve/mprotect/orw |
| [stack_pivot.py](pwn/templates/stack_pivot.py) | leave;ret / pop rsp / partial overwrite |
| [seccomp_bypass.py](pwn/templates/seccomp_bypass.py) | seccomp orw: open->read->write flag |
| [shellcode_collection.py](pwn/templates/shellcode_collection.py) | ready shellcodes: execve, orw, revshell |
| [one_gadget_finder.py](pwn/templates/one_gadget_finder.py) | find one-gadget magic addrs in libc |

## pwn utils - `pwn/utils/`

| script | what it does |
|--------|-------------|
| [libc_finder.py](pwn/utils/libc_finder.py) | identify libc from leaked addrs |
| [rop_gadget_finder.sh](pwn/utils/rop_gadget_finder.sh) | auto dump common rop gadgets |
| [checksec_all.sh](pwn/utils/checksec_all.sh) | checksec on all binaries in a dir |
| [patch_binary.py](pwn/utils/patch_binary.py) | patchelf wrapper + byte-level patching |
| [gdb_scripts.py](pwn/utils/gdb_scripts.py) | gdb/pwndbg cmd reference & templates |
| [canary_bruteforce.py](pwn/utils/canary_bruteforce.py) | byte-by-byte canary brute (forking servers) |

see also: [pwn cheatsheet](pwn/cheatsheet.md)

---

## rev templates - `rev/templates/`

| script | when to use |
|--------|-------------|
| [angr_solve.py](rev/templates/angr_solve.py) | angr auto-solver - stdin, argv, output matching |
| [z3_solve.py](rev/templates/z3_solve.py) | z3 constraints - bytes, eqs, matrix, bit ops |
| [xor_decrypt.py](rev/templates/xor_decrypt.py) | xor: single, multi-byte, rolling, brute-force |
| [rc4_decrypt.py](rev/templates/rc4_decrypt.py) | rc4 decrypt with ksa/prga |
| [aes_decrypt.py](rev/templates/aes_decrypt.py) | aes ecb/cbc/ctr + padding oracle |
| [custom_cipher_template.py](rev/templates/custom_cipher_template.py) | custom cipher: feistel, tea/xtea |
| [anti_debug_bypass.py](rev/templates/anti_debug_bypass.py) | bypass ptrace, timing, signal anti-debug |
| [unpack_upx.sh](rev/templates/unpack_upx.sh) | upx unpacker + packing detection |
| [dotnet_decompile.sh](rev/templates/dotnet_decompile.sh) | .net decompilation workflow |
| [java_decompile.sh](rev/templates/java_decompile.sh) | java jar/class decompilation |
| [golang_reversing.md](rev/templates/golang_reversing.md) | go binary reversing tips |

## rev utils - `rev/utils/`

| script | what it does |
|--------|-------------|
| [string_extract.py](rev/utils/string_extract.py) | smart strings: ascii, wide, b64, xor-hidden |
| [entropy_check.py](rev/utils/entropy_check.py) | detect packing via entropy |
| [patch_binary.py](rev/utils/patch_binary.py) | nop jumps, flip conditions, force returns |
| [dynamic_trace.sh](rev/utils/dynamic_trace.sh) | ltrace/strace with useful filters |
| [elf_parser.py](rev/utils/elf_parser.py) | quick elf header/section analysis |

see also: [rev cheatsheet](rev/cheatsheet.md)

---

## common - `common/`

| script | what it does |
|--------|-------------|
| [flag_finder.sh](common/flag_finder.sh) | search for flag patterns everywhere |
| [setup_env.sh](common/setup_env.sh) | install ctf tools in wsl/linux |
| [solve_wrapper.py](common/solve_wrapper.py) | local/remote/gdb connection handler |

---

## workflow

### pwn
```bash
# 1. recon
file ./chall && checksec ./chall
strings ./chall | grep -iE "flag|win|shell"

# 2. copy template
cp ctf-toolkit/pwn/templates/exploit_template.py exploit.py

# 3. edit: set BINARY, HOST, PORT, fill exploit()
vim exploit.py

# 4. test local
python3 exploit.py local
python3 exploit.py gdb

# 5. run remote
python3 exploit.py
```

### rev
```bash
# 1. recon
file ./chall
python3 ctf-toolkit/rev/utils/string_extract.py ./chall
python3 ctf-toolkit/rev/utils/entropy_check.py ./chall
ltrace -s 200 ./chall

# 2. packed? unpack
./ctf-toolkit/rev/templates/unpack_upx.sh ./chall

# 3. open in ghidra/ida, find the algorithm

# 4. constraint based -> z3
cp ctf-toolkit/rev/templates/z3_solve.py solve.py

# 5. too complex -> angr
cp ctf-toolkit/rev/templates/angr_solve.py solve.py
```

## decision tree

```
got a binary? -> checksec
  |
  |- nx disabled?      -> ret2shellcode
  |- no canary, no pie -> ret2win or ret2libc
  |- format string?    -> fmt_string_leak -> fmt_string_write
  |- heap challenge?   -> heap_uaf / heap_tcache_poison
  |- seccomp?          -> seccomp_bypass (orw)
  |- limited gadgets?  -> srop or ret2csu
  \- forking server?   -> canary_bruteforce
```
