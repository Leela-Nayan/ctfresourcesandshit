#!/usr/bin/env python3
"""
Solve Wrapper — Handles local/remote switching with retry logic

Drop-in wrapper for exploit scripts. Handles connection management.

Usage in your exploit:
    from solve_wrapper import *

    @exploit
    def solve(p, args):
        # p is already connected
        p.sendline(b'payload')
        p.interactive()
"""
from pwn import *
import sys
import os



def get_connection(binary='./chall', host='127.0.0.1', port=1337, libc='', ld=''):
    """
    Smart connection handler.

    Args (from sys.argv):
        local     → run binary locally
        gdb       → run locally + attach GDB
        remote    → connect to host:port (default)
        <host> <port> → override remote target
    """
    # Override host/port from argv
    for i, arg in enumerate(sys.argv[1:], 1):
        if ':' in arg and not arg.startswith('-'):
            host, port = arg.split(':')
            port = int(port)
            break
        try:
            if i < len(sys.argv) and int(sys.argv[i+1]):
                host = arg
                port = int(sys.argv[i+1])
                break
        except:
            pass

    if 'gdb' in sys.argv:
        gdbscript = '''
        continue
        '''
        env = {}
        if libc:
            env['LD_PRELOAD'] = libc
        if ld:
            p = process([ld, binary], env=env)
        else:
            p = process(binary, env=env)
        gdb.attach(p, gdbscript=gdbscript)
        return p

    elif 'local' in sys.argv:
        env = {}
        if libc:
            env['LD_PRELOAD'] = libc
        if ld:
            return process([ld, binary], env=env)
        return process(binary, env=env)

    else:
        log.info(f'Connecting to {host}:{port}')
        return remote(host, port)

def exploit(func):
    """
    Decorator for exploit functions.
    Handles connection and error recovery.

    usage:
        @exploit
        def solve(p, args):
            p.sendline(b'payload')
            p.interactive()
    """
    def wrapper(*args, **kwargs):
        retries = int(os.environ.get('RETRIES', '1'))
        for attempt in range(retries):
            try:
                p = get_connection(**kwargs)
                if attempt > 0:
                    log.info(f'Attempt {attempt + 1}/{retries}')
                func(p, *args)
                return
            except EOFError:
                log.warning(f'EOFError on attempt {attempt + 1}')
            except KeyboardInterrupt:
                log.info('Interrupted')
                return
            except Exception as e:
                log.error(f'Error: {e}')
                if attempt == retries - 1:
                    raise
    return wrapper


def find_flag(data, prefixes=None):
    """Extract flag from data."""
    if prefixes is None:
        prefixes = [b'inctf{', b'INCTF{', b'InCTF{', b'flag{', b'FLAG{', b'CTF{', b'ctf{']

    if isinstance(data, str):
        data = data.encode()

    for prefix in prefixes:
        idx = data.lower().find(prefix.lower())
        if idx != -1:
            end = data.find(b'}', idx)
            if end != -1:
                flag = data[idx:end+1]
                log.success(f' FLAG: {flag.decode(errors="replace")}')
                return flag
    return None


def p64_chain(*addrs):
    """Pack multiple 64-bit addresses."""
    return b''.join(p64(a) for a in addrs)

def p32_chain(*addrs):
    """Pack multiple 32-bit addresses."""
    return b''.join(p32(a) for a in addrs)

if __name__ == '__main__':
    print('Solve wrapper — import this in your exploit scripts')
    print(f'usage: python3 your_exploit.py [local|gdb|remote|host:port]')
    print(f'  Env: RETRIES=5 python3 exploit.py  # retry on failure')
