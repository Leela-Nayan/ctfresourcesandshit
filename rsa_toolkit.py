#!/usr/bin/env python3
"""
RSA attack toolkit — pure Python + gmpy2/sympy fallback.
Run individual functions from a REPL or import into a solve script.

pip install pycryptodome gmpy2 sympy --break-system-packages
"""

from math import gcd, isqrt
from functools import reduce

try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def long_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, "big")


def integer_nthroot(x: int, n: int):
    """Return (root, exact) for the integer n-th root of x."""
    if HAVE_GMPY2:
        root, exact = gmpy2.iroot(x, n)
        return int(root), bool(exact)
    # fallback binary search
    if x < 0:
        return 0, False
    lo, hi = 0, 1 << ((x.bit_length() // n) + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** n == x


# ---------------------------------------------------------------------------
# 1. Wiener's Attack — small private exponent d
#    Trigger: d small, or e very close to n / unusually large e
# ---------------------------------------------------------------------------

def continued_fraction(num, den):
    cf = []
    while den:
        cf.append(num // den)
        num, den = den, num % den
    return cf


def convergents(cf):
    convs = []
    for i in range(len(cf)):
        num = cf[i]
        den = 1
        for j in range(i - 1, -1, -1):
            num, den = cf[j] * num + den, num
        convs.append((num, den))
    return convs


def wiener_attack(e, n):
    """Return d if Wiener's attack succeeds, else None."""
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # solve x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq != disc:
            continue
        p = (b + sq) // 2
        q = (b - sq) // 2
        if p * q == n:
            return d
    return None


# ---------------------------------------------------------------------------
# 2. Common Modulus Attack
#    Trigger: same n, same message, two different e1/e2 with gcd(e1,e2)=1
# ---------------------------------------------------------------------------

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def common_modulus_attack(c1, c2, e1, e2, n):
    g, a, b = egcd(e1, e2)
    assert g == 1, "gcd(e1, e2) must be 1 for this attack"
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


# ---------------------------------------------------------------------------
# 3. Hastad's Broadcast Attack (CRT)
#    Trigger: same message, small e (often 3), sent to >= e different n's
# ---------------------------------------------------------------------------

def crt(residues, moduli):
    """Chinese Remainder Theorem combine."""
    if HAVE_GMPY2:
        result = 0
        M = reduce(lambda a, b: a * b, moduli)
        for r, m in zip(residues, moduli):
            Mi = M // m
            result += r * Mi * gmpy2.invert(Mi, m)
        return int(result % M)
    # fallback
    M = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        inv = pow(Mi, -1, m)
        result += r * Mi * inv
    return result % M


def hastad_broadcast(ciphertexts, moduli, e):
    """ciphertexts/moduli are lists of length >= e."""
    c = ciphertexts[:e]
    n = moduli[:e]
    M = crt(c, n)
    root, exact = integer_nthroot(M, e)
    if not exact:
        print("[!] Not an exact e-th root — message may not be small enough, "
              "or padding is used (try Coppersmith with padding instead).")
    return root


# ---------------------------------------------------------------------------
# 4. Fermat Factorization — p and q are close together
#    Trigger: n is a product of two primes that are suspiciously close
# ---------------------------------------------------------------------------

def fermat_factor(n, max_iter=10_000_000):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b  # p, q
        a += 1
    return None


# ---------------------------------------------------------------------------
# 5. Common Factor Across Multiple Moduli
#    Trigger: you're given many public keys (n1, n2, ...) from the same source
#    and suspect shared/reused prime generation
# ---------------------------------------------------------------------------

def find_shared_factors(moduli):
    """O(n^2) gcd sweep — fine for a few dozen to a few hundred moduli.
    For thousands, use Bernstein's batch-gcd instead (see note below)."""
    results = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if g != 1:
                results[(i, j)] = g
    return results


def batch_gcd(moduli):
    """Bernstein's product-tree batch GCD — use when you have hundreds+ of n's.
    Returns list of (index, factor) where a shared factor was found."""
    def product_tree(values):
        tree = [values]
        while len(tree[-1]) > 1:
            level = tree[-1]
            tree.append([level[i] * level[i + 1] if i + 1 < len(level) else level[i]
                         for i in range(0, len(level), 2)])
        return tree

    tree = product_tree(moduli)
    prod = tree[-1][0]
    rems = [prod]
    for level in reversed(tree[:-1]):
        new_rems = []
        idx = 0
        for i in range(0, len(level), 2):
            r = rems[idx]
            if i + 1 < len(level):
                new_rems.append(r % (level[i] ** 2))
                new_rems.append(r % (level[i + 1] ** 2))
            else:
                new_rems.append(r % (level[i] ** 2))
            idx += 1
        rems = new_rems

    found = []
    for i, (n, r) in enumerate(zip(moduli, rems)):
        g = gcd(r // n, n)
        if g != 1 and g != n:
            found.append((i, g))
    return found


# ---------------------------------------------------------------------------
# 6. Direct decrypt once you have p, q
# ---------------------------------------------------------------------------

def decrypt_with_pq(c, e, p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return long_to_bytes(m)


if __name__ == "__main__":
    print("Import this module and call the attack functions directly, e.g.:")
    print("  from rsa_toolkit import wiener_attack, decrypt_with_pq")
    print("  d = wiener_attack(e, n)")
