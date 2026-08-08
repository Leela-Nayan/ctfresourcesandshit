#!/usr/bin/env python3
"""
XOR toolkit — single-byte brute force, repeating-key keysize detection + crack,
and crib dragging for known-plaintext fragments.
"""

from itertools import cycle

ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07, ' ': 13.00,
}


def score_text(b: bytes) -> float:
    """Higher = more English-like. Penalizes non-printable bytes hard."""
    if not b:
        return -1e9
    score = 0.0
    for byte in b:
        c = chr(byte).lower()
        if c in ENGLISH_FREQ:
            score += ENGLISH_FREQ[c]
        elif 32 <= byte < 127:
            score += 0.2
        else:
            score -= 5.0
    return score


def single_byte_xor_brute(data: bytes, top_n=5):
    """Return top_n (score, key, plaintext) candidates."""
    results = []
    for key in range(256):
        pt = bytes(b ^ key for b in data)
        results.append((score_text(pt), key, pt))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top_n]


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysize(data: bytes, min_size=2, max_size=40, top_n=3):
    """Normalized Hamming-distance keysize guesser (classic Cryptopals approach)."""
    scores = []
    for size in range(min_size, max_size + 1):
        if len(data) < size * 4:
            continue
        chunks = [data[i * size:(i + 1) * size] for i in range(4)]
        dist = (
            hamming_distance(chunks[0], chunks[1])
            + hamming_distance(chunks[1], chunks[2])
            + hamming_distance(chunks[2], chunks[3])
        ) / 3
        norm = dist / size
        scores.append((norm, size))
    scores.sort()
    return scores[:top_n]


def repeating_key_xor_crack(data: bytes, keysize: int):
    """Given a keysize, recover the key by single-byte-XOR-cracking each column."""
    key = bytearray()
    for i in range(keysize):
        column = data[i::keysize]
        best = single_byte_xor_brute(column, top_n=1)[0]
        key.append(best[1])
    return bytes(key)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, cycle(key)))


def crib_drag(ciphertexts: list, crib: str, position_hint=None):
    """
    Multi-time-pad style crib dragging: if you have several ciphertexts XORed
    with the SAME key/keystream, XOR any two ciphertexts together to cancel
    the key, then slide a known/guessed plaintext fragment (crib) across to
    find where it produces readable text in the other stream.
    """
    results = []
    for i in range(len(ciphertexts)):
        for j in range(len(ciphertexts)):
            if i == j:
                continue
            c1, c2 = ciphertexts[i], ciphertexts[j]
            xored = xor_bytes(c1, c2)
            crib_b = crib.encode()
            positions = range(len(xored) - len(crib_b) + 1) if position_hint is None else [position_hint]
            for pos in positions:
                segment = xored[pos:pos + len(crib_b)]
                candidate = xor_bytes(segment, crib_b)  # recovers fragment of OTHER plaintext
                if all(32 <= b < 127 for b in candidate):
                    results.append((i, j, pos, candidate))
    return results


def full_repeating_key_pipeline(data: bytes):
    """One-shot: guess keysize, crack key, decrypt. Print top candidates."""
    print("[*] Guessing keysize via normalized Hamming distance...")
    for norm, size in guess_keysize(data):
        key = repeating_key_xor_crack(data, size)
        pt = xor_bytes(data, key)
        print(f"  keysize={size} norm_dist={norm:.3f} key={key!r}")
        print(f"    preview: {pt[:80]!r}")
    print("[*] Pick the keysize whose preview looks most like real text, "
          "then decrypt fully with xor_bytes(data, key).")


if __name__ == "__main__":
    print("Usage:")
    print("  from xor_toolkit import single_byte_xor_brute, full_repeating_key_pipeline")
    print("  single_byte_xor_brute(open('cipher.bin','rb').read())")
    print("  full_repeating_key_pipeline(open('cipher.bin','rb').read())")
