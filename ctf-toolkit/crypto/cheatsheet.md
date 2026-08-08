# crypto cheatsheet

## first steps
```bash
# Identify what you have:
file cipher.* 
xxd cipher.bin | head
python3 -c "import base64; print(base64.b64decode(open('cipher.txt').read()))"
# Is it hex? base64? raw bytes? ASCII?
```

online: https://gchq.github.io/CyberChef/
cipher id: https://www.dcode.fr/cipher-identifier

---

## classical ciphers

### Caesar / ROT-N
```python
# Brute-force all 26 rotations
text = "ENCRYPTED_TEXT_HERE"
for i in range(26):
    decoded = ''.join(chr((ord(c) - 65 + i) % 26 + 65) if c.isalpha() else c for c in text.upper())
    print(f"ROT-{i:2d}: {decoded}")
```
```bash
# Quick ROT13:
echo "text" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

### Vigenère
```python
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = ''
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            if c.isupper():
                result += chr((ord(c) - 65 - shift) % 26 + 65)
            else:
                result += chr((ord(c) - 97 - shift) % 26 + 97)
            ki += 1
        else:
            result += c
    return result

# If key unknown -> use https://www.dcode.fr/vigenere-cipher
# Or Kasiski examination to find key length
```

### Substitution Cipher
```bash
# Use: https://quipqiup.com/ (auto-solves substitution ciphers)
# Or:  https://www.dcode.fr/monoalphabetic-substitution
```

### Rail Fence
```python
def rail_fence_decrypt(cipher, num_rails):
    fence = [[None] * len(cipher) for _ in range(num_rails)]
    rails = list(range(num_rails)) + list(range(num_rails - 2, 0, -1))
    pattern = [rails[i % len(rails)] for i in range(len(cipher))]
    
    idx = 0
    for rail in range(num_rails):
        for i in range(len(cipher)):
            if pattern[i] == rail:
                fence[rail][i] = cipher[idx]
                idx += 1
    
    return ''.join(fence[pattern[i]][i] for i in range(len(cipher)))

# Brute force rails:
for r in range(2, 10):
    print(f"Rails={r}: {rail_fence_decrypt(ciphertext, r)}")
```

### Other classical (use dCode)
| Cipher | URL |
|--------|-----|
| Atbash | https://www.dcode.fr/atbash-cipher |
| Bacon | https://www.dcode.fr/bacon-cipher |
| Playfair | https://www.dcode.fr/playfair-cipher |
| Affine | https://www.dcode.fr/affine-cipher |
| Beaufort | https://www.dcode.fr/beaufort-cipher |
| Polybius | https://www.dcode.fr/polybius-cipher |

---

## rsa

### common rsa attacks

#### Given: n, e, c (standard)
```python
from Crypto.Util.number import long_to_bytes, inverse

n = 0x...  # modulus
e = 65537  # public exponent
c = 0x...  # ciphertext

# If you can factor n:
p = ...
q = ...
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

#### Small e, no padding (cube root attack)
```python
import gmpy2
# If e=3 and m^3 < n, just take cube root
m = gmpy2.iroot(c, e)[0]
print(long_to_bytes(int(m)))
```

#### Wiener's Attack (small d, large e)
```python
# pip install owiener
import owiener
d = owiener.attack(e, n)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

#### Hastad's Broadcast Attack (same m, small e, multiple n)
```python
# e=3, same message encrypted with 3 different n values
from sympy.ntheory.residues import nthroot_mod
import gmpy2
from functools import reduce

def chinese_remainder(n, a):
    total = 0
    prod = reduce(lambda x, y: x * y, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        total += a_i * inverse(p, n_i) * p
    return total % prod

# n_list = [n1, n2, n3], c_list = [c1, c2, c3]
x = chinese_remainder(n_list, c_list)
m = gmpy2.iroot(x, e)[0]
print(long_to_bytes(int(m)))
```

#### Common modulus attack (same n, different e, same m)
```python
# Two ciphertexts: c1 = m^e1 mod n, c2 = m^e2 mod n
# If gcd(e1, e2) == 1:
from Crypto.Util.number import inverse, long_to_bytes
import gmpy2

def gcd_extended(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = gcd_extended(b % a, a)
    return g, y - (b // a) * x, x

g, a, b = gcd_extended(e1, e2)
# m = c1^a * c2^b mod n
if a < 0:
    c1 = inverse(c1, n)
    a = -a
if b < 0:
    c2 = inverse(c2, n)
    b = -b
m = (pow(c1, a, n) * pow(c2, b, n)) % n
print(long_to_bytes(m))
```

#### Factor n online
```bash
# factordb.com — paste n, check if it's been factored
# http://factordb.com/
```

#### RsaCtfTool (all-in-one)
```bash
# https://github.com/RsaCtfTool/RsaCtfTool
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile cipher.txt
python3 RsaCtfTool.py -n <N> -e <e> --uncipher <c>
```

---

## aes / block ciphers

### ecb detection
```python
# ECB: same plaintext block -> same ciphertext block
# Check for repeated 16-byte blocks:
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
if len(blocks) != len(set(blocks)):
    print("ECB mode detected!")
```

### ecb byte-at-a-time
```python
# Classic ECB oracle attack:
# 1. Find block size (send increasing A's until output jumps)
# 2. Confirm ECB (send 2 blocks of same byte, check duplicate output)
# 3. Decrypt byte-by-byte:
#    - Send AAA...A (blocksize-1 known + 1 unknown)
#    - Build dictionary: encrypt(AAA...A + each_byte)
#    - Match output to dictionary
```

### cbc bit-flipping
```python
# Flip bit in ciphertext block N -> flips corresponding bit in plaintext block N+1
# XOR the byte you want to change:
# new_ct[offset] = ct[offset] ^ old_byte ^ new_byte
ct = bytearray(ciphertext)
target_offset = block_size * target_block + byte_position
ct[target_offset] ^= ord('old_char') ^ ord('new_char')
```

### cbc padding oracle
```python
# If server tells you "padding error" vs "decryption error":
# Use padding oracle to decrypt without the key
# Tool: https://github.com/AonCyberLabs/PadBuster
# padBuster.pl <URL> <ciphertext> <block_size>

# Or use the aes_decrypt.py template in rev/templates/
```

---

## xor

```python
# Single-byte XOR brute force
for key in range(256):
    decoded = bytes([b ^ key for b in ciphertext])
    if b'flag' in decoded or b'inctf' in decoded:
        print(f"Key: {key} -> {decoded}")

# Multi-byte XOR with known plaintext
key = bytes([c ^ p for c, p in zip(ciphertext, known_plaintext)])
print(f"Key: {key}")

# Repeating XOR
from itertools import cycle
def xor_decrypt(ct, key):
    return bytes([c ^ k for c, k in zip(ct, cycle(key))])
```

See also: [xor_decrypt.py](../rev/templates/xor_decrypt.py) in rev templates.

---

## diffie-hellman

### discrete log (small params)
```python
from sympy.ntheory.residues import discrete_log

# Given: g, p, A = g^a mod p
# Find: a
a = discrete_log(p, A, g)
shared_secret = pow(B, a, p)
```

### baby-step giant-step
```python
import math

def bsgs(g, h, p):
    """Baby-step Giant-step for discrete log: g^x = h (mod p)"""
    m = math.ceil(math.sqrt(p))
    table = {}
    power = 1
    for j in range(m):
        table[power] = j
        power = (power * g) % p
    
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * factor) % p
    return None
```

---

## useful tools

| Tool | What | Install/URL |
|------|------|------------|
| **CyberChef** | Decode/encode anything | https://gchq.github.io/CyberChef/ |
| **dCode** | Identify + decrypt ciphers | https://www.dcode.fr/en |
| **RsaCtfTool** | Auto RSA attacks | https://github.com/RsaCtfTool/RsaCtfTool |
| **factordb** | Factor large numbers | http://factordb.com/ |
| **CrackStation** | Hash lookup | https://crackstation.net/ |
| **hashcat** | GPU hash cracking | `hashcat -m 0 hash.txt rockyou.txt` |
| **john** | CPU hash cracking | `john --wordlist=rockyou.txt hash.txt` |
| **hash-identifier** | Identify hash type | `hash-identifier` or `hashid` |
| **sage** | Math/crypto library | `from sage.all import *` |
| **pycryptodome** | Python crypto | `pip install pycryptodome` |

## decision tree
```
Got crypto?
├- Looks like English but scrambled -> classical cipher -> dCode / quipqiup
├- Given n, e, c -> RSA -> try factordb -> RsaCtfTool
├- Hex/base64 blob -> AES? -> check mode (ECB repeats?)
├- XOR? -> xor_decrypt.py -> brute force / known plaintext
├- Hash? -> CrackStation -> hashcat/john
└- Math puzzle? -> sage / Z3 / sympy
```
