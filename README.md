# challenge_HacktheBox

Writeup / tooling for the HackTheBox challenge that demonstrates insecure RSA/AES bootstrap choices. The repository contains example key-generation scripts that choose neighbouring primes and use weak RNGs. This README explains the flaws, lists the files, and shows how to reproduce and exploit the vulnerability to recover the pre-shared secret.

Summary
- The RSA generator picks p with a prime generator then chooses q as a nearby prime (within ±10). That makes n = p*q trivially factorable by searching a small window around sqrt(n).
- The codebase contains Python scripts (legacy Python2 style) that illustrate the vulnerable behavior and an email message with a public key and an encrypted decimal message which you can decrypt once you factor n.
- This repo is a CTF/HackTheBox challenge — expected flag format: HTB{flag}.

Files of interest
- `fastprimes.py` / `AESbootstrap.py` — (same content) example RSA generation that:
  - generates a prime p via Crypto.Util.number.getPrime(512)
  - looks for q in [p-10, p+10] using sympy.isprime
  - prints/export keys and attempts to encrypt a message
  - NOTE: code is Python2-style and contains placeholders; do not run unmodified on production systems.
- `Email.txt` — challenge email with a public key PEM and an encrypted message (decimal).
- `description.txt` — short challenge description.

Why this is insecure (technical)
- q chosen as a small offset from p (q ≈ p ± k, small k): if |p − q| <= B and B is small (here 10), then given n you can factor n by checking only O(B) candidates around sqrt(n). This makes factoring trivial even for 1024‑bit modulus.
- Weak RNG warning (email): a custom PRNG was introduced (Mersenne Twister derived), which if used to generate secret material can further weaken key entropy.
- A typical secure RSA key requires p and q to be random, independent large primes; selecting q deterministically near p removes that independence and makes n factorable in negligible time.

What you need (dependencies)
- Python 3.8+ (we will use Python 3 for exploit scripts)
- pip packages:
  - sympy (optional for primality checks)
  - pycryptodome (optional to import PEM and work with RSA objects)
Install:
```
python3 -m venv .venv
source .venv/bin/activate
pip install sympy pycryptodome
```

Notes on the repository scripts
- The included `fastprimes.py` / `AESbootstrap.py` is written with Python2 idioms (print statements, long() usage). You can:
  - run them under Python 2.7 (not recommended) or
  - port them to Python 3 by replacing `long(...)` with `int(...)`, converting prints to functions, and fixing other small syntax bits.
- You do not need to run these scripts to solve the challenge — the weaknesses can be exploited from the public key and ciphertext in `Email.txt`.

Exploit example — factor the vulnerable modulus and decrypt the message
Below is a minimal Python 3 script that:
1. loads the public key PEM (from `Email.txt` or saved `pub.pem`),
2. reads the decimal ciphertext,
3. factors n by scanning a small window around floor(sqrt(n)),
4. computes the private exponent d and recovers the plaintext.

Save as `exploit_decrypt.py`:

```python
#!/usr/bin/env python3
import math
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from pathlib import Path

# Configuration: set filenames or paste values directly
PUB_PEM = "pub.pem"          # save the PEM block (BEGIN PUBLIC KEY...END PUBLIC KEY) to this file
CIPHERTEXT_FILE = "cipher.txt"  # file containing the decimal ciphertext from Email.txt (only digits)

# Read public key
key = RSA.import_key(open(PUB_PEM, "rb").read())
n = key.n
e = key.e
print(f"Loaded public key: n (bits)={n.bit_length()}, e={e}")

# Read ciphertext (decimal)
c = int(open(CIPHERTEXT_FILE, "r").read().strip())

# Fast factor around sqrt(n). The vulnerable scripts pick q within ±10 of p,
# so scanning a small window should find a divisor quickly.
s = math.isqrt(n)
print(f"sqrt(n) ≈ {s}")

found = False
# window size: try ±2000 by default (10 is enough for this repo, but be conservative)
for delta in range(-2000, 2001):
    p_candidate = s + delta
    if p_candidate <= 1:
        continue
    if n % p_candidate == 0:
        p = p_candidate
        q = n // p
        found = True
        print(f"Found factors: p={p} (bits={p.bit_length()}), q={q} (bits={q.bit_length()})")
        break

if not found:
    raise SystemExit("No factor found in window; increase window size or use a different method")

# compute private exponent d
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)   # Python 3.8+: modular inverse
m = pow(c, d, n)

# Convert to bytes and print
plaintext_bytes = long_to_bytes(m)
try:
    plaintext = plaintext_bytes.decode()
    print("Recovered plaintext (utf-8):")
    print(plaintext)
except UnicodeDecodeError:
    print("Recovered plaintext (raw bytes):")
    print(plaintext_bytes.hex())
```

Usage (example)
1. Extract the public key PEM from `Email.txt` and save as `pub.pem`. Extract the large decimal "MESSAGE" block and save as `cipher.txt` (only the digits).
2. Run:
```
python3 exploit_decrypt.py
```
If p and q are close (as in the vulnerable generator), the script will factor n almost instantaneously and show the recovered plaintext. The decrypted plaintext should contain the pre-shared AES seed or the CTF flag (HTB{...}).

Alternative factoring approach (pure math)
- If q = p ± k then p ≈ sqrt(n). Use that observation:
  - Let a = ceil(sqrt(n))
  - Check whether a^2 - n is a perfect square: if yes, then p = a - b, q = a + b where b^2 = a^2 - n
  - This is Fermat factorization and is extremely efficient when p and q are close.

Security lessons (concise)
- Never pick q deterministically near p. Ensure primes are generated independently and uniformly from strong CSPRNGs.
- Never implement your own PRNG for cryptographic use (Mersenne Twister is not cryptographically secure).
- Never transmit sensitive private keys or secrets via insecure channels.
- If you inherit a suspicious generator (vendor code or scripts), audit for tiny offsets, repeated seeds, or low entropy sources.

Appendix — quick tips
- If the factoring window above fails, try:
  - increase the `delta` range in the exploit script,
  - test Fermat factorization directly: search for a such that a^2 − n is a perfect square,
  - or run ECM/MPQS tools (not necessary here).
- You can also parse the email directly and run the exploit without manual copy/paste by scripting PEM/cipher extraction from `Email.txt`.

Status
- Educational / CTF challenge. The code demonstrates insecure RSA generation patterns and is intentionally vulnerable.

Author / Contact
- Nani-Des — https://github.com/Nani-Des
