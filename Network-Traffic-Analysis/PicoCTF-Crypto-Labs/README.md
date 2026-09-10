# PicoCTF: Cryptography & Multi-Layer Deobfuscation Analysis

**Platform:** PicoCTF / CyLab Security Academy  
**Category:** Cryptography & Obfuscation  
**Difficulty:** Easy to Medium  
**Author:** Daniel  

## Overview
Technical analysis and reversal of three cryptography and payload obfuscation challenges (`caesar`, `interencdec`, and `New Caesar`). The investigation covers classical rotation ciphers, nested Base64 transport encoding, and custom 4-bit nibble substitution in Python.

## Environment & Tools
* **Python 3:** Custom reversal scripts and modular arithmetic.
* **Linux Utilities:** Native CLI tools (`base64`, `xxd`).

## Technical Walkthrough

### 1. Caesar (Substitution Shift)
Analysis of `picoCTF{dspttjohuifsvcjdpohatwvibg}` confirmed an unshifted prefix. Comparing the first ciphertext letter `d` (ASCII 100) to expected plaintext `c` (ASCII 99) established a shift key of $k = 1$.

Applying a shift offset of $-25$ across internal characters yielded the flag:
`picoCTF{crossingtherubicongzsvuhaf}`

### 2. Interencdec (Nested Base64 & ROT-19)
1. **Layer 1:** Decoded the raw string `YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==` to reveal a byte string envelope: `b'd3BqZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0='`.
2. **Layer 2:** Stripped the `b'...'` wrapper and decoded the inner Base64 string to obtain `wpjdkpBTX{qaGx6aHl_k3jy9wa3k_78250hmj}`.
3. **Layer 3:** Applied a ROT-19 rotation cipher to recover the final plaintext:
`picoCTF{caesar_d3cr9pt3d_78250afc}`

### 3. New Caesar (Custom Base16 & Keyed Addition)
The challenge implements custom Base16 encoding (splitting 8-bit bytes into two 4-bit nibbles mapped to `abcdefghijklmnop`) followed by modular addition using a single-character key.

Reversal script to brute-force all 16 alphabet key candidates and filter printable ASCII:
```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]
cipher_text = "fegdeogdgecoeocgcgchcfcffccfca"

# Revertimos la adicion modular unshift
def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]

# Convertimos parejas de Base16 a ASCII
def b16_decode(b16_str):
    dec = ""
    # Un for para recorrer la cadena en pares
    for i in range(0, len(b16_str), 2):
        # Tomamos la pareja de letras
        c1 = b16_str[i]
        c2 = b16_str[i+1]
        
        # Obtenemos su valor numérico dentro del alfabeto
        val1 = ALPHABET.index(c1)
        val2 = ALPHABET.index(c2)
        
        # Unimos los 4 bits superiores (val1) y los 4 bits inferiores (val2)
        byte_value = (val1 << 4) + val2
        
        # Convertimos el número a su carácter ASCII correspondiente
        dec += chr(byte_value)
    return dec

# Brute Force en los 16 candidatos
for key in ALPHABET:
    # Invertimos el shift en toda la cadena
    b16_plain = ""
    for char in cipher_text:
        b16_plain += unshift(char, key)
    
    # De Base16 a texto ASCII
    try:
        possible_flag = b16_decode(b16_plain)
        print(f"Key '{key}': picoCTF{{{possible_flag}}}")
    except Exception:
        continue
```
# Exhaustive search across all 16 key candidates in ALPHABET
for key in ALPHABET:
    b16_plain = "".join([unshift(char, key) for char in cipher_text])
    try:
        possible_flag = b16_decode(b16_plain)
        # Filter printable ASCII range (decimal 32-126)
        if all(32 <= ord(c) <= 126 for c in possible_flag):
            print(f"[+] Recovered Candidate (Key '{key}'): picoCTF{{{possible_flag}}}")
    except Exception:
        continue

## Identified IOCs & Artifacts

| Challenge Name | Raw Input / Ciphertext Payload | Applied Parameter / Derived Key | Recovered Flag |
| :--- | :--- | :--- | :--- |
| **caesar** | `picoCTF{dspttjohuifsvcjdpohatwvibg}` | Shift Offset = $25$ | `picoCTF{crossingtherubicongzsvuhaf}` |
| **interencdec** | `YidkM0JxZGtwQlRYdHFhR...==` | Base64 (x2) + ROT-19 | `picoCTF{caesar_d3cr9pt3d_78250afc}` |
| **New Caesar** | `fegdeogdgecoeocgcgchcfcffccfca` | Key Candidate = `'p'` | `picoCTF{et_tu?_77866c61}` |

---

## Mitigation & Lessons Learned
* **Encoding vs. Encryption Boundaries:** Base64 and custom Base16 are deterministic data representation formats designed for transport compatibility, not confidentiality. SOC detection mechanisms must recognize that encoding layers offer zero protection against payload inspection.
* **Anomalous ASCII Distribution Monitoring:** In DFIR investigations, non-printable characters or unusual byte value distributions (outside standard ASCII ranges $32\text{--}126$) within text fields often indicate obfuscated payloads, custom binary encoders, or corrupted execution strings.
* **Integrity Control During Analysis:** Prior to running custom decoders or altering raw evidence, analysts should maintain Chain of Custody standards by computing SHA-256 hashes of original artifacts to ensure forensic data integrity.
