# Cryptography and Challenge Library Learning Intro
# PicoCTF Cryptography & Multi-Layer Deobfuscation Analysis

## Header / Title
* **Challenge Names:** `caesar`, `interencdec`, `New Caesar`
* **Platform:** PicoCTF / CyLab Security Academy
* **Categories:** Cryptography, Reverse Engineering, Obfuscation
* **Difficulty Tier:** Easy to Medium
* **Analyst:** Daniel (Systems Engineering Student & Aspiring DFIR/SOC Analyst)

---

## Executive Summary
This write-up documents the technical analysis and reversal of three cryptography and payload obfuscation challenges. The core investigation focused on deconstructing classical shift ciphers, stripping nested Base64 transport encodings, and reverse-engineering a custom nibble-based Base16 substitution algorithm using Python. All payloads were recovered locally without relying on third-party online decoders to maintain data isolation and analytical rigour.

---

## Tools & Environment Used
* **Python 3.x:** Developed custom reversal scripts, bitwise shifting routines, and modular arithmetic decoders.
* **Linux Terminal Utilities:** Used native utilities (`base64 -d`, `xxd`) for binary representation and payload stripping.
* **Standard Python Libraries (`string`, `base64`):** Leveraged for ASCII table mapping and character set filtering.

---

## Step-by-Step Investigation / Methodology

### 1. Lab: `caesar` (Substitution Shift Analysis)
* **Objective:** Decrypt a classic Caesar rotation cipher applied exclusively to the flag payload inside a static wrapper.
* **Execution:** Analysis of the string `picoCTF{dspttjohuifsvcjdpohatwvibg}` showed that the `picoCTF{}` prefix was unshifted. Calculating the distance between the first ciphertext character `d` (ASCII 100) and expected plaintext character `c` (ASCII 99) established a key shift offset of $k = 25$ (or $-1$).

$$\text{Shift Offset: } k = (100 - 99) \pmod{26} = 1 \implies \text{Decrypt Shift: } 25$$

Applying a $-25$ modular shift across all internal characters successfully yielded the plaintext payload.

### 2. Lab: `interencdec` (Nested Transport Encoding Stripping)
* **Objective:** Identify, isolate, and remove multi-layered Base64 wrappers before applying a shift cipher rotation.
* **Execution:**
  1. **Layer 1 Decoding:** Executed Base64 decoding on the raw string `YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==`, which produced a string-formatted Python bytes object: `b'd3BqZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0='`.
  2. **Layer 2 Envelope Removal:** Stripped the literal `b'...'` byte wrapper from the payload to avoid invalid padding errors, then passed the inner string through a second Base64 decode pass, producing: `wpjdkpBTX{qaGx6aHl_k3jy9wa3k_78250hmj}`.
  3. **Layer 3 Caesar Rotation:** Analyzed character offsets and applied a ROT-19 shift to map the scrambled alpha characters back into readable English text.

### 3. Lab: `New Caesar` (Custom Base16 & Keyed Modular Addition)
* **Objective:** Reverse-engineer a custom two-stage cipher featuring 4-bit nibble splitting and modular addition over a restricted 16-character alphabet.
* **Algorithm Deconstruction:**
  * **Custom Base16 Encoding:** Each 8-bit ASCII character was split into two 4-bit nibbles (upper and lower), mapped to `ALPHABET = "abcdefghijklmnop"`.
  * **Modular Addition:** Each character was shifted using a single-character key $k \in \text{ALPHABET}$:

$$c_i = (p_i + k_i) \pmod{16}$$

* **Reversal Script Logic:** A custom Python script was engineered to invert the shift through modular subtraction, reconstruct 8-bit integers via bitwise left-shifts (`(val1 << 4) + val2`), and iterate across all 16 candidate keys while filtering for printable ASCII output.

```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]
cipher_text = "fegdeogdgecoeocgcgchcfcffccfca"

def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]

def b16_decode(b16_str):
    dec = ""
    for i in range(0, len(b16_str), 2):
        val1 = ALPHABET.index(b16_str[i])
        val2 = ALPHABET.index(b16_str[i+1])
        byte_value = (val1 << 4) + val2
        dec += chr(byte_value)
    return dec
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
