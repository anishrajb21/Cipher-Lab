# Basic Encryption & Decryption (Caesar Cipher)
### Industrial Training / Cybersecurity Internship — Project 2
**Language:** Python 3 — standard library only, no external packages

---

## 1. Files in this project

| File | Purpose |
|---|---|
| `encryption_decryption.py` | The complete program |
| `test_encryption.py` | 34 automated test cases |
| `index.html` | Interactive browser-based cipher lab |
| `README.md` | This report |

**How to run:**

```bash
python encryption_decryption.py          # interactive menu
python encryption_decryption.py --test   # runs the built-in worked examples
python test_encryption.py                # runs all 34 test cases
```

### Open the web interface

Open `index.html` in a current web browser. It runs locally without a server or third-party packages. Choose Caesar or Vigenère, enter a message and key, and the actual cipher result and letter-frequency chart update as you type. Live analytics show character, word, letter, and unique-letter counts. The Caesar brute-force view calculates all 25 possible decryptions. Copy and save controls act on the calculated result; clipboard access depends on your browser's permissions.

The web interface and command-line program both demonstrate classical ciphers for learning only. Neither should be used to protect sensitive information.

---

## 2. Short explanation of the project

The program demonstrates **reversible cryptography**: the idea that a message can be scrambled into an unreadable form and then perfectly restored using the same key.

The user types a message and a shift key. The program encrypts the message, decrypts it again, displays both results, and then automatically compares the decrypted text with the original to confirm the round trip worked. A menu offers six options:

1. Encrypt and decrypt with automatic verification (the main demonstration)
2. Encrypt only
3. Decrypt only
4. Vigenère cipher — the advanced keyword-based version
5. Brute-force attack — cracks a message without knowing the key
6. Run the built-in test cases

Everything is written with plain loops, `ord()` and `chr()`, so the actual shifting logic is visible in the code rather than hidden inside an imported library.

---

## 3. Explanation of the Caesar cipher

The Caesar cipher is named after Julius Caesar, who reportedly used it around 58 BC to send military orders. It is one of the oldest recorded encryption methods.

The rule is simple: **replace every letter with the letter a fixed number of places further along the alphabet.**

With a shift of 3:

```
Plain  : A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Cipher : D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
```

So `HELLO` becomes `KHOOR`:

| Letter | Position | + 3 | New letter |
|---|---|---|---|
| H | 7 | 10 | K |
| E | 4 | 7 | H |
| L | 11 | 14 | O |
| L | 11 | 14 | O |
| O | 14 | 17 | R |

Notice the cipher row wraps around at the end: X, Y and Z loop back to A, B and C. In the code this wrapping is done with the modulo operator `% 26`, which gives the remainder after dividing by 26. Position 27 becomes position 1, so `Z` shifted by 2 correctly becomes `B` instead of running off the end of the alphabet.

**How the code shifts one character** (`shift_character()`), using `H` and a shift of 3:

1. `ord('H')` is 72; `ord('A')` is 65
2. `72 − 65 = 7`, so H sits at alphabet position 7 (A = 0)
3. `7 + 3 = 10`
4. `10 % 26 = 10` (the wrap-around step)
5. `10 + 65 = 75`, and `chr(75)` is `K`

Uppercase and lowercase are handled by separate branches using their own base values (`A` = 65, `a` = 97), so `AbCd` stays mixed-case after encryption. Anything that is not an English letter — spaces, digits, punctuation, accented characters — is returned unchanged, which preserves the layout of the message.

---

## 4. Explanation of encryption and decryption

**Encryption** converts readable **plaintext** into scrambled **ciphertext** so that anyone who intercepts it cannot understand it. **Decryption** is the reverse process, turning ciphertext back into plaintext.

Both operations need a **key**. In this project the key is the shift number. Because the same key is used to lock and unlock the message, this is called **symmetric encryption** — the same family that modern AES belongs to, even though AES is vastly more complex.

The neat part of the implementation is that decryption needed almost no new code:

```python
def decrypt_text(ciphertext, shift):
    return "".join(shift_character(c, -shift) for c in ciphertext)
```

Decrypting is just encrypting with a **negative** shift. If encryption moves every letter three places forward, decryption moves it three places back, landing exactly where it started. That is what "reversible" means, and it is why `decrypt_text(encrypt_text(message, 3), 3)` always returns the original message.

**Without the key, the ciphertext is meaningless** — that is the property called **confidentiality**.

---

## 5. Explanation of the shift-key mechanism

The shift key is the number of positions each letter moves. It is the secret that must be shared between sender and receiver.

| Key | `HELLO` becomes |
|---|---|
| 1 | IFMMP |
| 3 | KHOOR |
| 13 | URYYB |
| 25 | GDKKN |

Three important properties, all enforced by `validate_shift()`:

- **A shift of 0 or 26 does nothing.** Shifting 26 places returns every letter to itself, so the "ciphertext" equals the plaintext. The program rejects these keys with a clear error rather than silently producing an unencrypted message.
- **Keys wrap around.** A shift of 29 is identical to a shift of 3 (`29 % 26 = 3`), and −3 is identical to 23. The program accepts these and wraps them into the 1–25 range instead of crashing.
- **There are only 25 useful keys in total.** This is the cipher's fatal weakness, covered in section 9.

A shift of **13** is a special case known as **ROT13**. Since 13 is exactly half of 26, applying it twice returns the original text — encryption and decryption are the same operation. There is a test case covering this.

---

## 6. Example input and output

### Main demonstration (menu option 1)

```
==================================================
 ENCRYPT AND DECRYPT (full demonstration)
==================================================
Enter your message: Cyber Security 2025!
Enter shift key (1-25): 5

==================================================
 RESULT
==================================================
 Original Text  : Cyber Security 2025!
 Shift Key Used : 5
 Encrypted Text : Hdgjw Xjhzwnyd 2025!
 Decrypted Text : Cyber Security 2025!
--------------------------------------------------
 Verification   : SUCCESS
                  Decryption successful - original message restored.
==================================================
```

Note how the digits `2025`, the exclamation mark and the space survived untouched, and the capital `C` and `S` stayed capital.

### Input validation

```
Enter your message:
  ! No message entered. Please type something.
Enter your message: Cyber Security 2025!
Enter shift key (1-25): abc
  ! 'abc' is not a whole number. Please enter a number from 1 to 25.
Enter shift key (1-25): 0
  ! A shift of 0 (or 26) would leave the message unchanged. Please enter a number from 1 to 25.
Enter shift key (1-25): 5
```

The program loops until it gets valid input instead of crashing with a `ValueError`.

### Vigenère cipher (menu option 4)

```
 Original Text  : Meet me at the gate, 9pm!
 Keyword Used   : LEMON
 Encrypted Text : Xiqh zp ef hup kmhr, 9aq!
 Decrypted Text : Meet me at the gate, 9pm!
 Verification   : SUCCESS - original message restored.
```

### Brute-force attack (menu option 5)

```
Enter the encrypted text: KHOOR
  Key  1 -> JGNNQ
  Key  2 -> IFMMP
  Key  3 -> HELLO      <-- readable English, so the key was 3
  Key  4 -> GDKKN
  Key  5 -> FCJJM
  ...
```

No password and no special tools were needed — just 25 guesses.

---

## 7. Test cases

`test_encryption.py` contains **34 tests, all passing**.

### Test case 1 — the classic example

| Input | Key | Expected ciphertext | Decrypts back to |
|---|---|---|---|
| `HELLO` | 3 | `KHOOR` | `HELLO` |

Verifies the textbook example from the project brief works exactly as specified.

### Test case 2 — mixed characters

| Input | Key | Expected ciphertext |
|---|---|---|
| `Cyber Security 2025!` | 5 | `Hdgjw Xjhzwnyd 2025!` |

Verifies that uppercase stays uppercase, lowercase stays lowercase, and digits, spaces and punctuation pass through unchanged.

### Test case 3 — wrap-around

| Input | Key | Expected ciphertext |
|---|---|---|
| `Zebra` | 1 | `Afcsb` |

Verifies that `Z + 1` loops back to `A` instead of producing the character after Z. A second test confirms `A − 1` wraps backwards to `Z`.

### Test case 4 — every key works

`The Quick Brown Fox, 99!` is encrypted and decrypted with all 25 keys in a loop, and must match the original every time. A companion test confirms that decrypting with the **wrong** key does *not* recover the message.

### Test case 5 — Vigenère

`HELLO` with the keyword `KEY` produces `RIJVS`. A further test confirms that the two `L`s in `HELLO` encrypt to *different* letters, which is the specific advantage Vigenère has over Caesar.

### Test case 6 — input validation

Text keys (`abc`), decimals (`3.5`), empty input, `0` and `26` are all rejected. Out-of-range keys wrap correctly: `29 → 3`, `-3 → 23`. Surrounding spaces (`  7  `) are tolerated.

### Test case 7 — edge cases

A message with no letters (`12345 !@#`) comes back unchanged; a single character works; a 1,600-character message round-trips correctly; accented characters such as `é` pass through untouched rather than being mangled.

---

## 8. Cybersecurity concepts demonstrated

**Confidentiality.** One of the three pillars of the CIA triad (Confidentiality, Integrity, Availability). Encryption is the primary technical control that keeps data readable only by authorised parties.

**Plaintext, ciphertext and key.** The vocabulary used in every cryptographic system, from a Roman cipher to TLS on a banking website.

**Symmetric encryption.** The same key encrypts and decrypts. AES-256 works on this same principle, which raises the real-world problem of **key distribution**: how do you get the key to the recipient without an attacker intercepting it? That problem is what led to public-key cryptography.

**Reversible transformation.** Encryption must be perfectly reversible, which is what distinguishes it from **hashing**. A password check (Project 1) uses hashing because it is *deliberately* one-way; a message you need to read again later requires encryption.

**Kerckhoffs's principle.** A cryptosystem should stay secure even if everyone knows how the algorithm works — only the *key* should be secret. This program publishes its algorithm openly and still works, which is correct design. A system that depends on nobody knowing how it works is relying on "security through obscurity", which always fails eventually.

**Keyspace and brute-force attacks.** The keyspace is the total number of possible keys. Caesar has 25; AES-256 has 2²⁵⁶. The brute-force demonstration in the program shows in practice why keyspace size determines whether a cipher survives attack.

**Cryptanalysis.** The brute-force option is a working attack tool, not just theory. Understanding how ciphers break is as much a part of security work as building them.

**Input validation and fail-safe behaviour.** Every user input is validated before use. The program also refuses a shift of 0 rather than silently handing back an unencrypted message — failing loudly is safer than failing quietly.

---

## 9. Limitations of the Caesar cipher

**The Caesar cipher is a teaching tool. It is not secure and must never be used to protect real sensitive information.**

1. **Tiny keyspace.** Only 25 usable keys exist. A computer tries all of them in well under a millisecond. Menu option 5 demonstrates this attack in full. Any cipher that can be exhaustively searched is broken by definition.

2. **Frequency analysis.** Each plaintext letter always maps to the same ciphertext letter, so the statistical fingerprint of the language survives encryption. `E` is the most common letter in English, so the most common letter in the ciphertext is very likely to be the encrypted `E`. Arab mathematician al-Kindi described this attack in the 9th century — the cipher has been broken for over a thousand years.

3. **No integrity protection.** An attacker can alter the ciphertext in transit and the recipient has no way to detect it. Modern systems add a MAC or use authenticated encryption (AES-GCM) to catch tampering.

4. **Known-plaintext weakness.** If an attacker learns even one plaintext/ciphertext letter pair, the key is immediately revealed and the entire message falls.

5. **Deterministic output.** The same message and key always produce identical ciphertext. Real systems add a random IV or nonce so that encrypting the same message twice yields different results.

6. **Letters only.** Digits and symbols are not encrypted at all, so `2025` stays visible in the ciphertext and can leak meaningful information.

The Vigenère cipher fixes limitation 2 to a degree, since a repeating keyword flattens the letter frequencies — but it too was broken in the 19th century by the Kasiski examination, which finds the keyword length and then treats the message as several interleaved Caesar ciphers. **Neither cipher offers real security today.**

**For real data, use vetted modern algorithms — AES-256 for symmetric encryption, RSA or elliptic-curve cryptography for key exchange — through a reviewed library, never a hand-written implementation.**

---

## 10. Suggestions for future improvements

1. **Automatic frequency-analysis cracking.** Extend the brute-force option to score each of the 25 candidates against English letter frequencies and report the most likely key automatically, with no human reading required.
2. **Break the Vigenère cipher** using the Kasiski examination or the index of coincidence, to show that the advanced version is also defeatable.
3. **Add more classical ciphers** — Atbash, the Rail Fence transposition cipher, and the Playfair digraph cipher — for comparison.
4. **Implement AES-256 properly** using Python's `cryptography` library, alongside the Caesar version, so the difference between a toy cipher and a real one is visible side by side.
5. **Implement a one-time pad** to demonstrate the only cipher with proven perfect secrecy, and show why its key-management requirements make it impractical.
6. **Key derivation from a passphrase** using PBKDF2 or Argon2, which links this project back to Project 1's password work.
7. **File encryption** so whole text files can be processed, not just typed messages.
8. **Add an integrity check** with an HMAC, so tampering with the ciphertext is detected on decryption.
9. **A graphical interface** (Tkinter or a small Flask app) showing the alphabet sliding as the shift key changes, which makes the mechanism visually obvious.
10. **Support the full Unicode range** so messages in Hindi, Kannada or other scripts can be encrypted rather than passed through unchanged.
