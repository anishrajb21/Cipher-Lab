"""
=============================================================================
 BASIC ENCRYPTION & DECRYPTION (CAESAR CIPHER)
 Industrial Training / Cybersecurity Internship - Project 2
=============================================================================

 What this program does
 ----------------------
 It takes a message and a shift key from the user, encrypts the message with
 a Caesar cipher, decrypts it again with the same key, and proves that the
 decrypted text matches what was originally typed.

 It also includes a Vigenere cipher (an advanced version that uses a keyword
 instead of a single number) and a brute-force cracker that demonstrates
 exactly why the Caesar cipher is not safe for real data.

 IMPORTANT SECURITY NOTE
 -----------------------
 The Caesar cipher is a LEARNING TOOL, not real protection. It has only 25
 possible keys and a computer can try all of them instantly. Never use it
 for passwords, personal data, or anything that actually needs to be secret.
 Real systems use algorithms such as AES-256 or RSA.

 Run it with:  python encryption_decryption.py
=============================================================================
"""

import sys


# ---------------------------------------------------------------------------
# SECTION 1: CONFIGURATION
# ---------------------------------------------------------------------------

ALPHABET_SIZE = 26          # there are 26 letters in the English alphabet
UPPERCASE_A = ord("A")      # ASCII code 65
LOWERCASE_A = ord("a")      # ASCII code 97
LINE = "=" * 50


# ---------------------------------------------------------------------------
# SECTION 2: THE CORE CAESAR CIPHER LOGIC
#
# The whole cipher rests on one idea: move each letter forward along the
# alphabet by a fixed number of places. 'A' shifted by 3 becomes 'D'.
# To undo it, move backwards by the same number. 'D' shifted by -3 is 'A'.
# ---------------------------------------------------------------------------

def shift_character(character, shift):
    """
    Shift ONE character along the alphabet and return the result.

    Non-letters (spaces, digits, punctuation) are returned unchanged, so
    the shape of the message is preserved.

    How it works, step by step, using 'H' with a shift of 3:

      1. ord('H') is 72, and ord('A') is 65.
      2. 72 - 65 = 7, so 'H' is at alphabet position 7 (A=0, B=1, ...).
      3. 7 + 3 = 10.
      4. 10 % 26 = 10. The % ("modulo") gives the remainder after dividing
         by 26, which makes the alphabet wrap around: position 27 becomes
         position 1, so 'Z' + 2 loops back to 'B' instead of falling off
         the end.
      5. 10 + 65 = 75, and chr(75) is 'K'.

    So 'H' with a shift of 3 becomes 'K'.
    """
    # Note the comparison style: "A" <= character <= "Z" checks that the
    # character is an English capital letter. We cannot use .isupper() here,
    # because Python also counts accented letters such as 'E' with an accent
    # as uppercase, and those sit outside the 26-letter alphabet our maths
    # assumes. Restricting to A-Z and a-z keeps the cipher correct.
    if "A" <= character <= "Z":
        position = ord(character) - UPPERCASE_A
        new_position = (position + shift) % ALPHABET_SIZE
        return chr(new_position + UPPERCASE_A)

    elif "a" <= character <= "z":
        position = ord(character) - LOWERCASE_A
        new_position = (position + shift) % ALPHABET_SIZE
        return chr(new_position + LOWERCASE_A)

    else:
        # Spaces, numbers, punctuation, symbols and any non-English letters
        # are left exactly as they are.
        return character


def encrypt_text(plaintext, shift):
    """
    Encrypt a whole message by shifting every letter FORWARD.

    plaintext -> ciphertext.  Example: encrypt_text("HELLO", 3) = "KHOOR"
    """
    ciphertext = ""
    for character in plaintext:
        ciphertext = ciphertext + shift_character(character, shift)
    return ciphertext


def decrypt_text(ciphertext, shift):
    """
    Decrypt a message by shifting every letter BACKWARD by the same amount.

    Decryption is simply encryption with a negative shift, which is what
    makes the Caesar cipher 'reversible' or 'symmetric': the same key both
    locks and unlocks the message.

    ciphertext -> plaintext.  Example: decrypt_text("KHOOR", 3) = "HELLO"
    """
    plaintext = ""
    for character in ciphertext:
        plaintext = plaintext + shift_character(character, -shift)
    return plaintext


# ---------------------------------------------------------------------------
# SECTION 3: VIGENERE CIPHER (optional advanced version)
#
# The Caesar cipher uses ONE shift for the entire message. The Vigenere
# cipher uses a keyword, where each letter of the keyword supplies its own
# shift: 'K' shifts by 10, 'E' by 4, 'Y' by 24, and so on, repeating the
# keyword across the message. The same plaintext letter can therefore turn
# into different ciphertext letters, which hides the letter-frequency
# patterns that make a Caesar cipher so easy to break.
# ---------------------------------------------------------------------------

def vigenere_process(text, keyword, direction):
    """
    Shared engine for the Vigenere cipher.
    direction = 1 encrypts, direction = -1 decrypts.

    Note that the keyword position only advances on LETTERS, so spaces and
    punctuation do not knock the keyword out of alignment.
    """
    result = ""
    keyword = keyword.lower()
    keyword_index = 0

    for character in text:
        if "A" <= character <= "Z" or "a" <= character <= "z":
            key_letter = keyword[keyword_index % len(keyword)]
            shift = ord(key_letter) - LOWERCASE_A
            result = result + shift_character(character, shift * direction)
            keyword_index = keyword_index + 1
        else:
            result = result + character

    return result


def vigenere_encrypt(plaintext, keyword):
    """Encrypt using a keyword instead of a single number."""
    return vigenere_process(plaintext, keyword, 1)


def vigenere_decrypt(ciphertext, keyword):
    """Decrypt using the same keyword."""
    return vigenere_process(ciphertext, keyword, -1)


# ---------------------------------------------------------------------------
# SECTION 4: BRUTE-FORCE ATTACK (why Caesar is not secure)
# ---------------------------------------------------------------------------

def brute_force_caesar(ciphertext):
    """
    Try every one of the 25 possible keys and return all the results.

    This is the entire 'attack' against a Caesar cipher. An attacker does
    not need the key, a password, or any special tool - they just read the
    25 outputs and pick the one that is English. That is why this cipher
    protects nothing.
    """
    attempts = []
    for possible_shift in range(1, ALPHABET_SIZE):
        attempts.append((possible_shift, decrypt_text(ciphertext, possible_shift)))
    return attempts


# ---------------------------------------------------------------------------
# SECTION 5: INPUT VALIDATION
# ---------------------------------------------------------------------------

def validate_message(message):
    """
    Check the message before using it.
    Returns an error message, or None if the input is acceptable.
    """
    if message is None or len(message) == 0:
        return "No message entered. Please type something."
    if message.strip() == "":
        return "A message of only spaces cannot be encrypted meaningfully."
    return None


def validate_shift(raw_input_value):
    """
    Turn the user's typed shift key into a usable number.

    Returns a pair: (shift_number, error_message).
    Exactly one of the two will be None.

    Rules:
      - must be a whole number (int), so "abc" and "3.5" are rejected
      - 0 is rejected, because shifting by 0 leaves the message unchanged
      - any other integer is accepted and wrapped into the range 1-25,
        because shifting by 29 gives the same result as shifting by 3
    """
    if raw_input_value is None or raw_input_value.strip() == "":
        return None, "No shift key entered. Please enter a number from 1 to 25."

    try:
        shift = int(raw_input_value.strip())
    except ValueError:
        return None, ("'" + raw_input_value.strip() + "' is not a whole number. "
                      "Please enter a number from 1 to 25.")

    shift = shift % ALPHABET_SIZE   # wraps 29 -> 3, and -3 -> 23

    if shift == 0:
        return None, ("A shift of 0 (or 26) would leave the message unchanged. "
                      "Please enter a number from 1 to 25.")

    return shift, None


def validate_keyword(keyword):
    """A Vigenere keyword must contain letters only."""
    if keyword is None or keyword.strip() == "":
        return "No keyword entered. Please type a word such as 'KEY'."
    if not keyword.isalpha():
        return "The keyword must contain letters only (no spaces or numbers)."
    return None


# ---------------------------------------------------------------------------
# SECTION 6: THE MENU ACTIONS
# ---------------------------------------------------------------------------

def ask_for_message(prompt):
    """Keep asking until the user gives a usable message."""
    while True:
        message = input(prompt)
        error = validate_message(message)
        if error is None:
            return message
        print("  ! " + error)


def ask_for_shift():
    """Keep asking until the user gives a usable shift key."""
    while True:
        raw_value = input("Enter shift key (1-25): ")
        shift, error = validate_shift(raw_value)
        if error is None:
            return shift
        print("  ! " + error)


def ask_for_keyword():
    """Keep asking until the user gives a usable Vigenere keyword."""
    while True:
        keyword = input("Enter keyword (letters only): ")
        error = validate_keyword(keyword)
        if error is None:
            return keyword
        print("  ! " + error)


def run_full_demonstration():
    """
    Option 1: encrypt a message, decrypt it again, and prove the round trip
    worked. This is the main requirement of the project.
    """
    print("\n" + LINE)
    print(" ENCRYPT AND DECRYPT (full demonstration)")
    print(LINE)

    original_message = ask_for_message("Enter your message: ")
    shift = ask_for_shift()

    ciphertext = encrypt_text(original_message, shift)
    recovered_text = decrypt_text(ciphertext, shift)

    print("\n" + LINE)
    print(" RESULT")
    print(LINE)
    print(" Original Text  : " + original_message)
    print(" Shift Key Used : " + str(shift))
    print(" Encrypted Text : " + ciphertext)
    print(" Decrypted Text : " + recovered_text)
    print("-" * 50)

    # Automatic verification - compare the recovered text to the original.
    if recovered_text == original_message:
        print(" Verification   : SUCCESS")
        print("                  Decryption successful - original message restored.")
    else:
        print(" Verification   : FAILED")
        print("                  The decrypted text does not match the original.")
    print(LINE + "\n")


def run_encrypt_only():
    """Option 2: encrypt a message and show only the ciphertext."""
    print("\n" + LINE)
    print(" ENCRYPT A MESSAGE")
    print(LINE)
    message = ask_for_message("Enter the message to encrypt: ")
    shift = ask_for_shift()
    print("\n Encrypted Text : " + encrypt_text(message, shift))
    print(" Keep the key (" + str(shift) + ") safe - it is needed to decrypt.\n")


def run_decrypt_only():
    """Option 3: decrypt a ciphertext the user already has."""
    print("\n" + LINE)
    print(" DECRYPT A MESSAGE")
    print(LINE)
    message = ask_for_message("Enter the encrypted text: ")
    shift = ask_for_shift()
    print("\n Decrypted Text : " + decrypt_text(message, shift) + "\n")


def run_vigenere():
    """Option 4: the advanced keyword-based cipher."""
    print("\n" + LINE)
    print(" VIGENERE CIPHER (advanced)")
    print(LINE)
    message = ask_for_message("Enter your message: ")
    keyword = ask_for_keyword()

    ciphertext = vigenere_encrypt(message, keyword)
    recovered = vigenere_decrypt(ciphertext, keyword)

    print("\n Original Text  : " + message)
    print(" Keyword Used   : " + keyword.upper())
    print(" Encrypted Text : " + ciphertext)
    print(" Decrypted Text : " + recovered)
    if recovered == message:
        print(" Verification   : SUCCESS - original message restored.\n")
    else:
        print(" Verification   : FAILED\n")


def run_brute_force():
    """Option 5: crack a Caesar ciphertext without knowing the key."""
    print("\n" + LINE)
    print(" BRUTE-FORCE ATTACK DEMONSTRATION")
    print(LINE)
    print(" This tries all 25 keys without knowing the correct one.")
    print(" Read the list and look for the line that is readable English.\n")

    ciphertext = ask_for_message("Enter the encrypted text: ")

    for shift, attempt in brute_force_caesar(ciphertext):
        print("  Key " + str(shift).rjust(2) + " -> " + attempt)

    print("\n This is why a Caesar cipher must never be used for real data:")
    print(" an attacker needs no password, only 25 guesses.\n")


def run_built_in_tests():
    """Option 6: run the worked examples from the project report."""
    print("\n" + LINE)
    print(" BUILT-IN TEST CASES")
    print(LINE)

    tests = [
        ("HELLO", 3),
        ("Cyber Security 2025!", 5),
        ("Zebra", 1),
        ("attack at dawn", 13),
    ]

    for message, shift in tests:
        encrypted = encrypt_text(message, shift)
        decrypted = decrypt_text(encrypted, shift)
        status = "PASS" if decrypted == message else "FAIL"
        print("  [" + status + "] shift " + str(shift).rjust(2)
              + " | " + message + "  ->  " + encrypted + "  ->  " + decrypted)
    print()


# ---------------------------------------------------------------------------
# SECTION 7: MAIN PROGRAM
# ---------------------------------------------------------------------------

def print_menu():
    print(LINE)
    print(" BASIC ENCRYPTION & DECRYPTION")
    print(" Caesar Cipher - Cybersecurity Project 2")
    print(LINE)
    print(" 1. Encrypt and decrypt a message (full demonstration)")
    print(" 2. Encrypt a message only")
    print(" 3. Decrypt a message only")
    print(" 4. Vigenere cipher (advanced)")
    print(" 5. Brute-force attack demonstration")
    print(" 6. Run built-in test cases")
    print(" 7. Exit")
    print(LINE)


def main():
    print("\n Note: the Caesar cipher is for learning only.")
    print(" It is NOT secure and must never protect real sensitive data.\n")

    # A loop keeps the menu running until the user chooses to exit.
    running = True
    while running:
        print_menu()
        choice = input("Choose an option (1-7): ").strip()

        if choice == "1":
            run_full_demonstration()
        elif choice == "2":
            run_encrypt_only()
        elif choice == "3":
            run_decrypt_only()
        elif choice == "4":
            run_vigenere()
        elif choice == "5":
            run_brute_force()
        elif choice == "6":
            run_built_in_tests()
        elif choice == "7":
            running = False
        else:
            print("  ! '" + choice + "' is not a valid option. "
                  "Please choose a number from 1 to 7.\n")

    print("\n Thank you. Remember: real security needs real algorithms")
    print(" such as AES-256, not classical ciphers. Goodbye!\n")


if __name__ == "__main__":
    # Allow "python encryption_decryption.py --test" to run the test cases
    # directly without going through the menu.
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_built_in_tests()
    else:
        main()
