"""
=============================================================================
 TEST CASES for encryption_decryption.py
=============================================================================

 These tests prove that the cipher behaves the way the report describes:
 letters shift correctly, cases are preserved, non-letters are untouched,
 decryption reverses encryption exactly, and bad input is rejected.

 Run with:  python test_encryption.py
=============================================================================
"""

import unittest

from encryption_decryption import (
    encrypt_text,
    decrypt_text,
    shift_character,
    vigenere_encrypt,
    vigenere_decrypt,
    brute_force_caesar,
    validate_message,
    validate_shift,
    validate_keyword,
)


class TestSingleCharacterShift(unittest.TestCase):
    """Does one character shift correctly?"""

    def test_basic_forward_shift(self):
        self.assertEqual(shift_character("H", 3), "K")
        self.assertEqual(shift_character("a", 1), "b")

    def test_backward_shift(self):
        self.assertEqual(shift_character("K", -3), "H")

    def test_wrap_around_the_end_of_the_alphabet(self):
        # Z + 1 must loop back to A, not run past the alphabet
        self.assertEqual(shift_character("Z", 1), "A")
        self.assertEqual(shift_character("z", 3), "c")
        self.assertEqual(shift_character("A", -1), "Z")

    def test_non_letters_are_unchanged(self):
        self.assertEqual(shift_character(" ", 5), " ")
        self.assertEqual(shift_character("7", 5), "7")
        self.assertEqual(shift_character("!", 5), "!")


class TestCaseCase1BasicWord(unittest.TestCase):
    """TEST CASE 1 - the classic example: HELLO with shift 3."""

    def test_hello_encrypts_to_khoor(self):
        self.assertEqual(encrypt_text("HELLO", 3), "KHOOR")

    def test_khoor_decrypts_to_hello(self):
        self.assertEqual(decrypt_text("KHOOR", 3), "HELLO")


class TestCase2MixedCharacters(unittest.TestCase):
    """TEST CASE 2 - mixed case, digits, spaces and punctuation."""

    def test_mixed_message_round_trip(self):
        original = "Cyber Security 2025!"
        encrypted = encrypt_text(original, 5)
        self.assertEqual(encrypted, "Hdgjw Xjhzwnyd 2025!")
        self.assertEqual(decrypt_text(encrypted, 5), original)

    def test_digits_and_symbols_survive_untouched(self):
        encrypted = encrypt_text("abc 123 !@#", 7)
        self.assertIn("123", encrypted)
        self.assertIn("!@#", encrypted)

    def test_uppercase_stays_uppercase(self):
        encrypted = encrypt_text("AbCd", 4)
        self.assertTrue(encrypted[0].isupper())
        self.assertTrue(encrypted[1].islower())


class TestCase3WrapAround(unittest.TestCase):
    """TEST CASE 3 - letters near the end of the alphabet must wrap."""

    def test_zebra_shift_one(self):
        self.assertEqual(encrypt_text("Zebra", 1), "Afcsb")
        self.assertEqual(decrypt_text("Afcsb", 1), "Zebra")

    def test_rot13_is_its_own_inverse(self):
        # A shift of 13 applied twice returns the original text
        once = encrypt_text("attack at dawn", 13)
        twice = encrypt_text(once, 13)
        self.assertEqual(twice, "attack at dawn")


class TestRoundTripAlwaysWorks(unittest.TestCase):
    """Decryption must undo encryption for every valid key."""

    def test_every_key_from_1_to_25(self):
        message = "The Quick Brown Fox, 99!"
        for shift in range(1, 26):
            encrypted = encrypt_text(message, shift)
            self.assertEqual(decrypt_text(encrypted, shift), message)

    def test_wrong_key_does_not_recover_the_message(self):
        encrypted = encrypt_text("SECRET", 5)
        self.assertNotEqual(decrypt_text(encrypted, 6), "SECRET")


class TestVigenereCipher(unittest.TestCase):
    """The advanced keyword-based cipher."""

    def test_known_example(self):
        # HELLO with keyword KEY: shifts of 10, 4, 24, 10, 4
        self.assertEqual(vigenere_encrypt("HELLO", "KEY"), "RIJVS")

    def test_round_trip_with_spaces(self):
        original = "Meet me at the gate, 9pm!"
        encrypted = vigenere_encrypt(original, "LEMON")
        self.assertEqual(vigenere_decrypt(encrypted, "LEMON"), original)

    def test_repeated_letters_encrypt_differently(self):
        # The two Ls in HELLO become different letters - this is the
        # advantage Vigenere has over Caesar
        result = vigenere_encrypt("HELLO", "KEY")
        self.assertNotEqual(result[2], result[3])


class TestBruteForceAttack(unittest.TestCase):
    """Proving the Caesar cipher is breakable without the key."""

    def test_returns_all_25_possibilities(self):
        self.assertEqual(len(brute_force_caesar("KHOOR")), 25)

    def test_correct_plaintext_appears_in_the_list(self):
        attempts = brute_force_caesar(encrypt_text("HELLO", 3))
        plaintexts = [text for shift, text in attempts]
        self.assertIn("HELLO", plaintexts)


class TestInputValidation(unittest.TestCase):
    """Bad input must be rejected cleanly instead of crashing."""

    def test_empty_message_rejected(self):
        self.assertIsNotNone(validate_message(""))

    def test_spaces_only_message_rejected(self):
        self.assertIsNotNone(validate_message("    "))

    def test_valid_message_accepted(self):
        self.assertIsNone(validate_message("Hello"))

    def test_text_shift_key_rejected(self):
        shift, error = validate_shift("abc")
        self.assertIsNone(shift)
        self.assertIsNotNone(error)

    def test_decimal_shift_key_rejected(self):
        shift, error = validate_shift("3.5")
        self.assertIsNone(shift)

    def test_empty_shift_key_rejected(self):
        shift, error = validate_shift("")
        self.assertIsNone(shift)

    def test_zero_shift_rejected(self):
        shift, error = validate_shift("0")
        self.assertIsNone(shift)
        self.assertIsNotNone(error)

    def test_shift_of_26_rejected_as_no_change(self):
        shift, error = validate_shift("26")
        self.assertIsNone(shift)

    def test_large_shift_wraps_into_range(self):
        shift, error = validate_shift("29")
        self.assertEqual(shift, 3)
        self.assertIsNone(error)

    def test_negative_shift_wraps_into_range(self):
        shift, error = validate_shift("-3")
        self.assertEqual(shift, 23)

    def test_surrounding_spaces_are_tolerated(self):
        shift, error = validate_shift("  7  ")
        self.assertEqual(shift, 7)

    def test_keyword_validation(self):
        self.assertIsNone(validate_keyword("KEY"))
        self.assertIsNotNone(validate_keyword(""))
        self.assertIsNotNone(validate_keyword("key 1"))


class TestEdgeCases(unittest.TestCase):
    """Unusual input must not break the program."""

    def test_message_with_no_letters(self):
        self.assertEqual(encrypt_text("12345 !@#", 8), "12345 !@#")

    def test_single_character(self):
        self.assertEqual(encrypt_text("A", 25), "Z")

    def test_long_message_round_trip(self):
        long_message = "security " * 200
        self.assertEqual(decrypt_text(encrypt_text(long_message, 11), 11),
                         long_message)

    def test_non_english_characters_pass_through(self):
        self.assertEqual(encrypt_text("héllo", 3), "kéoor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
