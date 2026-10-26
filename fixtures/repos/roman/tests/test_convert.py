import unittest

from roman import to_roman


class ToRomanTest(unittest.TestCase):
    def test_additive(self) -> None:
        self.assertEqual(to_roman(3), "III")
        self.assertEqual(to_roman(2026), "MMXXVI")

    def test_subtractive(self) -> None:
        self.assertEqual(to_roman(4), "IV")
        self.assertEqual(to_roman(9), "IX")
        self.assertEqual(to_roman(1994), "MCMXCIV")

    def test_range(self) -> None:
        with self.assertRaises(ValueError):
            to_roman(0)
