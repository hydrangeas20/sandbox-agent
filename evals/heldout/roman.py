import unittest

from roman import to_roman


class HeldOut(unittest.TestCase):
    def test_more_subtractive(self) -> None:
        self.assertEqual(to_roman(3999), "MMMCMXCIX")
        self.assertEqual(to_roman(444), "CDXLIV")
        self.assertEqual(to_roman(40), "XL")
