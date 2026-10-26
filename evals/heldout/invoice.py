import unittest

from invoice import invoice_total


class HeldOut(unittest.TestCase):
    def test_rounding_cases(self) -> None:
        self.assertEqual(invoice_total([(3, 333)], 0.05), 1049)  # 49.95 -> 50
        self.assertEqual(invoice_total([(1, 1000)], 0.13), 1130)  # exact
        self.assertEqual(invoice_total([(1, 1001)], 0.13), 1131)  # 130.13 -> 130
