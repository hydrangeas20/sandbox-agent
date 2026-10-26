import unittest

from invoice import invoice_total, line_total


class InvoiceTest(unittest.TestCase):
    def test_line_total(self) -> None:
        self.assertEqual(line_total(3, 250), 750)

    def test_no_tax(self) -> None:
        self.assertEqual(invoice_total([(2, 500)], 0.0), 1000)

    def test_tax_rounds_to_nearest_cent(self) -> None:
        # 1999 * 0.13 = 259.87 -> 260
        self.assertEqual(invoice_total([(1, 1999)], 0.13), 2259)
