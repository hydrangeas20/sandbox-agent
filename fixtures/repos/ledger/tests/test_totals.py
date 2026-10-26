import unittest

from ledger import column_total

ROWS = [{"amount": "10.50"}, {"amount": "4.25"}, {"amount": "5.25"}]


class ColumnTotalTest(unittest.TestCase):
    def test_sums_every_row(self) -> None:
        self.assertAlmostEqual(column_total(ROWS, "amount"), 20.0)

    def test_empty(self) -> None:
        self.assertEqual(column_total([], "amount"), 0.0)
