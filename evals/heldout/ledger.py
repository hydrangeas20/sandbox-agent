import unittest

from ledger import column_total


class HeldOut(unittest.TestCase):
    def test_single_row_and_other_column(self) -> None:
        self.assertAlmostEqual(column_total([{"fee": "2.5"}], "fee"), 2.5)
        rows = [{"a": "1", "b": "10"}, {"a": "2", "b": "20"}]
        self.assertAlmostEqual(column_total(rows, "b"), 30.0)
