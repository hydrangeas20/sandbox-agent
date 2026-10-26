import unittest

from paginator import paginate


class HeldOut(unittest.TestCase):
    def test_second_page_and_per_page(self) -> None:
        self.assertEqual(paginate(list(range(1, 8)), 2, per_page=3).items, [4, 5, 6])
        self.assertEqual(paginate(["a"], 1, per_page=5).items, ["a"])
