import unittest

from paginator import paginate, total_pages


class TotalPagesTest(unittest.TestCase):
    def test_exact_multiple(self) -> None:
        self.assertEqual(total_pages(20, 10), 2)

    def test_partial_last_page(self) -> None:
        self.assertEqual(total_pages(21, 10), 3)

    def test_empty_has_one_page(self) -> None:
        self.assertEqual(total_pages(0, 10), 1)


class PaginateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.items = list(range(1, 26))  # 25 items

    def test_first_page_starts_at_first_item(self) -> None:
        page = paginate(self.items, 1, per_page=10)
        self.assertEqual(page.items, list(range(1, 11)))
        self.assertTrue(page.has_next)

    def test_last_page_is_partial(self) -> None:
        page = paginate(self.items, 3, per_page=10)
        self.assertEqual(page.items, [21, 22, 23, 24, 25])
        self.assertFalse(page.has_next)

    def test_out_of_range_page_rejected(self) -> None:
        with self.assertRaises(ValueError):
            paginate(self.items, 4, per_page=10)


if __name__ == "__main__":
    unittest.main()
