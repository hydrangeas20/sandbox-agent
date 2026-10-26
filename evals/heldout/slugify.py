import unittest

from slugify import slugify


class HeldOut(unittest.TestCase):
    def test_edges(self) -> None:
        self.assertEqual(slugify("--Already--Slugged--"), "already-slugged")
        self.assertEqual(slugify("!!!"), "")
        self.assertEqual(slugify(" x ", sep="_"), "x")
