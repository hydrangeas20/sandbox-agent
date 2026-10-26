import unittest

from slugify import slugify


class SlugifyTest(unittest.TestCase):
    def test_basic(self) -> None:
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_punctuation_is_trimmed(self) -> None:
        self.assertEqual(slugify("Hello, World!"), "hello-world")

    def test_surrounding_whitespace(self) -> None:
        self.assertEqual(slugify("  spaced out  "), "spaced-out")

    def test_custom_separator(self) -> None:
        self.assertEqual(slugify("a b", sep="_"), "a_b")
