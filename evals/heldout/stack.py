import unittest

from stack import EmptyStackError, Stack


class HeldOut(unittest.TestCase):
    def test_behaviour_unchanged(self) -> None:
        with self.assertRaises(EmptyStackError):
            Stack().peek()
        s = Stack()
        s.push("x")
        self.assertEqual(s.peek(), "x")
