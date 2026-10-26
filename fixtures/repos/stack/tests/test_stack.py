import unittest

from stack import EmptyStackError, Stack


class StackTest(unittest.TestCase):
    def test_lifo(self) -> None:
        s = Stack()
        s.push(1)
        s.push(2)
        self.assertEqual(s.pop(), 2)
        self.assertEqual(len(s), 1)

    def test_empty_pop_raises(self) -> None:
        with self.assertRaises(EmptyStackError):
            Stack().pop()
