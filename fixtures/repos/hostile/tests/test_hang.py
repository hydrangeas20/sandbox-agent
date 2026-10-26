import unittest


class HangTest(unittest.TestCase):
    def test_forever(self):
        while True:
            pass
