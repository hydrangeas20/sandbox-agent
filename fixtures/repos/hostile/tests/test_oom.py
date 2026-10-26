import unittest


class OomTest(unittest.TestCase):
    def test_allocate(self):
        blocks = []
        while True:
            blocks.append(bytearray(32 * 1024 * 1024))
            blocks[-1][::4096] = b"x" * len(blocks[-1][::4096])
