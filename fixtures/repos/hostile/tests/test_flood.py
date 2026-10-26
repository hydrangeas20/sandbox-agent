import sys
import unittest


class FloodTest(unittest.TestCase):
    def test_flood(self):
        chunk = "Z" * 65536
        for _ in range(2000):  # ~128 MiB
            sys.stdout.write(chunk)
