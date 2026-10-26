import unittest

from tempconv import c_to_f, f_to_c


class HeldOut(unittest.TestCase):
    def test_roundtrip(self) -> None:
        self.assertAlmostEqual(f_to_c(-40), -40.0)
        for c in (-10.0, 0.0, 21.5, 100.0):
            self.assertAlmostEqual(f_to_c(c_to_f(c)), c)
