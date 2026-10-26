import unittest

from tempconv import c_to_f, f_to_c


class ConvertTest(unittest.TestCase):
    def test_freezing(self) -> None:
        self.assertAlmostEqual(f_to_c(32), 0.0)
        self.assertAlmostEqual(c_to_f(0), 32.0)

    def test_boiling(self) -> None:
        self.assertAlmostEqual(f_to_c(212), 100.0)

    def test_body_temperature(self) -> None:
        self.assertAlmostEqual(f_to_c(98.6), 37.0)
