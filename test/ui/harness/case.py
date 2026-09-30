"""Base class for the UI tests.

One station serves every module in a run: it is opened, checked for the
opt-in marker and snapshotted on first use, and restored when the run ends.
"""
import atexit
import signal
import sys
import unittest

from .browser import Browser, USER, PASSWORD
from .station import Station

_station = None


def station():
    global _station
    if _station is None:
        if not USER or not PASSWORD:
            raise unittest.SkipTest("set RPI_SB_TEST_USER and RPI_SB_TEST_PASSWORD")
        s = Station()
        s.open()
        s.check_opted_in()
        s.snapshot()
        atexit.register(_finish, s)
        # atexit does not run on SIGTERM: make it an ordinary exit, so a
        # stopped run still puts the station back.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        _station = s
    return _station


def _finish(s):
    try:
        s.restore()
    finally:
        s.close()


class UITest(unittest.TestCase):
    """A module's tests share one browser; sign_in_first signs it in."""

    sign_in_first = True

    @classmethod
    def setUpClass(cls):
        cls.station = station()
        cls.b = Browser(cls.station.url)
        if cls.sign_in_first:
            cls.b.sign_in()

    @classmethod
    def tearDownClass(cls):
        cls.b.quit()

    def setUp(self):
        # An error an earlier test provoked on purpose is not this test's.
        self.b.drain_console()

    def assertClean(self, where=None, error_page=False):
        problems = self.b.problems(error_page)
        self.assertEqual([], problems, f"{where or self.b.path()}: page has problems")

    def assertSignedIn(self):
        session = self.b.signed_in()
        self.assertTrue(session, "expected a signed-in session")
        return session

    def assertAtLogin(self):
        self.assertTrue(self.b.path().startswith("/login"), f"expected /login, at {self.b.path()}")
