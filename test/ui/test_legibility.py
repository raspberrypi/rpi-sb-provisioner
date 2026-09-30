"""Every page legible and usable: at phone to desktop widths, by keyboard,
and against WCAG 2.1 AA, whether signed in or not.

The checks are in harness/legibility.py; legibility_survey.py prints them
all without failing, for looking into a new finding.
"""
import unittest

from ui.harness import legibility as L
from ui.harness.case import UITest

SERIAL = "10000000fedcba98"
WIDTHS = (375, 768, 1280, 1920)
PUBLIC = ["/devices", f"/devices/{SERIAL}", "/scantool"]
OPERATOR = ["/devices", "/devices#rel", "/devices#topo", f"/devices/{SERIAL}", "/options/get",
            "/customisation/list-scripts", "/customisation/get-script?script=naked-provisioner-post-flash",
            "/services", f"/service-log/rpi-sb-triage@{SERIAL}.service", "/manu-db", "/auditlog",
            "/auth/tokens", "/scantool", "/no-such-page"]


class Legibility:
    """Mixed into a UITest with the pages it covers."""

    PAGES = []

    def visit(self, page, width=1280):
        self.b.d.set_window_size(width, 1000)
        # A fragment alone does not reload the page, so leave it first.
        if "#" in page:
            self.b.get("/login" if not self.sign_in_first else "/auth/tokens")
        self.b.get(page)

    def each(self, check, widths=WIDTHS):
        for page in self.PAGES:
            for width in widths:
                with self.subTest(page=page, width=width):
                    self.visit(page, width)
                    self.assertEqual([], check(self.b.d), f"{page} at {width}px")

    def test_wcag_aa(self):
        for page in self.PAGES:
            with self.subTest(page=page):
                self.visit(page)
                found = [f"{rule} ({impact}): {help_} at {nodes}" for rule, impact, help_, nodes, _ in L.audit(self.b.d)]
                self.assertEqual([], found, page)

    def test_contrast_in_dark_mode(self):
        L.set_dark(self.b.d, True)
        try:
            for page in self.PAGES:
                with self.subTest(page=page):
                    self.visit(page)
                    found = [f"{help_} at {nodes}" for _, _, help_, nodes, _ in L.audit(self.b.d, ["color-contrast"])]
                    self.assertEqual([], found, page)
        finally:
            L.set_dark(self.b.d, False)

    def test_nothing_overflows(self):
        self.each(L.overflow)

    def test_no_control_is_covered(self):
        self.each(L.covered)

    def test_text_is_not_too_small(self):
        self.each(L.small_text)

    def test_every_control_is_reachable_by_keyboard(self):
        for page in self.PAGES:
            with self.subTest(page=page):
                self.visit(page)
                self.assertEqual([], L.keyboard(self.b.d), page)


class Operator(Legibility, UITest):
    PAGES = OPERATOR


class SignedOut(Legibility, UITest):
    sign_in_first = False
    PAGES = ["/login"] + PUBLIC

    def setUp(self):
        super().setUp()
        self.b.sign_out()


class Checks(unittest.TestCase):
    """The checks themselves catch what they claim to, on pages made to fail."""

    @classmethod
    def setUpClass(cls):
        from ui.harness.browser import Browser
        from ui.harness.case import station
        cls.b = Browser(station().url)

    @classmethod
    def tearDownClass(cls):
        cls.b.quit()

    def page(self, html):
        self.b.d.get("data:text/html;charset=utf-8," + html.replace("#", "%23"))

    def test_each_check_finds_its_fault(self):
        d = self.b.d
        d.set_window_size(800, 600)
        self.page('<html><body><p style="color:#bbb;background:#fff">faint</p></body></html>')
        self.assertIn("color-contrast", [v[0] for v in L.audit(d)])
        self.page('<html lang="en"><body><div style="width:2000px">wide</div></body></html>')
        self.assertTrue(L.overflow(d))
        self.page('<html lang="en"><body><div style="width:40px;overflow:hidden;white-space:nowrap">'
                  'a long clipped sentence</div></body></html>')
        self.assertTrue(any("clipped" in f for f in L.overflow(d)))
        self.page('<html lang="en"><body><button>under</button>'
                  '<div style="position:fixed;inset:0;background:#fff"></div></body></html>')
        self.assertTrue(L.covered(d))
        self.page('<html lang="en"><body><p style="font-size:9px">tiny</p></body></html>')
        self.assertTrue(L.small_text(d))
        self.page('<html lang="en"><body><div onclick="1" role="button">no tab stop</div>'
                  '<button style="outline:none">no ring</button></body></html>')
        found = L.keyboard(d)
        self.assertTrue(any("never reaches" in f for f in found), found)
        self.assertTrue(any("no visible focus" in f for f in found), found)

    def test_screen_reader_text_is_not_clipped_text(self):
    def test_a_closed_details_hides_its_contents(self):
        self.page('<html lang="en"><body><details><summary>More</summary><input aria-label="x"></details>'
                  '<div style="position:fixed;inset:0;pointer-events:none"></div></body></html>')
        self.assertEqual([], L.keyboard(self.b.d))

        self.page('<html lang="en"><body><span style="position:absolute;width:1px;height:1px;overflow:hidden;'
                  'clip:rect(0,0,0,0)">for screen readers</span></body></html>')
        self.assertEqual([], L.overflow(self.b.d))
