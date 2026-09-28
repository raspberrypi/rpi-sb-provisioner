"""Every page loads, fills itself in and links where it says."""
from ui.harness.case import UITest

PAGES = {
    "/devices": "Devices",
    "/options/get": "Options",
    "/customisation/list-scripts": "Customisation",
    "/services": "Services",
    "/manu-db": "Manufacturing",
    "/auditlog": "Audit Log",
    "/auth/tokens": "API tokens",
    "/scantool": "Code Scanner",
    "/images/list": "Images",
}


class Pages(UITest):
    def test_every_page_loads_cleanly(self):
        for page, heading in PAGES.items():
            with self.subTest(page=page):
                self.b.get(page)
                self.assertEqual(page, self.b.path())
                self.assertIn(heading.lower(), self.b.text().lower())
                self.assertClean(page)

    def test_nothing_is_loaded_from_elsewhere(self):
        # Stations are often offline, and code from another site would run
        # with the operator's session: every script, style, font and image
        # must come from the station itself.
        pages = list(PAGES) + ["/customisation/get-script?script=naked-provisioner-post-flash",
                               "/devices/ffffffffffffffff"]
        for page in pages:
            with self.subTest(page=page):
                self.b.get(page)
                elsewhere = self.b.d.execute_script("""
                    return performance.getEntriesByType('resource').map(e => e.name)
                        .filter(u => !u.startsWith(location.origin) && !u.startsWith('data:') &&
                                     !u.startsWith('ws:') && !u.startsWith('wss:'));""")
                self.assertEqual([], elsewhere, f"{page} loads from other sites")
                refs = self.b.d.execute_script("""
                    return [...document.querySelectorAll('script[src], link[href], img[src], iframe[src]')]
                        .map(e => e.src || e.href)
                        .filter(u => u && !u.startsWith(location.origin) && !u.startsWith('data:'));""")
                self.assertEqual([], [u for u in refs if "github.com/raspberrypi" not in u],
                                 f"{page} refers to other sites for code or style")

    def test_root_goes_to_devices(self):
        self.b.get("/")
        self.assertEqual("/devices", self.b.path())

    def test_navbar_links_all_work(self):
        self.b.get("/devices")
        links = [a.get_attribute("href") for a in self.b.all("nav a[href^='/'], nav a[href^='" + self.b.base + "']")]
        self.assertGreaterEqual(len(links), 7)
        for href in dict.fromkeys(links):
            with self.subTest(href=href):
                self.b.d.get(href)
                self.b.settle()
                self.assertFalse(self.b.path().startswith("/login"), f"{href} sent a signed-in operator to sign in")
                self.assertClean(href)

    def test_navbar_marks_the_current_page(self):
        for page in ("/devices", "/services", "/auditlog"):
            with self.subTest(page=page):
                self.b.get(page)
                current = self.b.all("nav [aria-current='page']")
                self.assertEqual(1, len(current), f"{page}: one navbar entry should be current")

    def test_version_and_operator_are_shown(self):
        self.b.get("/devices")
        text = self.b.text()
        version = self.station.sh("dpkg-query -W -f='${Version}' rpi-sb-provisioner").strip()
        self.assertIn(version, text)
        self.assertIn(self.assertSignedIn().get("user", ""), text)

    def test_unknown_page_is_a_clean_404(self):
        self.b.get("/no-such-page")
        self.assertIn("404", self.b.d.title + self.b.text())

    def test_skip_link_reaches_main_content(self):
        self.b.get("/devices")
        skip = self.b.all("a[href='#main-content'], a.skip-link")
        self.assertTrue(skip, "expected a skip-to-content link")
        target = skip[0].get_attribute("href").split("#", 1)[1]
        self.assertTrue(self.b.all("#" + target), f"skip link target #{target} is missing")
