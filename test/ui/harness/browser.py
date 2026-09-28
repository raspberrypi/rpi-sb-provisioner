"""Headless Chromium, signed in to the station's UI as an operator would be.

    RPI_SB_TEST_USER / RPI_SB_TEST_PASSWORD    an account in rpi-sb-provisioner
    RPI_SB_TEST_OUTSIDER / _OUTSIDER_PASSWORD  optional: a real account that is
                                               not in the group
"""
import json
import os
import tempfile
import time

from selenium import webdriver
from selenium.common.exceptions import (ElementClickInterceptedException, ElementNotInteractableException,
                                        NoAlertPresentException, TimeoutException)
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

USER = os.environ.get("RPI_SB_TEST_USER", "")
PASSWORD = os.environ.get("RPI_SB_TEST_PASSWORD", "")
OUTSIDER = os.environ.get("RPI_SB_TEST_OUTSIDER", "")
OUTSIDER_PASSWORD = os.environ.get("RPI_SB_TEST_OUTSIDER_PASSWORD", "")

# Planted by the escaping tests: it closes an attribute, a script and a JS
# string, so it becomes live wherever a page fails to escape it, and records
# its number in window.__xss when it does.
def payload(n):
    return ('"><img src=x onerror=window.__xss=(window.__xss||[]).concat(%d)>'
            "</script><svg onload=window.__xss=(window.__xss||[]).concat(%d)>"
            "';window.__xss=(window.__xss||[]).concat(%d);//") % (n, n, n)


PAYLOAD_MARK = "onerror=window.__xss"
# Console noise that says nothing about the page.
IGNORED_CONSOLE = ("favicon.ico",)


class Browser:
    def __init__(self, base_url, extra_args=()):
        self.base = base_url
        self.downloads = tempfile.mkdtemp(prefix="rpi-sb-ui-dl-")
        opts = webdriver.ChromeOptions()
        # Named outright: Selenium Manager has no aarch64 build.
        opts.binary_location = "/usr/bin/chromium"
        for a in ("--headless=new", "--no-sandbox", "--disable-gpu", "--window-size=1400,1000",
                  "--user-data-dir=" + tempfile.mkdtemp(prefix="rpi-sb-ui-"), *extra_args):
            opts.add_argument(a)
        opts.add_experimental_option("prefs", {
            "download.default_directory": self.downloads,
            "download.prompt_for_download": False,
        })
        opts.set_capability("goog:loggingPrefs", {"browser": "ALL"})
        self.d = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opts)
        self.d.set_page_load_timeout(30)
        self.d.set_script_timeout(60)

    def quit(self):
        self.d.quit()

    # --- navigation ------------------------------------------------------

    def get(self, path, settle=True):
        self.d.get(self.base + path)
        if settle:
            self.settle()

    def settle(self, quiet=0.7, timeout=15):
        """Waits until the page has loaded and its fetches have gone quiet."""
        WebDriverWait(self.d, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete")
        # Count requests via the Performance API; stop once none has started
        # for `quiet` seconds.
        deadline = time.time() + timeout
        last = -1
        stable_since = time.time()
        while time.time() < deadline:
            n = self.d.execute_script("return performance.getEntriesByType('resource').length")
            if n != last:
                last, stable_since = n, time.time()
            elif time.time() - stable_since >= quiet:
                return
            time.sleep(0.1)

    def path(self):
        """The current path and query, without the fragment pages add."""
        url = self.d.current_url.split("#", 1)[0]
        return url[len(self.base):] if url.startswith(self.base) else url

    def text(self):
        return self.d.execute_script("return document.body ? document.body.innerText : ''")

    def el(self, css, timeout=10):
        return WebDriverWait(self.d, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, css)))

    def visible(self, css, timeout=10):
        return WebDriverWait(self.d, timeout).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, css)))

    def all(self, css):
        return self.d.find_elements(By.CSS_SELECTOR, css)

    def click(self, css, timeout=10):
        self.press(self.el(css, timeout))

    def press(self, el):
        """Clicks as an operator would. Styled controls hide their inputs
        and the sticky navbar covers the top of the page, so bring the
        element to the centre, and fall back to a DOM click, which fires
        the same handlers."""
        self.d.execute_script("arguments[0].scrollIntoView({block: 'center'})", el)
        try:
            el.click()
        except (ElementClickInterceptedException, ElementNotInteractableException):
            self.d.execute_script("arguments[0].click()", el)

    def wait_text(self, css, contains, timeout=15):
        try:
            WebDriverWait(self.d, timeout).until(
                lambda d: contains in d.find_element(By.CSS_SELECTOR, css).text)
        except TimeoutException:
            found = [e.text for e in self.all(css)]
            raise AssertionError(f"{css} never contained {contains!r}; it has {found!r}")

    def accept_confirm(self):
        """Pre-answers the next confirm() and prompt() with yes."""
        self.d.execute_script("window.confirm = () => true; window.prompt = (m, v) => v || 'x';")

    # --- sessions --------------------------------------------------------

    def sign_in(self, user=None, password=None, next_path=None, here=False):
        """Signs in. here: use the sign-in form already open, keeping its next."""
        user = USER if user is None else user
        password = PASSWORD if password is None else password
        if not here:
            self.get("/login" + (f"?next={next_path}" if next_path else ""), settle=False)
        self.el("#username").clear()
        self.el("#username").send_keys(user)
        # Chromium can restore a form's earlier contents; typing onto them
        # would send the password twice over.
        self.el("#password").clear()
        self.el("#password").send_keys(password)
        # The old page is complete already, so mark it and wait for the
        # answer to replace it. An empty field is refused by the browser
        # itself (the inputs are required), and nothing is sent.
        self.d.execute_script("window.__rpiSbOldPage = true")
        self.click("button[type=submit]")
        if user and password:
            def replaced(d):
                try:
                    return d.execute_script("return !window.__rpiSbOldPage && document.readyState === 'complete'")
                except Exception:
                    return False
            WebDriverWait(self.d, 30).until(replaced)
        else:
            time.sleep(0.5)
        self.drain_console()
        errors = self.all("div.login-error")
        self.last_login_error = errors[0].text if errors else ""

    def sign_out(self):
        self.d.delete_all_cookies()

    def signed_in(self):
        return self.d.execute_async_script(
            "const done = arguments[0];"
            "fetch('/auth/session').then(r => r.ok ? r.json() : null)"
            ".then(s => done(s && s.user ? s : null), () => done(null));")

    def cookie(self, name):
        return self.d.get_cookie(name)

    # --- in-page requests -----------------------------------------------

    def fetch(self, path, method="GET", body=None, csrf=True, headers=None, raw=False):
        """A request made by the page itself: same origin, session cookie,
        and the CSRF header the UI's own scripts send. Returns (status, body)."""
        script = """
            const [path, method, body, csrf, extra, raw, done] = arguments;
            const h = Object.assign({}, extra || {});
            if (body !== null && !raw) h['Content-Type'] = 'application/json';
            const go = tok => {
                if (tok) h['X-CSRF-Token'] = tok;
                const init = {method, headers: h, credentials: 'same-origin'};
                if (body !== null) init.body = raw ? body : JSON.stringify(body);
                return fetch(path, init).then(r => r.text().then(t => done([r.status, t])));
            };
            (csrf ? fetch('/options/csrf-token').then(r => r.json()).then(j => j.token) : Promise.resolve(null))
                .then(go).catch(e => done([0, String(e)]));
        """
        status, text = self.d.execute_async_script(script, path, method, body, csrf, headers, raw)
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    # --- checks ----------------------------------------------------------

    def drain_console(self):
        self.d.get_log("browser")

    def problems(self, error_page=False):
        """What is wrong with the current page: planted payloads that ran,
        alerts, and JavaScript errors. Empties the console log. An error page
        may log its own 4xx status, which is the point of it."""
        found = []
        try:
            alert = self.d.switch_to.alert
            found.append(f"alert: {alert.text!r}")
            alert.accept()
        except NoAlertPresentException:
            pass
        fired = self.d.execute_script("return window.__xss || null")
        if fired:
            found.append(f"planted markup ran: {sorted(set(fired))}")
        for entry in self.d.get_log("browser"):
            own = error_page and self.d.current_url.split("#")[0] in entry["message"] \
                and "the server responded with a status of 4" in entry["message"]
            if entry["level"] == "SEVERE" and not own and not any(i in entry["message"] for i in IGNORED_CONSOLE):
                found.append("console: " + entry["message"][:300])
        return found

    def payloads_shown(self):
        return self.text().count(PAYLOAD_MARK)
