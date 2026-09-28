"""Legibility and accessibility checks for a page open in Selenium.

Plain functions over a WebDriver, with no other harness assumed, so another
suite can use them as they are. Each returns a list of findings, empty when
the page passes:

    audit(d)           axe-core's WCAG 2.1 A and AA rules
    overflow(d)        page wider than the window, and text clipped by its box
    covered(d)         controls hidden under something else, such as a navbar
    small_text(d)      visible text below MIN_FONT_PX
    keyboard(d)        controls Tab never reaches, or reaches without a visible focus
    set_dark(d, on)    emulate prefers-color-scheme: dark, for a second audit
"""
import os

AXE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor", "axe", "axe.min.js")
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
MIN_FONT_PX = 12
_axe_source = None

# What counts as something an operator can operate.
_CONTROLS = ("a[href], button, input:not([type=hidden]), select, textarea, "
             "[role=button], [role=tab], [tabindex]:not([tabindex='-1'])")

# Shared by the checks: is this element on screen and meant to be seen?
_SHOWN = """
    function shown(el) {
        if (!el.isConnected) return false;
        const s = getComputedStyle(el);
        if (s.visibility === 'hidden' || s.display === 'none' || Number(s.opacity) === 0) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    }
    function describe(el) {
        let d = el.tagName.toLowerCase();
        if (el.id) d += '#' + el.id;
        else if (el.classList.length) d += '.' + [...el.classList].slice(0, 2).join('.');
        const t = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().replace(/\\s+/g, ' ');
        return t ? d + ' "' + t.slice(0, 40) + '"' : d;
    }
"""


def audit(d, rules=None):
    """axe-core violations: [(rule, impact, help, [elements])]."""
    global _axe_source
    if _axe_source is None:
        with open(AXE) as f:
            _axe_source = f.read()
    if not d.execute_script("return typeof window.axe === 'object'"):
        d.execute_script(_axe_source)
    options = {"resultTypes": ["violations"]}
    options["runOnly"] = {"type": "rule", "values": rules} if rules else {"type": "tag", "values": WCAG}
    result = d.execute_async_script("""
        const [options, done] = arguments;
        axe.run(document, options).then(r => done(r.violations.map(v => [
            v.id, v.impact, v.help, v.nodes.map(n => n.target.join(' ')).slice(0, 8), v.nodes.length])),
            e => done([['axe-error', 'critical', String(e), [], 0]]));
    """, options)
    return [tuple(v) for v in result]


def overflow(d):
    """The page scrolling sideways, and text its box cuts off."""
    return d.execute_script(_SHOWN + """
        const found = [];
        const root = document.documentElement;
        if (root.scrollWidth > root.clientWidth + 1)
            found.push('page is ' + root.scrollWidth + 'px wide in a ' + root.clientWidth + 'px window');
        for (const el of document.querySelectorAll('body *')) {
            if (!shown(el) || !el.innerText || !el.innerText.trim()) continue;
            if ([...el.children].some(c => shown(c) && c.innerText && c.innerText.trim())) continue;
            const s = getComputedStyle(el);
            // Text hidden on purpose for screen readers is clipped by design.
            const r = el.getBoundingClientRect();
            if ((r.width <= 1 && r.height <= 1) || s.clip.startsWith('rect(0') || s.clipPath.includes('inset(50%')) continue;
            const cuts = s.overflowX !== 'visible' || s.overflowY !== 'visible' || s.textOverflow === 'ellipsis';
            if (!cuts || s.overflowX === 'auto' || s.overflowX === 'scroll') continue;
            if (el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
                found.push('clipped: ' + describe(el));
        }
        return found;
    """)


def covered(d):
    """Controls whose centre, scrolled into view, is under another element."""
    return d.execute_script(_SHOWN + """
        const found = [];
        const x0 = scrollX, y0 = scrollY;
        for (const el of document.querySelectorAll(arguments[0])) {
            if (!shown(el)) continue;
            el.scrollIntoView({block: 'center', inline: 'center'});
            const r = el.getBoundingClientRect();
            const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
            if (cx < 0 || cy < 0 || cx > innerWidth || cy > innerHeight) continue;
            const top = document.elementFromPoint(cx, cy);
            if (top && top !== el && !el.contains(top) && !top.contains(el) && !(el.labels && [...el.labels].some(l => l.contains(top))))
                found.push(describe(el) + ' is under ' + describe(top));
        }
        scrollTo(x0, y0);
        return found;
    """, _CONTROLS)


def small_text(d, min_px=MIN_FONT_PX):
    """Visible text set smaller than min_px, once per size and element kind."""
    return d.execute_script(_SHOWN + """
        const min = arguments[0], seen = new Set(), found = [];
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
            const t = walker.currentNode;
            if (!t.nodeValue.trim() || !t.parentElement || !shown(t.parentElement)) continue;
            const px = parseFloat(getComputedStyle(t.parentElement).fontSize);
            const key = describe(t.parentElement).split(' ')[0] + '@' + px;
            if (px < min && !seen.has(key)) { seen.add(key); found.push(describe(t.parentElement) + ' at ' + px + 'px'); }
        }
        return found;
    """, min_px)


def keyboard(d, limit=400):
    """Controls Tab does not reach, and ones it reaches with no visible focus."""
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.common.keys import Keys
    d.execute_script("document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0);")
    d.execute_script("""
        window.__rpiTabbed = new Set(); window.__rpiNoFocusRing = [];
        document.addEventListener('focusin', e => {
            const el = e.target; window.__rpiTabbed.add(el);
            const f = getComputedStyle(el);
            const ring = (f.outlineStyle !== 'none' && parseFloat(f.outlineWidth) > 0) || f.boxShadow !== 'none';
            if (!ring) window.__rpiNoFocusRing.push(el);
        });""")
    total = d.execute_script(_SHOWN + "return [...document.querySelectorAll(arguments[0])]"
                                      ".filter(e => shown(e) && !e.disabled).length", _CONTROLS)
    actions = ActionChains(d)
    for _ in range(min(limit, total + 10)):
        actions.send_keys(Keys.TAB)
    actions.perform()
    return d.execute_script(_SHOWN + """
        const found = [];
        for (const el of document.querySelectorAll(arguments[0]))
            if (shown(el) && !el.disabled && !window.__rpiTabbed.has(el)) found.push('Tab never reaches ' + describe(el));
        for (const el of new Set(window.__rpiNoFocusRing))
            found.push('no visible focus on ' + describe(el));
        return found;
    """, _CONTROLS)


def set_dark(d, on):
    d.execute_cdp_cmd("Emulation.setEmulatedMedia",
                      {"features": [{"name": "prefers-color-scheme", "value": "dark" if on else "light"}]})
