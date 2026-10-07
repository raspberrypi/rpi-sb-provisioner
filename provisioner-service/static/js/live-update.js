// Gentle live updates for pages that poll: services, a service log and the
// manufacturing database. Rebuilding a table every few seconds threw away
// whatever an operator had selected to copy, and their keyboard focus. These
// helpers change only what changed, hold an update while text is selected,
// and stop polling while the page cannot be seen.
(function () {
    'use strict';

    function sameAttributes(from, to) {
        for (const a of [...from.attributes]) {
            if (!to.hasAttribute(a.name)) from.removeAttribute(a.name);
        }
        for (const a of [...to.attributes]) {
            if (from.getAttribute(a.name) !== a.value) from.setAttribute(a.name, a.value);
        }
    }

    function key(node) {
        return node.nodeType === Node.ELEMENT_NODE ? node.getAttribute('data-key') : null;
    }

    // Make `from` look like `to`, touching only nodes that differ. Children
    // with a data-key are matched by key, so a row added at the top leaves
    // the rows below it, and any selection in them, alone.
    function morph(from, to) {
        if (from.nodeType === Node.TEXT_NODE || from.nodeType === Node.COMMENT_NODE) {
            if (from.data !== to.data) from.data = to.data;
            return;
        }
        sameAttributes(from, to);
        const keyed = new Map();
        for (const c of from.childNodes) {
            const k = key(c);
            if (k !== null) keyed.set(k, c);
        }
        let cursor = from.firstChild;
        for (const want of [...to.childNodes]) {
            const k = key(want);
            const have = k !== null ? keyed.get(k) : (cursor && key(cursor) === null ? cursor : null);
            if (have && k !== null) keyed.delete(k);
            if (have && have.nodeType === want.nodeType && have.nodeName === want.nodeName) {
                if (have !== cursor) from.insertBefore(have, cursor);
                morph(have, want);
                cursor = have.nextSibling;
            } else {
                if (have) {
                    if (have === cursor) cursor = cursor.nextSibling;
                    from.removeChild(have);
                }
                from.insertBefore(want, cursor);
            }
        }
        while (cursor) {
            const next = cursor.nextSibling;
            from.removeChild(cursor);
            cursor = next;
        }
    }

    // Replace el's contents with html, gently.
    function update(el, html) {
        const next = el.cloneNode(false);
        next.innerHTML = html;
        morph(el, next);
    }

    function selecting(el) {
        const s = window.getSelection();
        if (!s || s.isCollapsed || !s.rangeCount) return false;
        return el.contains(s.getRangeAt(0).commonAncestorContainer);
    }

    // Run fn now, or once nothing inside el is selected. Only the latest
    // update is kept. status, if given, says an update is waiting.
    const held = new Map();
    function whenFree(el, fn, status) {
        if (!selecting(el)) { fn(); return; }
        if (status && !held.has(el)) {
            status.dataset.before = status.textContent;
            status.textContent = '(Paused while text is selected)';
        }
        held.set(el, { fn: fn, status: status });
    }
    document.addEventListener('selectionchange', function () {
        for (const [el, h] of [...held]) {
            if (selecting(el)) continue;
            held.delete(el);
            if (h.status && h.status.dataset.before !== undefined) {
                h.status.textContent = h.status.dataset.before;
                delete h.status.dataset.before;
            }
            h.fn();
        }
    });

    // Call fn every ms while the page is visible, and once when it becomes
    // visible again. Returns a function that stops it.
    function poll(fn, ms) {
        const timer = setInterval(function () { if (!document.hidden) fn(); }, ms);
        function shown() { if (!document.hidden) fn(); }
        document.addEventListener('visibilitychange', shown);
        return function stop() {
            clearInterval(timer);
            document.removeEventListener('visibilitychange', shown);
        };
    }

    window.RpiLive = { morph: morph, update: update, whenFree: whenFree, poll: poll, selecting: selecting };
})();
