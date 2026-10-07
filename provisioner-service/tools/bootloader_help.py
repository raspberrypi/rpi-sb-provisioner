#!/usr/bin/env python3
"""Builds static/js/bootloader-help.json, the bootloader configuration editor's
help, from the Raspberry Pi Documentation. The UI serves it from
/options/bootloader-config/help.

The text is the documentation's own (CC BY-SA 4.0), taken at a pinned commit
so the help matches what was reviewed and ships to stations that are offline.
To refresh it, change COMMIT, run this script, and review the difference.

    provisioner-service/tools/bootloader_help.py [--from file.adoc]
"""
import argparse
import html
import json
import os
import re
import urllib.request

COMMIT = "3fa55d7c8d309355f977fd93ddec9aecd38898a8"
PATH = "documentation/asciidoc/computers/raspberry-pi/eeprom-bootloader.adoc"
SOURCE = f"https://raw.githubusercontent.com/raspberrypi/documentation/{COMMIT}/{PATH}"
SITE = "https://www.raspberrypi.com/documentation/computers/"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "static", "js", "bootloader-help.json")


def inline(text):
    """AsciiDoc inline markup to HTML; everything else is escaped."""
    out, pos = [], 0
    pattern = re.compile(r"`([^`]+)`|xref:([\w.-]+)\.adoc(#[\w-]+)?\[([^\]]*)\]"
                         r"|(https?://[^\s\[]+)\[([^\]]*)\]|<<([\w-]+)(?:,([^>]*))?>>")
    for m in pattern.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        if m.group(1) is not None:
            out.append(f"<code>{html.escape(m.group(1))}</code>")
        elif m.group(2) is not None:
            url = SITE + m.group(2) + ".html" + (m.group(3) or "")
            out.append(f'<a href="{html.escape(url)}" target="_blank" rel="noopener">{html.escape(m.group(4) or url)}</a>')
        elif m.group(5) is not None:
            out.append(f'<a href="{html.escape(m.group(5))}" target="_blank" rel="noopener">'
                       f"{html.escape(m.group(6) or m.group(5))}</a>")
        else:
            key = m.group(7)
            out.append(f'<a href="#" data-setting="{html.escape(key)}">{html.escape(m.group(8) or key)}</a>')
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return "".join(out)


def block(lines):
    """One setting's body to HTML: paragraphs, lists, tables, code, notes."""
    out, para, i = [], [], 0

    def flush():
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            flush()
        elif line.startswith("[source") or line.startswith("[cols") or line.startswith("[.") \
                or line.startswith("[options") or line == "[%header]":
            flush()
        elif line.startswith("----"):
            flush()
            j = i + 1
            while j < len(lines) and not lines[j].startswith("----"):
                j += 1
            out.append("<pre>" + html.escape("\n".join(lines[i + 1:j])) + "</pre>")
            i = j
        elif line.startswith("|==="):
            flush()
            j = i + 1
            while j < len(lines) and not lines[j].startswith("|==="):
                j += 1
            cells = [c.strip() for c in re.split(r"(?m)^\|\s?|\s\|\s", "\n".join(lines[i + 1:j])) if c.strip()]
            header = [c.strip() for c in lines[i + 1].split("|") if c.strip()] if i + 1 < j else []
            width = len(header) or 1
            rows = [cells[k:k + width] for k in range(0, len(cells), width)]
            t = "<table>"
            for n, row in enumerate(rows):
                tag = "th" if n == 0 and header else "td"
                t += "<tr>" + "".join(f"<{tag}>{inline(c)}</{tag}>" for c in row) + "</tr>"
            out.append(t + "</table>")
            i = j
        elif re.match(r"^=+ ", line):
            flush()
            out.append("<h5>" + inline(line.lstrip("= ")) + "</h5>")
        elif re.match(r"^(NOTE|TIP|WARNING|IMPORTANT|CAUTION): ", line):
            flush()
            kind, rest = line.split(": ", 1)
            para.append(rest)
            j = i + 1
            while j < len(lines) and lines[j].strip():
                para.append(lines[j].strip())
                j += 1
            out.append(f'<p class="note"><strong>{kind.title()}:</strong> ' + inline(" ".join(para)) + "</p>")
            para.clear()
            i = j
        elif re.match(r"^\*+ ", line):
            flush()
            items = []
            while i < len(lines) and re.match(r"^\*+ ", lines[i]):
                items.append("<li>" + inline(lines[i].lstrip("* ").rstrip()) + "</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        else:
            para.append(line.strip())
        i += 1
    flush()
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src")
    args = ap.parse_args()
    if args.src:
        with open(args.src, encoding="utf-8") as f:
            text = f.read()
    else:
        with urllib.request.urlopen(SOURCE, timeout=60) as r:
            text = r.read().decode("utf-8")
    settings, current, body = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^\[\[([A-Za-z0-9_]+)\]\]$", line)
        if m:
            if current:
                settings[current] = block(body)
            current, body = m.group(1), []
            continue
        if current is None:
            continue
        if re.match(r"^==== `?" + re.escape(current) + r"`?$", line):
            continue
        body.append(line)
    if current:
        settings[current] = block(body)
    settings.pop("config_txt", None)  # config.txt in the EEPROM, not a setting
    doc = {
        "source": SITE + "raspberry-pi.html#raspberry-pi-bootloader-configuration",
        "commit": COMMIT,
        "licence": "CC BY-SA 4.0",
        "attribution": "Raspberry Pi Documentation, (c) Raspberry Pi Ltd, "
                       "licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)",
        "settings": settings,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    print(f"{len(settings)} settings -> {OUT}")


if __name__ == "__main__":
    main()
