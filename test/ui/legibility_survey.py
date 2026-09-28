#!/usr/bin/env python3
"""Runs every legibility check over every page and reports what it finds.

A survey, not a test: it fails nothing, and exists to see the backlog before
the suite decides what to enforce. Same environment as run.py.

    test/ui/legibility_survey.py [--json findings.json]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ui.harness import legibility as L  # noqa: E402
from ui.harness.browser import Browser  # noqa: E402
from ui.harness.case import station  # noqa: E402

SERIAL = "10000000fedcba98"
SIGNED_OUT = ["/login", "/devices", f"/devices/{SERIAL}", "/scantool"]
SIGNED_IN = ["/devices", f"/devices/{SERIAL}", "/devices#rel", "/options/get", "/devices#topo", "/customisation/list-scripts",
             "/customisation/get-script?script=naked-provisioner-post-flash", "/services",
             f"/service-log/rpi-sb-triage@{SERIAL}.service", "/manu-db", "/auditlog",
             "/auth/tokens", "/scantool", "/no-such-page"]
WIDTHS = [375, 768, 1280, 1920]


def survey(b, page, findings):
    d = b.d
    for w in WIDTHS:
        d.set_window_size(w, 1000)
        b.get(page)
        for check in (L.overflow, L.covered, L.small_text):
            for f in check(d):
                findings.append({"page": page, "width": w, "check": check.__name__, "finding": f})
    d.set_window_size(1280, 1000)
    for dark in (False, True):
        L.set_dark(d, dark)
        b.get(page)
        for rule, impact, help_, nodes, count in L.audit(d, ["color-contrast"] if dark else None):
            findings.append({"page": page, "width": 1280, "check": "audit-dark" if dark else "audit",
                             "finding": f"{rule} ({impact}, {count}x): {help_}", "nodes": nodes})
    L.set_dark(d, False)
    b.get(page)
    for f in L.keyboard(d):
        findings.append({"page": page, "width": 1280, "check": "keyboard", "finding": f})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()
    s = station()
    b = Browser(s.url)
    findings = []
    try:
        for page in SIGNED_OUT:
            survey(b, page, findings)
            for f in findings:
                f.setdefault("as", "signed out")
        b.sign_in()
        for page in SIGNED_IN:
            survey(b, page, findings)
            for f in findings:
                f.setdefault("as", "operator")
    finally:
        b.quit()
    if args.json:
        with open(args.json, "w") as f:
            json.dump(findings, f, indent=1)
    by = {}
    for f in findings:
        by.setdefault((f["as"], f["page"]), []).append(f)
    for (who, page), fs in by.items():
        print(f"\n== {page} ({who}): {len(fs)}")
        seen = set()
        for f in fs:
            key = (f["check"], f["finding"])
            if key in seen:
                continue
            seen.add(key)
            widths = sorted({g["width"] for g in fs if (g["check"], g["finding"]) == key})
            print(f"  [{f['check']}] {f['finding']}  @{','.join(map(str, widths))}")
    print(f"\n{len(findings)} findings")


if __name__ == "__main__":
    main()
