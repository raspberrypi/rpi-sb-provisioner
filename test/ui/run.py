#!/usr/bin/env python3
"""Runs the UI tests against a provisioning station. See README.md.

    test/ui/run.py                 every module
    test/ui/run.py auth options    test_auth.py and test_options.py only
    test/ui/run.py -k revoke       tests whose names contain "revoke"
"""
import argparse
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("modules", nargs="*", help="module names without test_ and .py")
    ap.add_argument("-k", dest="pattern", action="append", help="only tests matching this")
    ap.add_argument("-f", "--failfast", action="store_true")
    args = ap.parse_args()

    loader = unittest.TestLoader()
    if args.pattern:
        loader.testNamePatterns = [f"*{p}*" for p in args.pattern]
    if args.modules:
        suite = unittest.TestSuite(loader.loadTestsFromName(f"ui.test_{m}") for m in args.modules)
    else:
        suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=os.path.dirname(HERE))
    result = unittest.TextTestRunner(verbosity=2, failfast=args.failfast).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
