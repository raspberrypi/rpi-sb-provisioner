# Web UI tests

Browser tests for the 2.3 web interface. Headless Chromium drives the real package on a real provisioning station, with PAM, the systemd sandbox, udev and fastbootd all in play, so a test passes only if an operator would see the same.

## What you need

On the machine running the tests:

    sudo apt install python3-selenium chromium-driver

The station can be this machine or one reached over SSH, such as a virtual machine or a spare jig. It needs:

- `rpi-sb-provisioner` installed and the web interface running;
- an account in the `rpi-sb-provisioner` group for the tests to sign in as;
- passwordless `sudo` for the SSH user (or for you, when the station is this machine);
- the opt-in marker, since the tests rewrite configuration, databases and hooks:

      sudo touch /var/lib/rpi-sb-provisioner/ui-test-station

Never mark a station that provisions real devices. Everything the tests change is snapshotted before they start and put back afterwards, but a production station is not the place to find out whether that worked.

## Running

    export RPI_SB_TEST_SSH="ssh -i ~/.ssh/station-key user@station"   # omit for this machine
    export RPI_SB_TEST_USER=operator RPI_SB_TEST_PASSWORD=...
    export RPI_SB_TEST_OUTSIDER=someone RPI_SB_TEST_OUTSIDER_PASSWORD=...   # optional: an account outside the group
    test/ui/run.py                 # everything
    test/ui/run.py auth escaping   # test_auth.py and test_escaping.py
    test/ui/run.py -k revoke       # tests whose names contain "revoke"

Modules run one after another: they share the one station.

## Layout

- `harness/station.py`: commands on the station, the tunnel to its web interface, snapshot and restore.
- `harness/browser.py`: the signed-in browser, in-page requests, and the checks every page must pass (no JavaScript errors, no planted markup run, no alerts).
- `harness/case.py`: the base class the tests share.
- `test_*.py`: one module per area of the interface.
- `harness/legibility.py`: contrast and WCAG AA through axe-core, sideways scrolling, clipped text, covered controls, small text, and keyboard reach. `test_legibility.py` holds every page to all of them; `legibility_survey.py` reports them without failing, for looking into a new finding.
- `vendor/axe/`: axe-core, kept here because stations are often offline. See its README for where it came from.

Some tests need more of the station and skip without it. The hostile USB device in `test_escaping.py` needs a spare gadget controller, such as `dummy_hcd` loaded with `num=2`.
