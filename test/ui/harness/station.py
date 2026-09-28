"""The provisioning station the UI tests run against.

The tests drive the real package on a real host: PAM, the systemd sandbox,
udev and all. That host is either this machine or one reached over SSH:

    RPI_SB_TEST_SSH   ssh command line for the station, for example
                      "ssh -i ~/.ssh/vmkey -p 2222 tdewey@127.0.0.1".
                      Unset: the station is this machine.

The SSH user needs passwordless sudo there. The tests rewrite configuration,
databases and hooks, so a station must opt in by carrying MARKER; everything
touched is snapshotted first and put back afterwards.
"""
import os
import shlex
import socket
import subprocess
import time
import urllib.request

MARKER = "/var/lib/rpi-sb-provisioner/ui-test-station"
UI_PORT = 3142
SNAPSHOT = "/var/tmp/rpi-sb-ui-test-snapshot.tar"
# Everything a test may change. Images the tests add are named uitest-*.
KEPT = [
    "/etc/rpi-sb-provisioner",
    "/srv/rpi-sb-provisioner/state.db",
    "/srv/rpi-sb-provisioner/manufacturing.db",
    "/srv/rpi-sb-provisioner/audit.db",
]


class StationError(RuntimeError):
    pass


class Station:
    def __init__(self):
        self.ssh = shlex.split(os.environ.get("RPI_SB_TEST_SSH", ""))
        self._tunnel = None
        self.url = None

    # --- commands -------------------------------------------------------

    def sh(self, script, check=True, timeout=120):
        """Runs a POSIX sh script as root on the station; returns stdout."""
        cmd = (self.ssh + ["-o", "BatchMode=yes", "sudo", "-n", "sh", "-s"]) if self.ssh \
            else ["sudo", "-n", "sh", "-s"]
        p = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise StationError(f"station script failed ({p.returncode}):\n{script}\n--- stderr\n{p.stderr}")
        return p.stdout

    def put(self, path, data, mode="0644"):
        """Writes bytes or text to a root-owned file on the station."""
        if isinstance(data, str):
            data = data.encode()
        cmd = (self.ssh + ["-o", "BatchMode=yes", "sudo", "-n", "sh", "-c"]) if self.ssh \
            else ["sudo", "-n", "sh", "-c"]
        inner = f"cat > {shlex.quote(path)} && chmod {mode} {shlex.quote(path)}"
        subprocess.run(cmd + [inner if not self.ssh else shlex.quote(inner)],
                       input=data, check=True, timeout=120)

    def sql(self, db, statement):
        return self.sh(f"sqlite3 {shlex.quote(db)} <<'SQL'\n{statement}\nSQL\n")

    def config(self):
        """The station's /etc/rpi-sb-provisioner/config as a dict (raw values)."""
        out = self.sh("cat /etc/rpi-sb-provisioner/config 2>/dev/null || true")
        values = {}
        for line in out.splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                values[k] = v
        return values

    def set_config(self, **values):
        """Sets config keys directly, bypassing the UI."""
        script = "C=/etc/rpi-sb-provisioner/config; touch $C; chmod 0600 $C\n"
        for k, v in values.items():
            script += f"sed -i '/^{k}=/d' $C\n"
            if v is not None:
                script += f"printf '%s\\n' {shlex.quote(f'{k}={v}')} >> $C\n"
        self.sh(script)

    def journal(self, unit, since):
        return self.sh(f"journalctl -u {shlex.quote(unit)} --since {shlex.quote(since)} -o cat --no-pager")

    def now(self):
        return self.sh("date '+%Y-%m-%d %H:%M:%S'").strip()

    # --- lifecycle ------------------------------------------------------

    def check_opted_in(self):
        if self.sh(f"test -e {MARKER} && echo yes || true").strip() != "yes":
            raise StationError(
                f"{self.describe()} is not marked as a UI test station. The tests rewrite its "
                f"configuration and databases; if that is fine, run there: sudo touch {MARKER}")

    def describe(self):
        return "this machine" if not self.ssh else "station " + " ".join(self.ssh[-1:])

    def snapshot(self):
        kept = " ".join(shlex.quote(p) for p in KEPT)
        self.sh(f"tar -cpf {SNAPSHOT} --ignore-failed-read {kept} 2>/dev/null; test -s {SNAPSHOT}")

    def restore(self):
        kept = " ".join(shlex.quote(p) for p in KEPT)
        self.sh(f"""
            systemctl stop rpi-provisioner-ui
            rm -rf {kept}
            tar -xpf {SNAPSHOT} -C /
            rm -f /srv/rpi-sb-provisioner/images/uitest-*
            systemctl start rpi-provisioner-ui
        """)
        self.wait_for_ui()

    def restart_ui(self):
        self.sh("systemctl restart rpi-provisioner-ui")
        self.wait_for_ui()

    # --- reaching the UI ------------------------------------------------

    def open(self):
        """Makes the station's UI reachable at self.url."""
        if not self.ssh:
            self.url = f"http://127.0.0.1:{UI_PORT}"
        else:
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            self._tunnel = subprocess.Popen(
                self.ssh + ["-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15",
                            "-L", f"127.0.0.1:{port}:127.0.0.1:{UI_PORT}"],
                stdin=subprocess.DEVNULL, start_new_session=True)
            self.url = f"http://127.0.0.1:{port}"
        self.wait_for_ui()

    def close(self):
        if self._tunnel:
            self._tunnel.terminate()
            self._tunnel.wait(timeout=10)
            self._tunnel = None

    def wait_for_ui(self, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(self.url + "/login", timeout=3).read()
                return
            except Exception:
                time.sleep(1)
        raise StationError(f"the web UI did not answer at {self.url}")
