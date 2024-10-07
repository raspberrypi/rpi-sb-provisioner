import os
import subprocess


def list_rpi_sb_units(service_name):
    output = subprocess.run(
        ["systemctl", "list-units", service_name, "-l", "--all", "--no-pager"],
        capture_output=True,
        text=True,
    )
    triage = []
    keywriter = []
    provisioner = []

    lines = output.stdout.split("\n")
    for line in lines:
        if "rpi-sb-" in line:
            name=line[line.find("rpi-sb-"):line.find(".service")]
            if "triage" in name:
                triage.append(name.replace("rpi-sb-triage@", ""))
            if "provisioner" in name:
                provisioner.append(name.replace("rpi-sb-provisioner@", ""))
    return [triage, keywriter, provisioner]


def list_working_units(service_name):
    output = subprocess.run(
        ["systemctl", "list-units", service_name, "-l", "--all", "--no-pager", "--plain"],
        capture_output=True,
        text=True,
    )
    units = []
    lines = output.stdout.split("\n")
    for line in lines:
        if "rpi-sb-" in line:
            if "failed" not in line:
                name=line[line.find("rpi-sb-"):line.find(".service")]
                if "triage" in name:
                    units.append(name.replace("rpi-sb-triage@", ""))
                if "provisioner" in name:
                    units.append(name.replace("rpi-sb-provisioner@", ""))
    return units


def list_failed_units(service_name):
    output = subprocess.run(
        ["systemctl", "list-units", service_name, "-l", "--all", "--no-pager", "--plain"],
        capture_output=True,
        text=True,
    )
    units = []
    lines = output.stdout.split("\n")
    for line in lines:
        if "rpi-sb-" in line:
            if "failed" in line:
                name=line[line.find("rpi-sb-"):line.find(".service")]
                if "triage" in name:
                    units.append(name.replace("rpi-sb-triage@", ""))
                if "provisioner" in name:
                    units.append(name.replace("rpi-sb-provisioner@", ""))
    return units


def list_seen_devices():
    output = subprocess.run(
        ["systemctl", "list-units", "rpi-sb-*", "-l", "--all", "--no-pager", "--plain"],
        capture_output=True,
        text=True,
    )
    units = []
    lines = output.stdout.split("\n")
    for line in lines:
        if "rpi-sb-provisioner" in line:
            name=line[line.find("rpi-sb-"):line.find(".service")]
            units.append(name.replace("rpi-sb-provisioner@", ""))
        
    return units


def list_completed_devices():
    all_devices = list_seen_devices()
    completed_devices = []
    for device in all_devices:
        if os.path.exists("/var/log/rpi-sb-provisioner/" + device + "/progress"):
            with open("/var/log/rpi-sb-provisioner/" + device + "/progress", "r") as f:
                status = f.read()
            if "PROVISIONER-FINISHED" in status:
                modified_time = os.stat("/var/log/rpi-sb-provisioner/" + device + "/progress").st_mtime_ns
                completed_devices.append((device, modified_time))
    return completed_devices


def list_failed_devices():
    all_devices = list_seen_devices()
    failed_devices = []
    for device in all_devices:
        if os.path.exists("/var/log/rpi-sb-provisioner/" + device + "/progress"):
            with open("/var/log/rpi-sb-provisioner/" + device + "/progress", "r") as f:
                status = f.read()
            if "PROVISIONER-ABORTED" in status or "KEYWRITER-ABORTED" in status:
                modified_time = os.stat("/var/log/rpi-sb-provisioner/" + device + "/progress").st_mtime_ns
                failed_devices.append((device, modified_time))
    return failed_devices


def list_device_files(device_name):
    device_files_dir = os.path.join("/var/log/rpi-sb-provisioner", device_name)
    try:
        ret = os.listdir(device_files_dir)
        if "metadata" in ret:
            ret.remove("metadata")
    except FileNotFoundError:
        return []
    else:
        return ret


def read_device_file(device_name, filename):
    device_file_path = os.path.join("/var/log/rpi-sb-provisioner", device_name, filename)
    try:
        with open(device_file_path, "r") as f:
            contents = f.read()
    except FileNotFoundError:
        return "Unable to read/open file!"
    else:
        return contents
