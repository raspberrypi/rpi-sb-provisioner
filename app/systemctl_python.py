import subprocess
from os import listdir, path

def list_rpi_sb_units(service_name):
    output = subprocess.run(["systemctl", "list-units", service_name, "-l", "--all", "--no-pager"], capture_output=True)
    triage=[]
    keywriter=[]
    provisioner=[]

    lines = output.stdout.decode().split("\n")
    for line in lines:
        if "rpi-sb-" in line:
            name=line[line.find("rpi-sb-"):line.find(".service")]
            if "triage" in name:
                triage.append(name.replace("rpi-sb-triage@", ""))
            if "keywriter" in name:
                keywriter.append(name.replace("rpi-sb-keywriter@", ""))
            if "provisioner" in name:
                provisioner.append(name.replace("rpi-sb-provisioner@", ""))
    return [triage, keywriter, provisioner]

def list_working_units(service_name):
    output = subprocess.run(["systemctl", "list-units", service_name, "-l", "--all", "--no-pager"], capture_output=True)
    units=[]
    lines = output.stdout.decode().split("\n")
    for line in lines:
        if "rpi-sb-" in line:
            if not("failed" in line):
                name=line[line.find("rpi-sb-"):line.find(".service")]
                units.append(name)
    return units

def list_failed_units(service_name):
    output = subprocess.run(["systemctl", "list-units", service_name, "-l", "--all", "--no-pager"], capture_output=True)
    units=[]
    lines = output.stdout.decode().split("\n")
    for line in lines:
        if "rpi-sb-" in line:
            if "failed" in line:
                name=line[line.find("rpi-sb-"):line.find(".service")]
                units.append(name)
    return units

def list_seen_devices():
    if path.exists("/var/log/rpi-sb-provisioner/"):
        devices = listdir("/var/log/rpi-sb-provisioner")
        return devices
    else:
        return []

def list_completed_devices():
    all_devices = list_seen_devices()
    completed_devices = []
    for device in all_devices:
        if path.exists("/var/log/rpi-sb-provisioner/" + device + "/success"):
            f = open("/var/log/rpi-sb-provisioner/" + device + "/success", "r")
            status = f.read()
            if "1" in status:
                completed_devices.append(device)
            f.close()
    return completed_devices

def list_failed_devices():
    all_devices = list_seen_devices()
    failed_devices = []
    for device in all_devices:
        if path.exists("/var/log/rpi-sb-provisioner/" + device + "/finished"):
            if not(path.exists("/var/log/rpi-sb-provisioner/" + device + "/success")):
                f = open("/var/log/rpi-sb-provisioner/" + device + "/finished", "r")
                status = f.read()
                if "1" in status:
                    failed_devices.append(device)
                f.close()
    return failed_devices

def list_device_files(device_name):
    if path.exists("/var/log/rpi-sb-provisioner/" + device_name):
        return listdir("/var/log/rpi-sb-provisioner/" + device_name)
    else:
        return []

def read_device_file(device_name, filename):
    contents = "Unable to read/open file!"
    if path.exists("/var/log/rpi-sb-provisioner/" + device_name + "/" + filename):
        f = open("/var/log/rpi-sb-provisioner/" + device_name + "/" + filename, "r")
        contents = f.read()
        f.close()
    return contents