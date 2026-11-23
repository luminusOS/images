#!/usr/bin/env python3
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET


def guestfish(image, commands, *, readonly):
    return subprocess.run(
        ["guestfish", "--ro" if readonly else "--rw", "-a", image],
        input="run\n" + "\n".join(commands) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout


def require_backed_overlay(image):
    info = json.loads(subprocess.check_output(
        ["qemu-img", "info", "-f", "qcow2", "--output=json", image],
    ))
    if info.get("backing-filename-format") != "qcow2" or not info.get("backing-filename"):
        raise ValueError("expected a qcow2 overlay with an explicit qcow2 backing image")


def prepare(image, public_key):
    require_backed_overlay(image)
    filesystems = guestfish(image, ["list-filesystems"], readonly=True)
    roots = re.findall(r"^(btrfsvol:/dev/[a-z0-9]+/root): btrfs$", filesystems, re.M)
    if len(roots) != 1:
        raise ValueError("expected one image-builder Btrfs root subvolume")
    mount = f"mount {roots[0]} /"
    etcs = [path.rstrip("/") for path in guestfish(
        image, [mount, "glob echo /ostree/deploy/*/deploy/*/etc"], readonly=True,
    ).split()]
    if len(etcs) != 1 or not re.fullmatch(
        r"/ostree/deploy/[A-Za-z0-9_-]+/deploy/[a-f0-9]{64}\.[0-9]+/etc", etcs[0],
    ):
        raise ValueError("expected one OSTree deployment in the pristine candidate")
    etc = etcs[0]
    zone_path = f"{etc}/firewalld/zones/public.xml"
    zone = ET.fromstring(guestfish(image, [mount, f"cat {zone_path}"], readonly=True))
    if zone.tag != "zone":
        raise ValueError("expected the workstation public firewalld zone")
    add_ssh = not any(service.get("name") == "ssh" for service in zone.findall("service"))
    if add_ssh:
        ET.SubElement(zone, "service", name="ssh")
    with tempfile.TemporaryDirectory(prefix="candidate-access-") as tmp:
        archive = Path(tmp) / "ssh.tar"
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
            for path, data, mode in (
                ("ssh/boot-test-authorized-keys", Path(public_key).read_bytes(), 0o600),
                ("ssh/sshd_config.d/05-luminusos-boot-test.conf",
                 b"AuthorizedKeysFile /etc/ssh/boot-test-authorized-keys\n"
                 b"PermitRootLogin prohibit-password\n", 0o644),
            ):
                entry = tarfile.TarInfo(path)
                entry.size = len(data)
                entry.mode = mode
                entry.pax_headers["SCHILY.xattr.security.selinux"] = "system_u:object_r:etc_t:s0\0"
                tar.addfile(entry, io.BytesIO(data))
        commands = [mount, f"tar-in {shlex.quote(str(archive))} {etc} xattrs:true"]
        if add_ssh:
            zone_file = Path(tmp) / "public.xml"
            ET.ElementTree(zone).write(zone_file, encoding="utf-8", xml_declaration=True)
            commands.append(f"upload {shlex.quote(str(zone_file))} {zone_path}")
        system = f"{etc}/systemd/system"
        guestfish(image, [
            *commands, f"mkdir-p {system}/multi-user.target.wants",
            f"ln-sf /usr/lib/systemd/system/sshd.service {system}/multi-user.target.wants/sshd.service",
            f"ln-sf /dev/null {system}/bootc-fetch-apply-updates.timer", "sync",
        ], readonly=False)


if __name__ == "__main__":
    prepare(*sys.argv[1:])
