import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

HOSTS = ("archive.ubuntu.com", "security.ubuntu.com")
ENDPOINTS = (
    "https://archive.ubuntu.com/ubuntu/dists/noble/InRelease",
    "https://security.ubuntu.com/ubuntu/dists/noble-security/InRelease",
)
SOURCE_FILES = (
    "/etc/apt/apt-mirrors.txt",
    "/etc/apt/sources.list.d/ubuntu.sources",
    "/etc/apt/sources.list",
)
PUBLIC_HOSTS = {*HOSTS, "azure.archive.ubuntu.com"}


def command(arguments, timeout):
    try:
        result = subprocess.run(
            arguments,
            env={"PATH": os.defpath},
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return "unknown", ""


def source_summary(path):
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            text = stream.read(65536)
    except FileNotFoundError:
        return {"exists": False, "ubuntu_hosts": [], "suites": []}
    except OSError:
        return {"exists": "unknown", "ubuntu_hosts": [], "suites": []}
    hosts = set()
    for candidate in re.findall(r"https?://[^\s]+", text):
        try:
            host = urlsplit(candidate).hostname
        except ValueError:
            continue
        if host in PUBLIC_HOSTS:
            hosts.add(host)
    suites = re.findall(r"\bnoble(?:-updates|-backports|-security)?\b", text)
    return {
        "exists": True,
        "ubuntu_hosts": sorted(hosts),
        "suites": sorted(set(suites)),
    }


def collect():
    _, version = command(["apt-get", "--version"], 5)
    header = (version.splitlines() or [""])[0]
    match = re.match(r"apt ([0-9]+(?:\.[0-9]+)+)(?:\s|[a-z+~])", header)
    report = {
        "apt_version": match.group(1) if match else "unknown",
        "dns": [],
        "https": [],
        "sources": {name: source_summary(Path(name)) for name in SOURCE_FILES},
    }
    for host in HOSTS:
        code, output = command(["getent", "ahostsv4", host], 5)
        report["dns"].append(
            {
                "host": host,
                "returncode": code,
                "resolved": code == 0 and bool(output.strip()),
            }
        )
    for endpoint in ENDPOINTS:
        code, output = command(
            [
                "curl",
                "--disable",
                "--fail",
                "--silent",
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                endpoint,
            ],
            20,
        )
        status = output.strip()
        report["https"].append(
            {
                "endpoint": endpoint,
                "returncode": code,
                "http_status": status
                if re.fullmatch(r"[0-9]{3}", status)
                else "unknown",
            }
        )
    return report


def main():
    print(json.dumps(collect(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
