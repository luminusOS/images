import argparse
import hashlib
import io
import os
import shutil
import tarfile
import urllib.request
from pathlib import Path

TOOLS = {
    "syft": (
        "1.34.2",
        "b62a3d4167f9a04bc190a5e654b05711737527ed47b616dc398e541f903c2d72",
    ),
    "grype": (
        "0.101.1",
        "3a1aba2db34d034e2443336e5fc78154651ee2820c74ff8c5602a2b6eec84a89",
    ),
}


def install(name: str, destination: Path) -> None:
    version, expected = TOOLS[name]
    filename = f"{name}_{version}_linux_amd64.tar.gz"
    url = f"https://github.com/anchore/{name}/releases/download/v{version}/{filename}"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(100_000_001)
    if len(data) > 100_000_000 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"{name} archive checksum mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = [member for member in archive.getmembers() if member.name == name]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError(f"invalid {name} archive")
        source = archive.extractfile(members[0])
        if source is None:
            raise ValueError(f"missing {name} executable")
        target = destination / name
        with source, target.open("wb") as output:
            shutil.copyfileobj(source, output)
        os.chmod(target, 0o755)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    for name in TOOLS:
        install(name, args.destination)


if __name__ == "__main__":
    main()
