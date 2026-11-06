import sys

import yaml


with open(sys.argv[1], encoding="utf-8") as file:
    partitions = yaml.safe_load(file)["partition_table"]["partitions"]

boot = [p["payload"] for p in partitions if p.get("payload", {}).get("mountpoint") == "/boot"]
assert len(boot) == 1 and boot[0]["type"] == "ext4", "/boot must be ext4"
btrfs = [p for p in partitions if p.get("payload_type") == "btrfs"]
assert len(btrfs) == 1, "expected one Btrfs partition"
mounts = {v["mountpoint"] for v in btrfs[0]["payload"]["subvolumes"]}
assert {"/", "/home", "/var"} <= mounts, "missing Btrfs subvolumes"
