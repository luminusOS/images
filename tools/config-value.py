#!/usr/bin/env python3
import argparse
import sys

from config_values import read_config

KEYS = {
    "DEFAULT_FEDORA_VERSION",
    "FEDORA_BOOTC_DIGEST",
    "AURORA_SHELL_VERSION",
    "AURORA_SHELL_SHA256",
    "ELASTIC_SWAP_VERSION",
    "ELASTIC_SWAP_SHA256",
    "SIRIUS_VERSION",
    "SIRIUS_RPM_VERSION",
    "UPDATE_CHANNEL",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("key")
    args = parser.parse_args()
    try:
        values = read_config()
        if args.key not in KEYS or args.key not in values:
            raise ValueError(f"Unknown configuration key: {args.key}")
        print(values[args.key])
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
