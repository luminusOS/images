#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
import sys

MAJOR = (
    "kernel-core",
    "linux-firmware",
    "mesa-dri-drivers",
    "gnome-shell",
    "mutter",
    "nautilus",
    "bootc",
    "systemd",
    "NetworkManager",
    "pipewire",
    "flatpak",
    "podman",
)


def rpm_list(image):
    command = (
        shlex.split(os.environ["RPM_LIST_CMD"]) + [image]
        if os.environ.get("RPM_LIST_CMD")
        else [
            "podman",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "rpm",
            image,
            "-qa",
            "--qf",
            "%{NAME} %{VERSION}-%{RELEASE}\n",
        ]
    )
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return sorted(result.stdout.splitlines())


def versions(lines):
    result = {}
    for line in lines:
        fields = line.split()
        if len(fields) >= 2:
            result.setdefault(fields[0], fields[1])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("new_image")
    parser.add_argument("new_tag")
    parser.add_argument("prev_image", nargs="?", default="")
    parser.add_argument("prev_tag", nargs="?", default="")
    args = parser.parse_args()
    try:
        new_list = rpm_list(args.new_image)
        previous_list = rpm_list(args.prev_image) if args.prev_image else []
        now, before = versions(new_list), versions(previous_list)
        print(
            f"This is an automatically generated changelog for release {args.new_tag}.\n"
        )
        print(
            f"From previous testing version {args.prev_tag} there have been the following changes."
            if args.prev_tag
            else "This is the first automatic testing release, so there is nothing to compare against."
        )
        print(
            "\n### Major packages\n\n| Name | Version | Previous |\n| --- | --- | --- |"
        )
        for name in MAJOR:
            if name in now:
                old = before.get(name, "")
                previous = f"{old} " if old and old != now[name] else ""
                print(f"| {name} | {now[name]} | {previous}|")
        if args.prev_image:
            changed = {
                line.split()[0]
                for line in set(new_list) - set(previous_list)
                if line.split()
            }
            print(f"\n{len(changed)} packages were added or updated in total.")
        print("\n### Commits\n")
        tag_ref = f"refs/tags/{args.prev_tag}"
        valid = (
            bool(args.prev_tag)
            and subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", f"{tag_ref}^{{commit}}"],
                stdout=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
        git = ["git", "log", "--no-merges", "--format=%h%x1f%s%x1f%an"] + (
            [f"{tag_ref}..HEAD"] if valid else ["-n", "10"]
        )
        result = subprocess.run(git, capture_output=True, text=True, check=False)
        rows = []
        for line in result.stdout.splitlines():
            fields = line.split("\x1f")
            if len(fields) == 3:
                subject = (
                    fields[1]
                    .translate(str.maketrans("", "", "`<>"))
                    .replace("|", r"\|")
                )
                rows.append(f"| {fields[0]} | {subject} | {fields[2]} |")
        if rows:
            print("| Hash | Subject | Author |\n| --- | --- | --- |")
            print("\n".join(rows))
        else:
            print(
                "No repository changes since the previous release; the Fedora base was updated."
            )
        print(
            f"\n### How to rebase\n\n```\nsudo bootc switch {args.new_image.removeprefix('docker://')}\n```\n"
        )
        print("Already on this branch? `sudo bootc upgrade` is enough.")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"release-notes: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
