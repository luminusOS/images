#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from qemu_common import resolve_ovmf


def count_colors(path):
    with Path(path).open("rb") as image:
        if image.readline().strip() != b"P6":
            raise ValueError("not a P6 PPM")
        tokens = []
        while len(tokens) < 3:
            line = image.readline()
            if not line:
                raise ValueError("incomplete PPM header")
            if not line.startswith(b"#"):
                tokens.extend(line.split())
        width, height, maximum = map(int, tokens)
        if width <= 0 or height <= 0 or maximum != 255:
            raise ValueError("invalid PPM dimensions or color depth")
        data = image.read(width * height * 3)
        if len(data) != width * height * 3:
            raise ValueError("incomplete PPM data")
        return len({data[i : i + 3] for i in range(0, len(data) - 2, 12)})


def screendump(socket_path, image_path):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(str(socket_path))
        stream = conn.makefile("rwb", buffering=0)
        greeting = json.loads(stream.readline())
        if "QMP" not in greeting:
            raise ValueError("invalid QMP greeting")
        for command in (
            {"execute": "qmp_capabilities"},
            {
                "execute": "screendump",
                "arguments": {"filename": str(image_path.resolve())},
            },
        ):
            stream.write(json.dumps(command).encode() + b"\n")
            while True:
                response = json.loads(stream.readline())
                if "error" in response:
                    raise ValueError(f"QMP error: {response['error']}")
                if "return" in response:
                    break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("iso", "disk"))
    parser.add_argument("image", type=Path)
    parser.add_argument("outdir", type=Path, nargs="?", default=Path("boot-test-out"))
    args = parser.parse_args()
    if not args.image.is_file():
        parser.error(f"image does not exist: {args.image}")
    args.outdir.mkdir(parents=True, exist_ok=True)
    proc = None
    old_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        code, template = resolve_ovmf(os.environ)
        variables = args.outdir / "vars.fd"
        shutil.copyfile(template, variables)
        qmp = args.outdir / "qmp.sock"
        command = [
            "qemu-system-x86_64",
            "-machine",
            "q35",
            "-m",
            "6G",
            "-smp",
            "2",
            "-display",
            "none",
            "-vga",
            "virtio",
            "-serial",
            f"file:{args.outdir / 'serial.log'}",
            "-qmp",
            f"unix:{qmp},server,nowait",
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive",
            f"if=pflash,format=raw,file={variables}",
        ]
        command += (
            ["-enable-kvm", "-cpu", "host"]
            if os.access("/dev/kvm", os.W_OK)
            else ["-cpu", "max"]
        )
        command += (
            ["-cdrom", str(args.image), "-boot", "d"]
            if args.mode == "iso"
            else ["-snapshot", "-drive", f"file={args.image},format=qcow2,if=virtio"]
        )
        proc = subprocess.Popen(command, start_new_session=True)
        shot = None
        final_screenshot_ok = False
        for elapsed in range(30, (420 if args.mode == "iso" else 300) + 1, 30):
            time.sleep(30)
            if proc.poll() is not None:
                raise RuntimeError("QEMU exited early")
            shot = args.outdir / f"screen-{elapsed:03}.ppm"
            final_screenshot_ok = False
            try:
                screendump(qmp, shot)
                final_screenshot_ok = True
            except (OSError, ValueError, json.JSONDecodeError) as error:
                print(f"QMP screenshot failed: {error}", file=sys.stderr)
        if not final_screenshot_ok or shot is None or not shot.is_file():
            raise RuntimeError("final screenshot missing")
        colors = count_colors(shot)
        print(f"Final screendump has {colors} distinct sampled colors (minimum 64)")
        if shutil.which("tesseract"):
            subprocess.run(
                ["tesseract", str(shot), str(args.outdir / "final-screen")],
                stderr=subprocess.DEVNULL,
                check=False,
            )
            ocr_output = args.outdir / "final-screen.txt"
            if ocr_output.is_file():
                text = ocr_output.read_text(errors="replace")
                print(f"--- OCR of final screen ---\n{text}")
                print(
                    "OCR: recognized expected installer/setup wording"
                    if re.search(
                        r"sirius|luminus|install|setup|welcome", text, re.IGNORECASE
                    )
                    else "OCR: expected wording not found (advisory only)"
                )
        return int(colors < 64)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"boot-test: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except ProcessLookupError:
                proc.wait()
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())
