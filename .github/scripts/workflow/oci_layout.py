import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYERS = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}
REF = "org.opencontainers.image.ref.name"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
IMAGE = re.compile(
    r"(?:[a-z0-9][a-z0-9._-]*(?::[0-9]+)?/)*"
    r"[a-z0-9][a-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z"
)
MAX_JSON_BYTES = 1024 * 1024
MAX_LAYER_BYTES = 20 * 1024**3
MAX_LAYERS = 256
CHUNK_BYTES = 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(path):
    path = Path(path)
    require(".." not in path.parts, "parent traversal forbidden")
    return path.absolute()


@contextmanager
def directory(path):
    path = safe_path(path)
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def subdirectory(parent, name):
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def contents(parent, name, limit, expected=None, collect=True):
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=parent,
    )
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "not a regular OCI file")
        require(0 < info.st_size <= limit, "OCI file size limit exceeded")
        if expected is not None:
            require(info.st_size == expected["size"], "OCI blob size mismatch")
        checksum = hashlib.sha256()
        chunks = []
        total = 0
        while chunk := stream.read(CHUNK_BYTES):
            total += len(chunk)
            require(
                total <= info.st_size and total <= limit, "OCI file grew during read"
            )
            checksum.update(chunk)
            if collect:
                chunks.append(chunk)
        require(total == info.st_size, "OCI file size changed during read")
        if expected is not None:
            require(
                "sha256:" + checksum.hexdigest() == expected["digest"],
                "OCI blob digest mismatch",
            )
        return b"".join(chunks) if collect else None


def document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate OCI JSON key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"invalid OCI JSON constant: {value}")

    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite OCI JSON number")
        return number

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique,
        parse_constant=invalid_constant,
        parse_float=finite_float,
    )
    require(isinstance(value, dict), "OCI JSON must be an object")
    return value


def fields(value, required, optional=()):
    require(
        isinstance(value, dict)
        and set(required) <= value.keys()
        and value.keys() <= set(required) | set(optional),
        "invalid OCI object fields",
    )
    if "annotations" in value:
        require(
            isinstance(value["annotations"], dict)
            and all(isinstance(v, str) for v in value["annotations"].values()),
            "invalid OCI annotations",
        )


def platform(value):
    require(
        isinstance(value, dict)
        and value.get("os") == "linux"
        and value.get("architecture") == "amd64",
        "OCI platform must be linux/amd64",
    )


def blob(root, descriptor, media_types, json_blob=False):
    fields(descriptor, {"mediaType", "digest", "size"}, {"annotations", "platform"})
    require(
        isinstance(descriptor["mediaType"], str)
        and descriptor["mediaType"] in media_types,
        "unsupported OCI blob mediaType",
    )
    require(
        isinstance(descriptor["digest"], str)
        and DIGEST.fullmatch(descriptor["digest"]),
        "invalid OCI blob digest",
    )
    require(
        type(descriptor["size"]) is int and descriptor["size"] > 0,
        "invalid OCI blob size",
    )
    if "platform" in descriptor:
        fields(descriptor["platform"], {"os", "architecture"})
        platform(descriptor["platform"])
    limit = MAX_JSON_BYTES if json_blob else MAX_LAYER_BYTES
    require(descriptor["size"] <= limit, "OCI blob size limit exceeded")
    with subdirectory(root, "blobs") as blobs, subdirectory(blobs, "sha256") as hashes:
        raw = contents(
            hashes, descriptor["digest"][7:], limit, descriptor, collect=json_blob
        )
    return document(raw) if json_blob else None


def manifest_digest(layout, ref):
    """Verify one linux/amd64 OCI image and return its exact stored manifest hash."""
    require(isinstance(ref, str) and TAG.fullmatch(ref), "invalid OCI ref")
    with directory(layout) as root:
        return checked_manifest(root, ref)


def checked_manifest(root, ref):
    return checked_image(root, ref)[0]


def checked_image(root, ref):
    metadata = document(contents(root, "oci-layout", MAX_JSON_BYTES))
    fields(metadata, {"imageLayoutVersion"})
    require(metadata["imageLayoutVersion"] == "1.0.0", "unsupported OCI layout version")
    index = document(contents(root, "index.json", MAX_JSON_BYTES))
    fields(index, {"schemaVersion", "manifests"}, {"mediaType", "annotations"})
    require(
        type(index["schemaVersion"]) is int and index["schemaVersion"] == 2,
        "invalid OCI index schemaVersion",
    )
    require(index.get("mediaType", INDEX) == INDEX, "unsupported OCI index mediaType")
    require(
        isinstance(index["manifests"], list) and len(index["manifests"]) == 1,
        "OCI layout must contain exactly one manifest",
    )
    descriptor = index["manifests"][0]
    manifest = blob(root, descriptor, {MANIFEST}, json_blob=True)
    require(descriptor.get("annotations", {}).get(REF) == ref, "OCI ref mismatch")
    fields(
        manifest,
        {"schemaVersion", "mediaType", "config", "layers"},
        {"annotations"},
    )
    require(
        type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2,
        "invalid OCI manifest schemaVersion",
    )
    require(manifest["mediaType"] == MANIFEST, "unsupported OCI manifest mediaType")
    config = blob(root, manifest["config"], {CONFIG}, json_blob=True)
    platform(config)
    require(
        isinstance(manifest["layers"], list) and len(manifest["layers"]) <= MAX_LAYERS,
        "invalid OCI layers",
    )
    for layer in manifest["layers"]:
        blob(root, layer, LAYERS)
    return descriptor["digest"], config, len(manifest["layers"])


def expected_digest(value):
    require(
        isinstance(value, str) and DIGEST.fullmatch(value),
        "invalid expected OCI digest",
    )


def fetch_core(repository, run_id, layout, expected):
    expected_digest(expected)
    layout = safe_path(layout)
    with directory(layout.parent) as parent:
        require(not os.path.lexists(layout), "OCI destination must not exist")
        from release_pipeline import download

        with tempfile.TemporaryDirectory(dir=f"/proc/self/fd/{parent}") as temp:
            staged = Path(temp) / "core-oci"
            with subdirectory(parent, Path(temp).name) as source:
                download(repository, run_id, "core-oci", staged)
                with subdirectory(source, staged.name) as validated:
                    require(
                        checked_manifest(validated, "core") == expected,
                        "core OCI manifest digest mismatch",
                    )
                    require(
                        not os.path.lexists(layout), "OCI destination must not exist"
                    )
                    os.rename(
                        staged.name, layout.name, src_dir_fd=source, dst_dir_fd=parent
                    )
                    with subdirectory(parent, layout.name) as installed:
                        require(
                            os.path.samestat(os.fstat(installed), os.fstat(validated)),
                            "OCI installed directory changed",
                        )
                        require(
                            checked_manifest(installed, "core") == expected,
                            "core OCI manifest digest mismatch",
                        )
                    with directory(layout.parent) as current:
                        require(
                            os.path.samestat(os.fstat(current), os.fstat(parent)),
                            "OCI destination parent changed",
                        )
    return {"manifest_digest": expected}


def declared_diff_ids(layout, ref, expected):
    expected_digest(expected)
    with directory(layout) as root:
        digest, config, layer_count = checked_image(root, ref)
    require(digest == expected, "OCI manifest digest mismatch")
    rootfs = config.get("rootfs")
    fields(rootfs, {"type", "diff_ids"})
    require(rootfs["type"] == "layers", "invalid OCI rootfs type")
    diff_ids = rootfs["diff_ids"]
    require(
        isinstance(diff_ids, list)
        and 0 < len(diff_ids) == layer_count <= MAX_LAYERS
        and all(
            isinstance(value, str) and DIGEST.fullmatch(value) for value in diff_ids
        ),
        "invalid OCI declared diff_ids",
    )
    return diff_ids


def ancestry(core_layout, layout, core_digest, digest):
    core = declared_diff_ids(core_layout, "core", core_digest)
    workstation = declared_diff_ids(layout, "workstation", digest)
    require(
        workstation[: len(core)] == core,
        "OCI declared core diff_ids prefix mismatch",
    )
    return {"declared_diff_ids_prefix": "true"}


def export_layout(image, layout, ref, *, docker_host=""):
    require(
        isinstance(image, str) and IMAGE.fullmatch(image),
        "expected a local tagged Docker image",
    )
    require(isinstance(ref, str) and TAG.fullmatch(ref), "invalid OCI ref")
    source_options = []
    if docker_host:
        require(
            isinstance(docker_host, str)
            and re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", docker_host),
            "expected a local Unix Docker socket",
        )
        safe_path(docker_host[7:])
        source_options = ["--src-daemon-host", docker_host]
    layout = safe_path(layout)
    require(
        layout.name
        and ":" not in str(layout)
        and not any(c in str(layout) for c in "\r\n\x00"),
        "invalid OCI destination",
    )
    with directory(layout.parent) as parent:
        try:
            os.mkdir(layout.name, dir_fd=parent)
        except FileExistsError:
            pass
        with subdirectory(parent, layout.name) as destination:
            require(not os.listdir(destination), "OCI export destination must be empty")
            version = subprocess.run(
                ["skopeo", "--version"], check=True, capture_output=True, text=True
            ).stdout.rstrip("\n")
            require(
                len(version) <= 256
                and re.fullmatch(r"skopeo version [^\r\n]+", version),
                "invalid skopeo version output",
            )
            subprocess.run(
                [
                    "skopeo",
                    "copy",
                    "--dest-compress",
                    "--dest-compress-format",
                    "gzip",
                    *source_options,
                    f"docker-daemon:{image}",
                    f"oci:/proc/self/fd/{destination}:{ref}",
                ],
                check=True,
                capture_output=True,
                text=True,
                pass_fds=(destination,),
            )
            digest = checked_manifest(destination, ref)
            with directory(layout) as current:
                require(
                    os.path.samestat(os.fstat(current), os.fstat(destination)),
                    "OCI destination changed",
                )
            return {
                "manifest_digest": digest,
                "skopeo_version": version,
            }


def outputs(result):
    require(
        all(
            isinstance(value, str) and not any(c in value for c in "\r\n")
            for value in result.values()
        ),
        "invalid OCI output",
    )
    if os.environ.get("GITHUB_OUTPUT"):
        path = safe_path(os.environ["GITHUB_OUTPUT"])
        with directory(path.parent) as parent:
            descriptor = os.open(
                path.name,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                require(
                    stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                    "invalid output file",
                )
                stream.writelines(f"{key}={value}\n" for key, value in result.items())
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    validate = actions.add_parser("validate")
    export = actions.add_parser("export")
    for action in (validate, export):
        action.add_argument("--layout", type=Path, required=True)
        action.add_argument("--ref", required=True)
    export.add_argument("--image", required=True)
    export.add_argument("--docker-host", default="")
    fetch = actions.add_parser("fetch-core")
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--run-id", type=int, required=True)
    fetch.add_argument("--layout", type=Path, required=True)
    fetch.add_argument("--expected-digest", required=True)
    prefix = actions.add_parser("ancestry")
    prefix.add_argument("--core-layout", type=Path, required=True)
    prefix.add_argument("--layout", type=Path, required=True)
    prefix.add_argument("--core-digest", required=True)
    prefix.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    try:
        if args.action == "export":
            result = export_layout(
                args.image, args.layout, args.ref, docker_host=args.docker_host
            )
        elif args.action == "fetch-core":
            result = fetch_core(
                args.repository, args.run_id, args.layout, args.expected_digest
            )
        elif args.action == "ancestry":
            result = ancestry(
                args.core_layout, args.layout, args.core_digest, args.expected_digest
            )
        else:
            result = {"manifest_digest": manifest_digest(args.layout, args.ref)}
        outputs(result)
        return 0
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        RecursionError,
        zipfile.BadZipFile,
    ) as error:
        print(f"OCI layout rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
