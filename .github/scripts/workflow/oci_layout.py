import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from contextlib import ExitStack, contextmanager
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
MAX_DIFFID_TOTAL_BYTES = 64 * 1024**3
DIFFID_TIMEOUT_SECONDS = 600
MAX_LAYERS = 256
CHUNK_BYTES = 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
NEGATIVE_SUBJECT = "io.luminusos.test.negative-subject"
NEGATIVE_KINDS = ("unsigned", "foreign-key")


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


def contents(
    parent, name, limit, expected=None, collect=True, sink=None, deadline=None
):
    if deadline is not None:
        require(time.monotonic() < deadline, "OCI diff_id deadline exceeded")
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
            if deadline is not None:
                require(time.monotonic() < deadline, "OCI diff_id deadline exceeded")
            total += len(chunk)
            require(
                total <= info.st_size and total <= limit, "OCI file grew during read"
            )
            checksum.update(chunk)
            if sink is not None:
                sink.write(chunk)
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


def blob(root, descriptor, media_types, json_blob=False, *, sink=None, deadline=None):
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
            hashes,
            descriptor["digest"][7:],
            limit,
            descriptor,
            collect=json_blob,
            sink=sink,
            deadline=deadline,
        )
    return document(raw) if json_blob else None


def manifest_digest(layout, ref):
    """Verify one linux/amd64 OCI image and return its exact stored manifest hash."""
    require(isinstance(ref, str) and TAG.fullmatch(ref), "invalid OCI ref")
    with directory(layout) as root:
        return checked_manifest(root, ref)


def checked_manifest(root, ref):
    return checked_image(root, ref)[0]


def checked_image(root, ref, *, deadline=None):
    metadata = document(contents(root, "oci-layout", MAX_JSON_BYTES, deadline=deadline))
    fields(metadata, {"imageLayoutVersion"})
    require(metadata["imageLayoutVersion"] == "1.0.0", "unsupported OCI layout version")
    index = document(contents(root, "index.json", MAX_JSON_BYTES, deadline=deadline))
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
    manifest = blob(root, descriptor, {MANIFEST}, json_blob=True, deadline=deadline)
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
    config = blob(root, manifest["config"], {CONFIG}, json_blob=True, deadline=deadline)
    platform(config)
    require(
        isinstance(manifest["layers"], list) and len(manifest["layers"]) <= MAX_LAYERS,
        "invalid OCI layers",
    )
    for layer in manifest["layers"]:
        blob(root, layer, LAYERS, deadline=deadline)
    return descriptor["digest"], config, len(manifest["layers"])


class DiffIDHasher:
    def __init__(self, compressed, remaining, deadline):
        self.compressed = compressed
        self.remaining = remaining
        self.deadline = deadline
        self.checksum = hashlib.sha256()
        self.size = 0
        self.decoder = None

    def check_deadline(self):
        require(time.monotonic() < self.deadline, "OCI diff_id deadline exceeded")

    def update(self, output):
        self.check_deadline()
        self.size += len(output)
        require(self.size <= MAX_LAYER_BYTES, "decompressed OCI layer limit exceeded")
        require(self.size <= self.remaining, "decompressed OCI image limit exceeded")
        self.checksum.update(output)

    def write(self, data):
        self.check_deadline()
        if not self.compressed:
            self.update(data)
            return
        if self.decoder is None:
            self.decoder = zlib.decompressobj(31)
        while True:
            self.check_deadline()
            try:
                output = self.decoder.decompress(data, CHUNK_BYTES)
            except zlib.error:
                raise ValueError("invalid OCI gzip stream") from None
            self.update(output)
            if self.decoder.eof:
                data = self.decoder.unused_data
                self.decoder = None
                if not data:
                    return
                self.decoder = zlib.decompressobj(31)
            else:
                data = self.decoder.unconsumed_tail
                if not data and len(output) < CHUNK_BYTES:
                    return

    def finish(self):
        self.check_deadline()
        require(self.decoder is None, "truncated OCI gzip stream")
        return "sha256:" + self.checksum.hexdigest()


def verify_diff_ids(root, ref, expected):
    deadline = time.monotonic() + DIFFID_TIMEOUT_SECONDS
    expected_digest(expected)
    digest, config, layer_count = checked_image(root, ref, deadline=deadline)
    require(digest == expected, "OCI manifest digest mismatch")
    rootfs = config.get("rootfs")
    fields(rootfs, {"type", "diff_ids"})
    require(rootfs["type"] == "layers", "invalid OCI rootfs type")
    declared = rootfs["diff_ids"]
    require(
        isinstance(declared, list)
        and 0 < len(declared) == layer_count <= MAX_LAYERS
        and all(
            isinstance(value, str) and DIGEST.fullmatch(value) for value in declared
        ),
        "invalid OCI declared diff_ids",
    )
    index = document(contents(root, "index.json", MAX_JSON_BYTES, deadline=deadline))
    descriptor = index["manifests"][0]
    require(descriptor["digest"] == expected, "OCI manifest digest mismatch")
    manifest = blob(root, descriptor, {MANIFEST}, json_blob=True, deadline=deadline)
    total = 0
    verified = []
    for layer, wanted in zip(manifest["layers"], declared, strict=True):
        sink = DiffIDHasher(
            layer["mediaType"].endswith("+gzip"),
            MAX_DIFFID_TOTAL_BYTES - total,
            deadline,
        )
        blob(root, layer, LAYERS, sink=sink, deadline=deadline)
        actual = sink.finish()
        require(actual == wanted, "decompressed OCI diff_id mismatch")
        total += sink.size
        verified.append(actual)
    return verified


def expected_digest(value):
    require(
        isinstance(value, str) and DIGEST.fullmatch(value),
        "invalid expected OCI digest",
    )


def negative_base(root, ref, expected):
    expected_digest(expected)
    require(isinstance(ref, str) and TAG.fullmatch(ref), "invalid OCI ref")
    raw_index = contents(root, "index.json", MAX_JSON_BYTES)
    require(checked_manifest(root, ref) == expected, "B OCI manifest digest mismatch")
    require(
        contents(root, "index.json", MAX_JSON_BYTES) == raw_index, "B index changed"
    )
    index = document(raw_index)
    require(index["manifests"][0]["digest"] == expected, "B index changed")
    manifest = blob(root, index["manifests"][0], {MANIFEST}, json_blob=True)
    require(
        NEGATIVE_SUBJECT not in manifest.get("annotations", {}),
        "B already has negative subject annotation",
    )
    return index, manifest


def negative_documents(index, manifest, kind):
    require(kind in NEGATIVE_KINDS, "invalid negative subject kind")
    derived = copy.deepcopy(manifest)
    derived.setdefault("annotations", {})[NEGATIVE_SUBJECT] = kind
    raw = json.dumps(derived, separators=(",", ":"), ensure_ascii=True).encode()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    result = copy.deepcopy(index)
    descriptor = result["manifests"][0]
    descriptor.update(digest=digest, size=len(raw))
    descriptor["annotations"][REF] = "negative-" + kind
    return result, raw, digest


def checked_negative_subject(source, ref, expected, subject, kind):
    index, manifest = negative_base(source, ref, expected)
    wanted_index, raw, digest = negative_documents(index, manifest, kind)
    require(digest != expected, "negative subject must differ from B")
    require(
        checked_manifest(subject, "negative-" + kind) == digest,
        "negative subject manifest relation mismatch",
    )
    require(
        document(contents(subject, "index.json", MAX_JSON_BYTES)) == wanted_index,
        "negative subject index relation mismatch",
    )
    with (
        subdirectory(subject, "blobs") as blobs,
        subdirectory(blobs, "sha256") as hashes,
    ):
        require(
            contents(hashes, digest[7:], MAX_JSON_BYTES) == raw,
            "negative subject manifest bytes mismatch",
        )
        require(
            set(os.listdir(hashes))
            == {
                digest[7:],
                *(d["digest"][7:] for d in [manifest["config"], *manifest["layers"]]),
            },
            "unexpected negative subject blobs",
        )
    require(
        set(os.listdir(subject)) == {"blobs", "index.json", "oci-layout"},
        "unexpected negative subject files",
    )
    with subdirectory(subject, "blobs") as blobs:
        require(set(os.listdir(blobs)) == {"sha256"}, "unexpected blob directories")
    return digest


def verify_negative_subject(source, ref, expected, subject, kind):
    """Verify a local byte derivation, not signatures, provenance or runtime state."""
    with directory(source) as base, directory(subject) as derived:
        return checked_negative_subject(base, ref, expected, derived, kind)


@contextmanager
def new_oci_file(parent, name):
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    with os.fdopen(descriptor, "wb") as stream:
        yield stream


def write_negative_subject(source, destination, index, manifest, kind):
    derived_index, raw, digest = negative_documents(index, manifest, kind)
    os.mkdir("blobs", mode=0o700, dir_fd=destination)
    with subdirectory(destination, "blobs") as blobs:
        os.mkdir("sha256", mode=0o700, dir_fd=blobs)
        with subdirectory(blobs, "sha256") as hashes:
            with (
                subdirectory(source, "blobs") as source_blobs,
                subdirectory(source_blobs, "sha256") as source_hashes,
            ):
                copied = set()
                for descriptor in [manifest["config"], *manifest["layers"]]:
                    name = descriptor["digest"][7:]
                    if name in copied:
                        continue
                    with new_oci_file(hashes, name) as stream:
                        contents(
                            source_hashes,
                            name,
                            MAX_LAYER_BYTES,
                            descriptor,
                            collect=False,
                            sink=stream,
                        )
                    copied.add(name)
            with new_oci_file(hashes, digest[7:]) as stream:
                stream.write(raw)
    for name, raw in (
        ("index.json", json.dumps(derived_index).encode()),
        ("oci-layout", contents(source, "oci-layout", MAX_JSON_BYTES)),
    ):
        with new_oci_file(destination, name) as stream:
            stream.write(raw)


def derive_negative_subjects(source, ref, expected, unsigned, foreign_key):
    """Create two local subjects. Failures retain partial directories; never retry over them.

    Neither subject carries signatures. No result is returned until both verify.
    Files are exclusively created through retained directory FDs, never replaced
    or cleaned up by path after a failure.
    """
    source = safe_path(source)
    paths = [safe_path(path) for path in (unsigned, foreign_key)]
    require(paths[0] != paths[1], "negative destinations must differ")
    for path in paths:
        require(
            source != path and source not in path.parents,
            "destination must be outside B",
        )
        require(
            path.name and not any(c in str(path) for c in ":\r\n\x00"),
            "invalid OCI destination",
        )
    with (
        directory(source) as base,
        directory(paths[0].parent) as first_parent,
        directory(paths[1].parent) as second_parent,
    ):
        index, manifest = negative_base(base, ref, expected)
        parents = (first_parent, second_parent)
        for parent, path in zip(parents, paths):
            require(
                path.name not in os.listdir(parent), "OCI destination must not exist"
            )
        with ExitStack() as stack:
            destinations = []
            identities = []
            for parent, path in zip(parents, paths):
                os.mkdir(path.name, mode=0o700, dir_fd=parent)
                identity = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                destination = stack.enter_context(subdirectory(parent, path.name))
                require(
                    os.path.samestat(identity, os.fstat(destination)),
                    "OCI destination changed",
                )
                destinations.append(destination)
                identities.append(identity)
            for destination, kind in zip(destinations, NEGATIVE_KINDS):
                write_negative_subject(base, destination, index, manifest, kind)
            result = {}
            for parent, path, destination, identity, kind in zip(
                parents, paths, destinations, identities, NEGATIVE_KINDS
            ):
                with directory(path) as current:
                    require(
                        os.path.samestat(os.fstat(current), identity),
                        "OCI destination changed",
                    )
                    result[kind] = checked_negative_subject(
                        base, ref, expected, current, kind
                    )
                with directory(path.parent) as current_parent:
                    require(
                        os.path.samestat(os.fstat(current_parent), os.fstat(parent)),
                        "OCI destination parent changed",
                    )
            require(
                len({expected, *result.values()}) == 3,
                "negative subject digests must differ",
            )
            return result


def fetch_core(repository, run_id, layout, expected):
    return fetch_layout(repository, run_id, layout, expected, "core", "core")


def fetch_payload(repository, run_id, layout, expected):
    return fetch_layout(repository, run_id, layout, expected, "workstation", "latest")


def fetch_layout(repository, run_id, layout, expected, ref, destination_ref):
    expected_digest(expected)
    layout = safe_path(layout)
    with directory(layout.parent) as parent:
        require(not os.path.lexists(layout), "OCI destination must not exist")
        from release_pipeline import download

        with tempfile.TemporaryDirectory(dir=f"/proc/self/fd/{parent}") as temp:
            staged = Path(temp) / f"{ref}-oci"
            with subdirectory(parent, Path(temp).name) as source:
                download(repository, run_id, f"{ref}-oci", staged)
                with subdirectory(source, staged.name) as validated:
                    require(
                        checked_manifest(validated, ref) == expected,
                        f"{ref} OCI manifest digest mismatch",
                    )
                    if destination_ref != ref:
                        index = document(
                            contents(validated, "index.json", MAX_JSON_BYTES)
                        )
                        index["manifests"][0]["annotations"][REF] = destination_ref
                        descriptor = os.open(
                            ".index-remap",
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | os.O_NOFOLLOW
                            | os.O_CLOEXEC,
                            0o600,
                            dir_fd=validated,
                        )
                        with os.fdopen(descriptor, "wb") as stream:
                            stream.write(json.dumps(index).encode("utf-8"))
                        os.replace(
                            ".index-remap",
                            "index.json",
                            src_dir_fd=validated,
                            dst_dir_fd=validated,
                        )
                        require(
                            checked_manifest(validated, destination_ref) == expected,
                            f"{ref} OCI manifest digest mismatch",
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
                            checked_manifest(installed, destination_ref) == expected,
                            f"{ref} OCI manifest digest mismatch",
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
    payload = actions.add_parser("fetch-payload")
    for acquisition in (fetch, payload):
        acquisition.add_argument("--repository", required=True)
        acquisition.add_argument("--run-id", type=int, required=True)
        acquisition.add_argument("--layout", type=Path, required=True)
        acquisition.add_argument("--expected-digest", required=True)
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
        elif args.action == "fetch-payload":
            result = fetch_payload(
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
