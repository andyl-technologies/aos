"""Runs one native published-package qualification scenario.

The coordinator has already authenticated the release and downloaded the exact
public object graph. This program independently checks those bytes, imports the
signed NAR closure, exercises the user-facing APM lifecycle in private state,
and runs the package's immutable functional probe after installation and after
generation recovery. A report is written only after every operation succeeds.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import Any, BinaryIO

from qualification_k3s_bindings import bind_k3s_fleet, configuration_output_names


ROOT = pathlib.Path.cwd()
REQUEST = ROOT / "request.json"
OBJECTS = ROOT / "objects.json"
DOWNLOADS = ROOT / "downloads.json"
REPORT = ROOT / "scenario-report.json"

PLATFORM = os.environ["AOS_QUALIFICATION_PLATFORM"]
PROBES = pathlib.Path(os.environ["AOS_QUALIFICATION_PROBES"])
TRUST_KEYS = json.loads(os.environ["AOS_QUALIFICATION_TRUST_KEYS"])
STAGING_HUB_URL = os.environ["AOS_QUALIFICATION_STAGING_HUB_URL"]
APM = os.environ["AOS_QUALIFICATION_APM"]
NIX_STORE = os.environ["AOS_QUALIFICATION_NIX_STORE"]
ZSTD = os.environ["AOS_QUALIFICATION_ZSTD"]
UNAME = os.environ["AOS_QUALIFICATION_UNAME"]
BOUND_IMAGE_VARIANT = os.environ.get("AOS_QUALIFICATION_BOUND_IMAGE_VARIANT")
BOUND_K3S_TOPOLOGY = os.environ.get("AOS_QUALIFICATION_BOUND_K3S_TOPOLOGY")

EXPECTED_CHECKS = {
    "anonymous-download",
    "closure-verification",
    "functional-behavior",
    "dependency-obligations",
    "permissions-and-confinement",
}
PACKAGE_CASE = re.compile(
    r"^package-function/(?P<package>[A-Za-z0-9_.+@-]+)/"
    r"(?P<platform>x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin)$"
)
NIX_BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"
STORE_PATH = re.compile(
    rf"^/nix/store/[{NIX_BASE32}]{{32}}-[A-Za-z0-9+._?=-]+$"
)
PROBE_RESULT_SCHEMA = "aos.release.package-functional-result/v1"
PROBE_REGISTRY_SCHEMA = "aos.release.package-probes/v1"
MANIFEST_OBJECT = "control/release-manifest-envelope"
MAX_PROBE_RESULT_BYTES = 1024 * 1024
MAX_I_JSON_INTEGER = (1 << 53) - 1


def canonical(value: Any) -> bytes:
    """Encodes the canonical JSON form used by release evidence."""

    validate_json_value(value)
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def digest(domain: str, value: Any) -> str:
    """Computes a domain-separated canonical SHA-256 identity."""

    hashed = hashlib.sha256()
    hashed.update(domain.encode())
    hashed.update(b"\0")
    hashed.update(canonical(value))
    return "sha256:" + hashed.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Builds one JSON object while rejecting repeated member names."""

    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise RuntimeError(f"JSON object repeats member {key!r}")
        value[key] = child
    return value


def reject_non_integer_number(value: str) -> None:
    """Rejects every non-integer JSON number and non-finite extension."""

    raise RuntimeError(f"JSON contains unsupported number {value!r}")


def validate_json_value(value: Any) -> None:
    """Enforces the AOS integer-only I-JSON value constraints."""

    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_I_JSON_INTEGER:
            raise RuntimeError("JSON integer is outside the exact I-JSON range")
        return
    if isinstance(value, list):
        for child in value:
            validate_json_value(child)
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise RuntimeError("JSON object member name is not ASCII")
            validate_json_value(child)
        return
    raise RuntimeError(f"JSON contains unsupported value type {type(value).__name__}")


def decode_json(raw: bytes, label: str) -> Any:
    """Decodes strict JSON without duplicate keys, floats, or extensions."""

    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_float=reject_non_integer_number,
            parse_constant=reject_non_integer_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as error:
        raise RuntimeError(f"invalid {label} JSON") from error
    validate_json_value(value)
    return value


def read_json(path: pathlib.Path) -> Any:
    """Reads a strict JSON document from an exact path."""

    with path.open("rb") as source:
        return decode_json(source.read(), str(path))


def write_canonical(path: pathlib.Path, value: Any) -> None:
    """Writes canonical JSON with the repository's required trailing newline."""

    path.write_bytes(canonical(value) + b"\n")


def hash_file(path: pathlib.Path) -> tuple[int, str]:
    """Returns an exact file's length and SHA-256 identity."""

    size = 0
    hashed = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            size += len(block)
            hashed.update(block)
    return size, "sha256:" + hashed.hexdigest()


def canonical_sha256(value: str) -> str:
    """Normalizes a hexadecimal, SRI, or Nix-base32 SHA-256 identity."""

    if value.startswith("sha256-"):
        try:
            decoded = base64.b64decode(value.removeprefix("sha256-"), validate=True)
        except ValueError as error:
            raise RuntimeError("invalid SRI SHA-256 identity") from error
    elif value.startswith("sha256:"):
        encoded = value.removeprefix("sha256:")
        if len(encoded) == 64 and re.fullmatch(r"[0-9A-Fa-f]{64}", encoded):
            decoded = bytes.fromhex(encoded)
        elif len(encoded) == 52:
            decoded = decode_nix_base32(encoded)
        else:
            raise RuntimeError("invalid SHA-256 identity")
    else:
        raise RuntimeError("SHA-256 identity lacks an accepted prefix")
    if len(decoded) != 32:
        raise RuntimeError("SHA-256 identity does not contain 32 bytes")
    return "sha256:" + decoded.hex()


def decode_nix_base32(encoded: str) -> bytes:
    """Decodes Nix's reverse-digit, little-endian base32 representation."""

    decoded = bytearray(len(encoded) * 5 // 8)
    for index, character in enumerate(reversed(encoded)):
        try:
            digit = NIX_BASE32.index(character)
        except ValueError as error:
            raise RuntimeError("invalid Nix-base32 SHA-256 identity") from error
        bit = index * 5
        byte_index, shift = divmod(bit, 8)
        if byte_index >= len(decoded):
            raise RuntimeError("invalid Nix-base32 SHA-256 length")
        decoded[byte_index] |= (digit << shift) & 0xFF
        carry = digit >> (8 - shift)
        if byte_index + 1 < len(decoded):
            decoded[byte_index + 1] |= carry
        elif carry:
            raise RuntimeError("noncanonical Nix-base32 SHA-256 identity")
    return bytes(decoded)


def run(
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
    cwd: pathlib.Path | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[bytes]:
    """Runs a required command and retains bounded diagnostics on failure."""

    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if result.returncode != 0:
        output = (result.stdout + result.stderr)[-64 * 1024 :].decode(
            errors="replace"
        )
        raise RuntimeError(
            f"command failed with status {result.returncode}: "
            f"{arguments!r}\n{output}"
        )
    return result


def one(values: list[Any], label: str) -> Any:
    """Returns the only matching value or fails closed."""

    if len(values) != 1:
        raise RuntimeError(f"expected exactly one {label}, found {len(values)}")
    return values[0]


def write_nix_string(destination: BinaryIO, value: str) -> None:
    """Writes one string using Nix's aligned wire encoding."""

    encoded = value.encode()
    destination.write(struct.pack("<Q", len(encoded)))
    destination.write(encoded)
    destination.write(b"\0" * ((8 - len(encoded) % 8) % 8))


@dataclass(frozen=True)
class NarInfo:
    """Carries the signed import identity parsed from one narinfo object."""

    store_path: str
    nar_hash: str
    references: tuple[str, ...]
    deriver: str | None
    compression: str

    @classmethod
    def parse(cls, path: pathlib.Path) -> "NarInfo":
        """Parses the bounded narinfo fields needed for local import."""

        fields: dict[str, list[str]] = {}
        for line in path.read_text().splitlines():
            key, separator, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if not separator or not key:
                raise RuntimeError(f"invalid narinfo line in {path}: {line!r}")
            fields.setdefault(key, []).append(value)

        def required(name: str) -> str:
            return one(fields.get(name, []), f"narinfo {name}")

        store_path = required("StorePath")
        if not STORE_PATH.fullmatch(store_path):
            raise RuntimeError("narinfo contains an invalid store path")
        reference_fields = fields.get("References", [])
        if len(reference_fields) > 1:
            raise RuntimeError("narinfo repeats References")
        references = tuple(
            f"/nix/store/{value}"
            for value in (reference_fields[0] if reference_fields else "").split()
        )
        if any(not STORE_PATH.fullmatch(value) for value in references):
            raise RuntimeError("narinfo contains an invalid reference")
        deriver_fields = fields.get("Deriver", [])
        if len(deriver_fields) > 1:
            raise RuntimeError("narinfo repeats Deriver")
        deriver_value = deriver_fields[0] if deriver_fields else ""
        deriver = None if deriver_value in {"", "unknown-deriver"} else deriver_value
        if deriver is not None and not deriver.startswith("/nix/store/"):
            deriver = f"/nix/store/{deriver}"
        if deriver is not None and not STORE_PATH.fullmatch(deriver):
            raise RuntimeError("narinfo contains an invalid deriver")
        if deriver is not None and not deriver.endswith(".drv"):
            raise RuntimeError("narinfo contains an invalid deriver")
        compression = required("Compression")
        if compression not in {"none", "zstd"}:
            raise RuntimeError(f"unsupported qualification NAR compression {compression!r}")

        return cls(
            store_path=store_path,
            nar_hash=required("NarHash"),
            references=references,
            deriver=deriver,
            compression=compression,
        )


class PackageScenario:
    """Owns validation, import, package lifecycle, and report construction."""

    def __init__(self) -> None:
        self.request = read_json(REQUEST)
        self.case = self.request["qualification_case"]
        self.objects: dict[str, str] = read_json(OBJECTS)
        self.downloads = read_json(DOWNLOADS)
        self.manifest = read_json(pathlib.Path(self.objects[MANIFEST_OBJECT]))
        manifest_artifacts = self.manifest["payload"]["artifacts"]
        self.artifacts = {
            artifact["id"]: artifact
            for artifact in manifest_artifacts
        }
        if len(self.artifacts) != len(manifest_artifacts):
            raise RuntimeError("release manifest repeats an artifact identity")
        probe_registry = read_json(PROBES)
        if probe_registry.get("schema_version") != PROBE_REGISTRY_SCHEMA:
            raise RuntimeError("package probe registry has an unsupported schema")
        probes = probe_registry.get("packages")
        if (
            not isinstance(probes, dict)
            or any(
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_.+@-]+", name) is None
                or not isinstance(path, str)
                for name, path in probes.items()
            )
        ):
            raise RuntimeError("package probe registry has invalid entries")
        self.probes: dict[str, str] = probes
        self.package = ""
        self.version = ""
        self.client_name = ""
        self.staging_url = ""
        self.probe = ""
        self.outputs: dict[str, str] = {}
        self.package_artifact_ids: list[str] = []
        self.closure: dict[str, NarInfo] = {}
        self.closure_artifacts: dict[str, str] = {}
        self.imported_nar_hashes: dict[str, str] = {}
        self.started_at = ""
        self.started_seconds = 0

    def execute(self) -> None:
        """Runs the complete scenario and writes its canonical report."""

        self.validate_inputs()
        self.started_at, self.started_seconds = timestamp()
        self.validate_downloads()
        self.resolve_closure()
        self.import_closure()
        self.validate_store_graph()
        self.validate_permissions()

        recovered_generation, first_probe, recovered_probe = self.exercise_apm()
        if first_probe != recovered_probe:
            raise RuntimeError("functional result changed after generation recovery")

        self.write_report(recovered_generation, first_probe)

    def validate_inputs(self) -> None:
        """Binds the request, case, release manifest, and immutable probe."""

        if self.request["platform"] != PLATFORM:
            raise RuntimeError("request platform differs from native executor")
        native = os.uname()
        architecture = {"arm64": "aarch64"}.get(native.machine, native.machine)
        native_platform = f"{architecture}-{native.sysname.lower()}"
        if native_platform != PLATFORM:
            raise RuntimeError(
                f"native machine platform {native_platform!r} differs from "
                f"the configured executor platform {PLATFORM!r}"
            )

        match = PACKAGE_CASE.fullmatch(self.case["id"])
        if match is None or match.group("platform") != PLATFORM:
            raise RuntimeError("scenario received an invalid package case identity")
        self.package = match.group("package")
        if (
            self.case.get("schema_version")
            != "aos.release.qualification-case/v2"
            or self.case["requirement_id"] != "package-function"
            or self.case["phase"] != "staging"
            or self.case["platform"] != PLATFORM
            or self.case.get("target") is not None
            or self.case.get("claim") is not None
            or set(self.case["checks"]) != EXPECTED_CHECKS
        ):
            raise RuntimeError("package case differs from the implemented program")
        if self.case.get("package_role") not in {
            "general-catalog",
            "qualified-workload",
            "system-integrity",
        }:
            raise RuntimeError("package case lacks a supported effective role")

        payload = self.manifest["payload"]
        if (
            payload["registry"] != self.request["registry"]
            or payload["release_id"] != self.request["release_id"]
            or self.manifest["payload_digest"] != self.request["manifest_digest"]
            or digest("aos.release.manifest/v1", payload)
            != self.request["manifest_digest"]
        ):
            raise RuntimeError("release manifest differs from the exact request")
        self.version = payload["version"]

        package = one(
            [entry for entry in payload["packages"] if entry["name"] == self.package],
            "package manifest entry",
        )
        cell = one(
            [
                entry
                for entry in package["platforms"]
                if entry["platform"] == PLATFORM
            ],
            "package platform cell",
        )
        decision = cell["decision"]
        if decision.get("state") != "artifact":
            raise RuntimeError("package case refers to a non-artifact platform cell")
        artifact_ids = decision["artifact"]["artifact_ids"]
        self.package_artifact_ids = list(artifact_ids)
        expected_subjects = list(artifact_ids)
        if BOUND_K3S_TOPOLOGY is not None:
            bindings = bind_k3s_fleet(
                payload, PLATFORM, self.package, BOUND_IMAGE_VARIANT, BOUND_K3S_TOPOLOGY
            )
            expected_subjects = bindings.subjects
        elif BOUND_IMAGE_VARIANT is not None:
            image = one(
                [
                    entry
                    for entry in payload["images"]
                    if entry["system_variant"] == BOUND_IMAGE_VARIANT
                ],
                "bound image manifest entry",
            )
            image_cell = one(
                [entry for entry in image["platforms"] if entry["platform"] == PLATFORM],
                "bound image platform cell",
            )
            image_decision = image_cell["decision"]
            if image_decision.get("state") != "artifact":
                raise RuntimeError("bound image case refers to a non-artifact platform cell")
            expected_subjects.extend(image_decision["artifact"]["artifact_ids"])
        expected_subjects = sorted(set(expected_subjects))
        if expected_subjects != self.case["subjects"]:
            raise RuntimeError("package cell artifacts differ from the exact case subjects")

        companion_names = configuration_output_names(
            decision["artifact"].get("configuration"), artifact_ids, self.artifacts
        )
        for artifact_id in artifact_ids:
            artifact = self.artifacts.get(artifact_id)
            if (
                artifact is None
                or artifact["kind"] != "package-nar"
                or artifact["platform"] != PLATFORM
                or artifact.get("store_path") is None
                or artifact.get("output") is None
            ):
                raise RuntimeError("package subject lacks its exact Nix output identity")
            output_name = companion_names.get(artifact_id, artifact["output"])
            if output_name in self.outputs:
                raise RuntimeError("package case repeats a named Nix output")
            self.outputs[output_name] = artifact["store_path"]
        if "out" not in self.outputs:
            raise RuntimeError("package case has no primary out output")

        self.probe = self.probes.get(self.package, "")
        if not self.probe:
            raise RuntimeError(
                f"package {self.package!r} has no reviewed functional probe"
            )
        probe_path = pathlib.Path(self.probe)
        if (
            not self.probe.startswith("/nix/store/")
            or not probe_path.is_file()
            or not os.access(probe_path, os.X_OK)
        ):
            raise RuntimeError("package has no immutable executable functional probe")

        self.client_name = (
            "andyl"
            if self.request["registry"] == "andyl/main"
            else self.request["registry"].replace("/", "-")
        )
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.client_name):
            raise RuntimeError("registry does not map to a safe APM client name")
        expected_prefix = self.client_name + ":Ed25519:"
        if not TRUST_KEYS or any(
            not isinstance(key, str) or not key.startswith(expected_prefix)
            for key in TRUST_KEYS
        ):
            raise RuntimeError("qualification trust keys belong to another registry")

        staging_hub = urllib.parse.urlsplit(STAGING_HUB_URL)
        if (
            staging_hub.scheme != "https"
            or not staging_hub.hostname
            or staging_hub.username is not None
            or staging_hub.password is not None
            or staging_hub.query
            or staging_hub.fragment
            or staging_hub.path not in {"", "/"}
        ):
            raise RuntimeError("staging Hub URL is not a bounded HTTPS origin")
        registry_path = urllib.parse.quote(self.request["registry"], safe="/")
        self.staging_url = STAGING_HUB_URL.rstrip("/") + f"/{registry_path}/"

    def validate_downloads(self) -> None:
        """Rechecks every exact anonymously downloaded staging object."""

        request_objects = {
            entry["artifact_id"]: entry for entry in self.request["objects"]
        }
        if len(request_objects) != len(self.request["objects"]):
            raise RuntimeError("request repeats a downloaded object identity")
        if set(request_objects) != set(self.objects) or set(self.objects) != set(
            self.downloads
        ):
            raise RuntimeError("downloaded object inventory differs from the request")

        for artifact_id, expected in request_objects.items():
            path = pathlib.Path(self.objects[artifact_id])
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"downloaded object {artifact_id} is not a regular file")
            size, sha256 = hash_file(path)
            if size != expected["size_bytes"] or sha256 != expected["sha256"]:
                raise RuntimeError(f"downloaded object {artifact_id} changed after capture")
            trace = self.downloads[artifact_id]
            if trace != {"mode": "full", "requests": [{"status": 200}]}:
                raise RuntimeError(f"object {artifact_id} was not anonymously downloaded once")

    def resolve_closure(self) -> None:
        """Resolves signed NAR identities and their exact Contains graph."""

        visited: set[str] = set()
        active: set[str] = set()

        def visit(artifact_id: str) -> None:
            if artifact_id in visited:
                return
            if artifact_id in active:
                raise RuntimeError("package NAR graph contains a cycle")
            active.add(artifact_id)
            artifact = self.artifacts.get(artifact_id)
            if artifact is None:
                raise RuntimeError(f"package closure artifact {artifact_id} is missing")
            if artifact["media_type"] != "application/x-nix-nar":
                raise RuntimeError(f"package closure artifact {artifact_id} is not a NAR")

            authenticated = [
                relation["target"]
                for relation in artifact["relationships"]
                if relation["relation"] == "authenticated-by"
            ]
            narinfo_id = one(authenticated, f"narinfo relationship for {artifact_id}")
            narinfo_artifact = self.artifacts.get(narinfo_id)
            if narinfo_artifact is None or narinfo_artifact["kind"] != "nar-info":
                raise RuntimeError(f"package closure artifact {artifact_id} lacks narinfo")
            narinfo = NarInfo.parse(pathlib.Path(self.objects[narinfo_id]))
            declared_compression = artifact["compression"]
            if declared_compression != narinfo.compression:
                raise RuntimeError(f"artifact and narinfo compression differ for {artifact_id}")
            declared_path = artifact.get("store_path")
            if declared_path is not None and declared_path != narinfo.store_path:
                raise RuntimeError(f"artifact and narinfo paths differ for {artifact_id}")
            if narinfo.store_path in self.closure:
                raise RuntimeError("package closure repeats a Nix store path")
            self.closure[narinfo.store_path] = narinfo
            self.closure_artifacts[narinfo.store_path] = artifact_id

            contained = [
                relation["target"]
                for relation in artifact["relationships"]
                if relation["relation"] == "contains"
            ]
            for dependency_id in contained:
                visit(dependency_id)
            expected_references = tuple(
                sorted(
                    self._store_path_for_artifact(dependency_id)
                    for dependency_id in contained
                )
            )
            if tuple(sorted(narinfo.references)) != expected_references:
                raise RuntimeError(
                    f"narinfo references differ from Contains edges for {artifact_id}"
                )
            active.remove(artifact_id)
            visited.add(artifact_id)

        for subject in self.package_artifact_ids:
            visit(subject)

    def _store_path_for_artifact(self, artifact_id: str) -> str:
        artifact = self.artifacts[artifact_id]
        declared = artifact.get("store_path")
        if declared is not None:
            return declared
        authenticated = [
            relation["target"]
            for relation in artifact["relationships"]
            if relation["relation"] == "authenticated-by"
        ]
        narinfo_id = one(authenticated, f"narinfo relationship for {artifact_id}")
        return NarInfo.parse(pathlib.Path(self.objects[narinfo_id])).store_path

    def import_closure(self) -> None:
        """Imports the exact downloaded NAR graph in dependency order."""

        imported: set[str] = set()

        def import_path(store_path: str) -> None:
            if store_path in imported:
                return
            info = self.closure[store_path]
            for reference in info.references:
                import_path(reference)
            artifact_id = self.closure_artifacts[store_path]
            artifact = self.artifacts[artifact_id]
            transport = pathlib.Path(self.objects[artifact_id])
            self.imported_nar_hashes[store_path] = self._import_nar(
                transport, info
            )
            declared_hash = artifact.get("nar_hash")
            if declared_hash is not None and canonical_sha256(
                declared_hash
            ) != self.imported_nar_hashes[store_path]:
                raise RuntimeError(f"uncompressed NAR hash differs for {artifact_id}")
            imported.add(store_path)

        for store_path in self.outputs.values():
            import_path(store_path)

    def _import_nar(self, transport: pathlib.Path, info: NarInfo) -> str:
        process = subprocess.Popen(
            [NIX_STORE, "--import"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdin is None:
            raise RuntimeError("nix-store import did not expose stdin")
        process.stdin.write(struct.pack("<Q", 1))
        hashed = hashlib.sha256()

        decoder: subprocess.Popen[bytes] | None = None
        if info.compression == "zstd":
            decoder = subprocess.Popen(
                [ZSTD, "-q", "-d", "-c", str(transport)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if decoder.stdout is None:
                raise RuntimeError("zstd decoder did not expose stdout")
            source: BinaryIO = decoder.stdout
        else:
            source = transport.open("rb")

        with source:
            while block := source.read(8 * 1024 * 1024):
                hashed.update(block)
                process.stdin.write(block)
        if decoder is not None:
            decoder_stderr = decoder.stderr.read() if decoder.stderr is not None else b""
            decoder_returncode = decoder.wait()
            if decoder_returncode != 0:
                process.kill()
                raise RuntimeError(
                    "zstd failed while decoding a qualification NAR: "
                    + decoder_stderr[-64 * 1024 :].decode(errors="replace")
                )

        process.stdin.write(struct.pack("<Q", 0x4558494E))
        write_nix_string(process.stdin, info.store_path)
        process.stdin.write(struct.pack("<Q", len(info.references)))
        for reference in info.references:
            write_nix_string(process.stdin, reference)
        write_nix_string(process.stdin, info.deriver or "")
        process.stdin.write(struct.pack("<Q", 0))
        process.stdin.write(struct.pack("<Q", 0))
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=1800)
        if process.returncode != 0:
            raise RuntimeError(
                f"nix-store rejected {info.store_path}: "
                + stderr[-64 * 1024 :].decode(errors="replace")
            )
        imported = [line for line in stdout.decode().splitlines() if line]
        if not imported or imported[-1] != info.store_path:
            raise RuntimeError("nix-store import returned another store path")

        observed_hash = "sha256:" + hashed.hexdigest()
        if canonical_sha256(info.nar_hash) != observed_hash:
            raise RuntimeError(f"uncompressed NAR differs from narinfo for {info.store_path}")
        return observed_hash

    def validate_store_graph(self) -> None:
        """Compares Nix's realized references with the signed NAR graph."""

        roots = sorted(self.outputs.values())
        requisites = set(
            run([NIX_STORE, "--query", "--requisites", *roots])
            .stdout.decode()
            .splitlines()
        )
        if requisites != set(self.closure):
            raise RuntimeError("realized Nix closure differs from the signed manifest graph")
        for store_path, info in self.closure.items():
            references = tuple(
                sorted(
                    run([NIX_STORE, "--query", "--references", store_path])
                    .stdout.decode()
                    .splitlines()
                )
            )
            if references != tuple(sorted(info.references)):
                raise RuntimeError(f"Nix references differ for {store_path}")

    def validate_permissions(self) -> None:
        """Rejects writable regular files or directories in subject outputs."""

        for output_name, store_path in self.outputs.items():
            root = pathlib.Path(store_path)
            if root.is_symlink() or not root.exists():
                raise RuntimeError(f"package output {output_name} was not imported")
            for directory, names, files in os.walk(root, followlinks=False):
                directory_path = pathlib.Path(directory)
                self._validate_mode(directory_path)
                for name in names + files:
                    path = directory_path / name
                    if not path.is_symlink():
                        self._validate_mode(path)

    @staticmethod
    def _validate_mode(path: pathlib.Path) -> None:
        mode = path.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(f"package output contains a writable shared path: {path}")

    def exercise_apm(self) -> tuple[str, dict[str, Any], dict[str, Any]]:
        """Installs, changes, removes, and recovers the exact package."""

        common_environment = os.environ.copy()
        add = [
            APM,
            "registry",
            "add",
            self.staging_url,
            "--name",
            self.client_name,
            "--priority",
            "1000",
            "--tag",
            self.version,
        ]
        for key in TRUST_KEYS:
            add.extend(["--trust-key", key])
        run(add, environment=common_environment)

        run(
            [APM, "install", self.package, "--registry", self.client_name, "--yes"],
            environment=common_environment,
        )
        self._validate_profile_outputs(present=True)
        first_probe = self._run_probe("installed")
        run([APM, "verify", self.package], environment=common_environment)

        run([APM, "reinstall", self.package, "--yes"], environment=common_environment)
        self._validate_profile_outputs(present=True)
        run([APM, "verify", self.package], environment=common_environment)

        run([APM, "remove", self.package, "--yes"], environment=common_environment)
        self._validate_profile_outputs(present=False)
        run([APM, "rollback"], environment=common_environment)
        recovered_generation = self._validate_profile_outputs(present=True)
        run([APM, "verify", self.package], environment=common_environment)
        recovered_probe = self._run_probe("recovered")

        return recovered_generation, first_probe, recovered_probe

    def _profile_current(self) -> pathlib.Path:
        return pathlib.Path(os.environ["AOS_PROFILE_ROOT"]) / "per-user" / os.environ[
            "USER"
        ] / "current"

    def _validate_profile_outputs(self, *, present: bool) -> str:
        current = self._profile_current()
        if not current.is_symlink():
            raise RuntimeError("APM profile lacks its current generation link")
        generation = os.readlink(current)
        if not re.fullmatch(r"gen-[1-9][0-9]*", pathlib.Path(generation).name):
            raise RuntimeError("APM profile current link has an invalid generation")
        for store_path in [self.outputs["out"]]:
            store_hash = pathlib.Path(store_path).name.split("-", 1)[0]
            rooted = current / "usr" / store_hash
            if rooted.is_symlink() != present:
                state = "present" if present else "absent"
                raise RuntimeError(f"package output {store_path} is not {state} in APM profile")
            if present and pathlib.Path(os.path.realpath(rooted)) != pathlib.Path(store_path):
                raise RuntimeError("APM profile root resolves to another package output")
        return pathlib.Path(generation).name

    def _run_probe(self, label: str) -> dict[str, Any]:
        work = ROOT / f"probe-{label}"
        work.mkdir()
        report = work / "result.json"
        closure_path = ":".join(
            str(pathlib.Path(store_path) / directory)
            for store_path in sorted(self.closure)
            for directory in ("bin", "sbin")
            if (pathlib.Path(store_path) / directory).is_dir()
        )
        environment = {
            "HOME": str(work / "home"),
            "USER": os.environ["USER"],
            "TMPDIR": str(work / "tmp"),
            "LC_ALL": "C",
            "PATH": closure_path,
            "AOS_QUALIFICATION_PACKAGE": self.package,
            "AOS_QUALIFICATION_PLATFORM": PLATFORM,
            "AOS_QUALIFICATION_PACKAGE_OUTPUTS": canonical(self.outputs).decode(),
            "AOS_QUALIFICATION_PACKAGE_CLOSURE": canonical(
                sorted(self.closure)
            ).decode(),
            "AOS_QUALIFICATION_PACKAGE_PROFILE": str(self._profile_current()),
            "AOS_QUALIFICATION_PROBE_REPORT": str(report),
            "AOS_QUALIFICATION_PROBE_WORK": str(work),
            "AOS_QUALIFICATION_BASH": os.environ["AOS_QUALIFICATION_BASH"],
            "AOS_QUALIFICATION_CC": os.environ["AOS_QUALIFICATION_CC"],
            "AOS_QUALIFICATION_CXX": os.environ["AOS_QUALIFICATION_CXX"],
            "AOS_QUALIFICATION_PYTHON": os.environ["AOS_QUALIFICATION_PYTHON"],
        }
        pathlib.Path(environment["HOME"]).mkdir()
        pathlib.Path(environment["TMPDIR"]).mkdir()
        run([self.probe], environment=environment, cwd=work)
        if report.is_symlink() or not report.is_file():
            raise RuntimeError("functional probe did not write its regular result file")
        raw = report.read_bytes()
        if len(raw) > MAX_PROBE_RESULT_BYTES:
            raise RuntimeError("functional probe result exceeds its size bound")
        result = decode_json(raw, "functional probe result")
        if raw != canonical(result) + b"\n":
            raise RuntimeError("functional probe result is not canonical JSON")
        if (
            set(result)
            != {
                "schema_version",
                "package",
                "platform",
                "primary",
                "bad_input",
            }
            or result.get("schema_version") != PROBE_RESULT_SCHEMA
            or result.get("package") != self.package
            or result.get("platform") != PLATFORM
        ):
            raise RuntimeError("functional probe result has another identity")
        for result_name in ("primary", "bad_input"):
            observation = result.get(result_name)
            if not isinstance(observation, dict) or set(observation) != {
                "input",
                "operation",
                "expected",
                "observed",
            }:
                raise RuntimeError(f"functional probe lacks its {result_name} observation")
            if any(
                not isinstance(value, str) or not value.strip()
                for value in observation.values()
            ):
                raise RuntimeError(f"functional probe has an empty {result_name} field")
        return result

    def write_report(self, recovered_generation: str, probe: dict[str, Any]) -> None:
        """Writes the scenario report after all effects and checks finish."""

        finished_at, finished_seconds = timestamp()
        machine = run([UNAME, "-m"]).stdout.decode().strip()
        kernel = run([UNAME, "-sr"]).stdout.decode().strip()
        nix_version = run([NIX_STORE, "--version"]).stdout.decode().strip()
        apm_version = run([APM, "--version"], environment=os.environ.copy()).stdout.decode().strip()
        environment = {
            "schema_version": "aos.release.package-environment/v1",
            "platform": PLATFORM,
            "machine": machine,
            "kernel": kernel,
            "nix_store": nix_version,
            "apm": apm_version,
            "probe": self.probe,
            "outputs": self.outputs,
            "closure_store_paths": sorted(self.closure),
        }
        checks = {
            "anonymous-download": {
                "passed": True,
                "detail": (
                    f"Rehashed {len(self.objects)} exact objects downloaded once with "
                    "anonymous HTTPS status 200."
                ),
            },
            "closure-verification": {
                "passed": True,
                "detail": (
                    f"Imported and rehashed {len(self.closure)} signed NAR closure members; "
                    "Nix reported the same realized closure."
                ),
            },
            "functional-behavior": {
                "passed": True,
                "detail": (
                    "The reviewed package-specific primary and bad-input operations passed "
                    "after install and generation recovery."
                ),
            },
            "dependency-obligations": {
                "passed": True,
                "detail": (
                    "Every direct and transitive Nix reference matched signed Contains edges "
                    "and narinfo metadata."
                ),
            },
            "permissions-and-confinement": {
                "passed": True,
                "detail": (
                    "Subject outputs had no group/world-writable paths and the probe received "
                    "only subject-closure PATH entries plus named AOS harness tools."
                ),
            },
        }
        operations = {
            "anonymous_objects": len(self.objects),
            "imported_nars": len(self.closure),
            "package_installs": 1,
            "package_changes": 1,
            "package_removals": 1,
            "generation_recoveries": 1,
            "functional_probe_runs": 2,
        }
        report = {
            "schema_version": "aos.release.qualification-scenario-report/v1",
            "registry": self.request["registry"],
            "release_id": self.request["release_id"],
            "staging_receipt_digest": self.request["staging_receipt_digest"],
            "manifest_digest": self.request["manifest_digest"],
            "case_digest": digest(self.case["schema_version"], self.case),
            "started_at": self.started_at,
            "finished_at": finished_at,
            "observed_seconds": max(0, finished_seconds - self.started_seconds),
            "checks": checks,
            "operations": operations,
            "environment": environment,
            "package": {
                "name": self.package,
                "version": self.version,
                "role": self.case["package_role"],
                "outputs": self.outputs,
                "recovered_generation": recovered_generation,
                "functional_probe": probe,
                "nar_hashes": self.imported_nar_hashes,
            },
        }
        write_canonical(REPORT, report)


def timestamp() -> tuple[str, int]:
    """Returns a canonical UTC timestamp and matching integer seconds."""

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    return now.isoformat().replace("+00:00", "Z"), int(now.timestamp())


def main() -> None:
    """Runs the package scenario and preserves every failure for the coordinator."""

    PackageScenario().execute()


if __name__ == "__main__":
    main()
