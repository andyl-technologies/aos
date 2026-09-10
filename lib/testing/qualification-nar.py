"""Imports a manifest-bound NAR closure through an isolated Nix store.

The qualification coordinator has already verified the release envelope and
downloaded every related object. This module independently binds each NAR to
its manifest record and narinfo, restores it into a new local store, compares
the realized reference graph, and exports the exact imported closure for a
guest store.
"""

from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import re
import selectors
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable


NIX_BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"
STORE_PATH = re.compile(
    rf"^/nix/store/[{NIX_BASE32}]{{32}}-[A-Za-z0-9+._?=-]+$"
)


def one(values: list[Any], label: str) -> Any:
    """Returns the only matching value or fails closed."""

    if len(values) != 1:
        raise RuntimeError(f"expected exactly one {label}, found {len(values)}")
    return values[0]


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


def write_nix_string(destination: BinaryIO, value: str) -> None:
    """Writes one string using Nix's aligned wire encoding."""

    encoded = value.encode()
    destination.write(struct.pack("<Q", len(encoded)))
    destination.write(encoded)
    destination.write(b"\0" * ((8 - len(encoded) % 8) % 8))


def run(
    arguments: list[str],
    *,
    environment: dict[str, str],
    timeout: int = 1800,
) -> subprocess.CompletedProcess[bytes]:
    """Runs one isolated-store command with bounded failure diagnostics."""

    result = subprocess.run(
        arguments,
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


@dataclass(frozen=True)
class NarInfo:
    """Carries the signed import identity parsed from one narinfo object."""

    store_path: str
    nar_hash: str
    nar_size: int
    references: tuple[str, ...]
    deriver: str | None
    compression: str

    @classmethod
    def parse(cls, path: pathlib.Path) -> "NarInfo":
        """Parses the bounded narinfo fields needed for local import."""

        fields: dict[str, list[str]] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
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
        if deriver is not None and (
            not STORE_PATH.fullmatch(deriver) or not deriver.endswith(".drv")
        ):
            raise RuntimeError("narinfo contains an invalid deriver")

        compression = required("Compression")
        if compression not in {"none", "zstd"}:
            raise RuntimeError(
                f"unsupported qualification NAR compression {compression!r}"
            )
        try:
            nar_size = int(required("NarSize"))
        except ValueError as error:
            raise RuntimeError("narinfo contains an invalid NarSize") from error
        if nar_size <= 0:
            raise RuntimeError("narinfo contains a non-positive NarSize")
        return cls(
            store_path=store_path,
            nar_hash=required("NarHash"),
            nar_size=nar_size,
            references=references,
            deriver=deriver,
            compression=compression,
        )


class NarClosure:
    """Resolves and imports one manifest-authenticated Nix closure."""

    def __init__(
        self,
        artifacts: dict[str, dict[str, Any]],
        objects: dict[str, str],
        nix_store: str,
        zstd: str,
        store_root: pathlib.Path,
        validate_object: Callable[[dict[str, Any]], None],
    ) -> None:
        if store_root.exists():
            raise RuntimeError("isolated qualification store already exists")
        self.artifacts = artifacts
        self.objects = objects
        self.nix_store = nix_store
        self.zstd = zstd
        self.store_root = store_root
        self.validate_object = validate_object
        self.environment = os.environ.copy()
        self.environment["NIX_REMOTE"] = f"local?root={store_root}"
        self.infos: dict[str, NarInfo] = {}
        self.artifact_ids: dict[str, str] = {}
        self.imported_nar_hashes: dict[str, str] = {}
        self.initially_absent: list[str] = []

    def resolve(self, root_artifact_ids: list[str]) -> None:
        """Resolves exact narinfo identities and recursive Contains edges."""

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
            if artifact.get("media_type") != "application/x-nix-nar":
                raise RuntimeError(f"package closure artifact {artifact_id} is not a NAR")
            self.validate_object(artifact)

            authenticated = [
                relation["target"]
                for relation in artifact.get("relationships", [])
                if relation.get("relation") == "authenticated-by"
            ]
            narinfo_id = one(authenticated, f"narinfo relationship for {artifact_id}")
            narinfo_artifact = self.artifacts.get(narinfo_id)
            if narinfo_artifact is None or narinfo_artifact.get("kind") != "nar-info":
                raise RuntimeError(f"package closure artifact {artifact_id} lacks narinfo")
            self.validate_object(narinfo_artifact)
            narinfo = NarInfo.parse(pathlib.Path(self.objects[narinfo_id]))
            if artifact.get("compression") != narinfo.compression:
                raise RuntimeError(f"artifact and narinfo compression differ for {artifact_id}")
            declared_path = artifact.get("store_path")
            if declared_path is not None and declared_path != narinfo.store_path:
                raise RuntimeError(f"artifact and narinfo paths differ for {artifact_id}")
            if narinfo.store_path in self.infos:
                raise RuntimeError("package closure repeats a Nix store path")
            self.infos[narinfo.store_path] = narinfo
            self.artifact_ids[narinfo.store_path] = artifact_id

            contained = [
                relation["target"]
                for relation in artifact.get("relationships", [])
                if relation.get("relation") == "contains"
            ]
            for dependency_id in contained:
                # Nix records an ordinary self-reference for some outputs. The
                # release graph preserves that edge, but it is already resolved
                # by the current visit and has no import-order dependency.
                if dependency_id != artifact_id:
                    visit(dependency_id)
            expected_references = tuple(
                sorted(self._store_path_for_artifact(value) for value in contained)
            )
            if tuple(sorted(narinfo.references)) != expected_references:
                raise RuntimeError(
                    f"narinfo references differ from Contains edges for {artifact_id}"
                )
            active.remove(artifact_id)
            visited.add(artifact_id)

        for artifact_id in root_artifact_ids:
            visit(artifact_id)

    def _store_path_for_artifact(self, artifact_id: str) -> str:
        artifact = self.artifacts[artifact_id]
        declared = artifact.get("store_path")
        if declared is not None:
            return declared
        authenticated = [
            relation["target"]
            for relation in artifact.get("relationships", [])
            if relation.get("relation") == "authenticated-by"
        ]
        narinfo_id = one(authenticated, f"narinfo relationship for {artifact_id}")
        return NarInfo.parse(pathlib.Path(self.objects[narinfo_id])).store_path

    def import_roots(self, roots: list[str]) -> None:
        """Imports the downloaded closure into an initially empty local store."""

        if not roots or any(root not in self.infos for root in roots):
            raise RuntimeError("qualification import roots are absent from the NAR graph")
        for root in roots:
            result = subprocess.run(
                [self.nix_store, "--check-validity", root],
                env=self.environment,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                raise RuntimeError("candidate output was already present in isolated store")
            if result.returncode != 1:
                raise RuntimeError(
                    "could not inspect the isolated qualification store: "
                    + result.stderr[-64 * 1024 :].decode(errors="replace")
                )
            self.initially_absent.append(root)

        imported: set[str] = set()

        def import_path(store_path: str) -> None:
            if store_path in imported:
                return
            info = self.infos[store_path]
            for reference in info.references:
                if reference != store_path:
                    import_path(reference)
            artifact_id = self.artifact_ids[store_path]
            artifact = self.artifacts[artifact_id]
            transport = pathlib.Path(self.objects[artifact_id])
            observed = self._import_nar(transport, info)
            declared_hash = artifact.get("nar_hash")
            if declared_hash is not None and canonical_sha256(declared_hash) != observed:
                raise RuntimeError(f"uncompressed NAR hash differs for {artifact_id}")
            self.imported_nar_hashes[store_path] = observed
            imported.add(store_path)

        for root in roots:
            import_path(root)
        if imported != set(self.infos):
            raise RuntimeError("resolved package graph contains unreachable NARs")

        self._validate_store_graph(roots)

    def _import_nar(self, transport: pathlib.Path, info: NarInfo) -> str:
        import_stream = self.store_root.parent / (
            f"import-{pathlib.PurePosixPath(info.store_path).name}.export"
        )
        try:
            with import_stream.open("xb") as destination:
                destination.write(struct.pack("<Q", 1))
                observed_hash = self._write_nar(transport, info, destination)
                destination.write(struct.pack("<Q", 0x4558494E))
                write_nix_string(destination, info.store_path)
                destination.write(struct.pack("<Q", len(info.references)))
                for reference in info.references:
                    write_nix_string(destination, reference)
                write_nix_string(destination, info.deriver or "")
                destination.write(struct.pack("<Q", 0))
                destination.write(struct.pack("<Q", 0))

            with import_stream.open("rb") as source:
                result = subprocess.run(
                    [self.nix_store, "--import"],
                    env=self.environment,
                    check=False,
                    stdin=source,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1800,
                )
        finally:
            import_stream.unlink(missing_ok=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"nix-store rejected {info.store_path}: "
                + result.stderr[-64 * 1024 :].decode(errors="replace")
            )
        imported = [line for line in result.stdout.decode().splitlines() if line]
        if not imported or imported[-1] != info.store_path:
            raise RuntimeError("nix-store import returned another store path")
        if canonical_sha256(info.nar_hash) != observed_hash:
            raise RuntimeError(f"uncompressed NAR differs from narinfo for {info.store_path}")
        return observed_hash

    def _write_nar(
        self,
        transport: pathlib.Path,
        info: NarInfo,
        destination: BinaryIO,
    ) -> str:
        """Writes and hashes exactly the narinfo-declared uncompressed bytes."""

        hashed = hashlib.sha256()
        if info.compression == "none":
            if transport.stat().st_size != info.nar_size:
                raise RuntimeError(f"uncompressed NAR size differs for {info.store_path}")
            with transport.open("rb") as source:
                while block := source.read(8 * 1024 * 1024):
                    hashed.update(block)
                    destination.write(block)
            return "sha256:" + hashed.hexdigest()

        error_path = self.store_root.parent / (
            f"decode-{pathlib.PurePosixPath(info.store_path).name}.log"
        )
        decoded_size = 0
        deadline = time.monotonic() + 1800
        try:
            with error_path.open("xb") as error_output:
                decoder = subprocess.Popen(
                    [self.zstd, "-q", "-d", "-c", str(transport)],
                    stdout=subprocess.PIPE,
                    stderr=error_output,
                )
                if decoder.stdout is None:
                    decoder.kill()
                    decoder.wait()
                    raise RuntimeError("zstd decoder did not expose stdout")
                os.set_blocking(decoder.stdout.fileno(), False)
                selector = selectors.DefaultSelector()
                selector.register(decoder.stdout, selectors.EVENT_READ)
                try:
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(decoder.args, 1800)
                        events = selector.select(timeout=min(remaining, 30))
                        if not events:
                            if decoder.poll() is not None:
                                block = decoder.stdout.read()
                                if block:
                                    decoded_size += len(block)
                                    hashed.update(block)
                                    destination.write(block)
                                break
                            continue
                        block = os.read(decoder.stdout.fileno(), 8 * 1024 * 1024)
                        if not block:
                            break
                        decoded_size += len(block)
                        if decoded_size > info.nar_size:
                            raise RuntimeError(
                                f"decoded NAR exceeds NarSize for {info.store_path}"
                            )
                        hashed.update(block)
                        destination.write(block)
                except BaseException:
                    decoder.kill()
                    decoder.wait()
                    raise
                finally:
                    selector.close()
                    decoder.stdout.close()
                try:
                    decoder.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    decoder.kill()
                    decoder.wait()
                    raise
        finally:
            diagnostics = error_path.read_bytes()[-64 * 1024 :] if error_path.exists() else b""
            error_path.unlink(missing_ok=True)
        if decoder.returncode != 0:
            raise RuntimeError(
                "zstd failed while decoding a qualification NAR: "
                + diagnostics.decode(errors="replace")
            )
        if decoded_size != info.nar_size:
            raise RuntimeError(f"decoded NAR size differs for {info.store_path}")
        return "sha256:" + hashed.hexdigest()

    def _validate_store_graph(self, roots: list[str]) -> None:
        requisites = run(
            [self.nix_store, "--query", "--requisites", *roots],
            environment=self.environment,
        ).stdout.decode().splitlines()
        if set(requisites) != set(self.infos):
            raise RuntimeError("realized Nix closure differs from the signed manifest graph")
        for store_path, info in self.infos.items():
            references = tuple(
                sorted(
                    run(
                        [self.nix_store, "--query", "--references", store_path],
                        environment=self.environment,
                    )
                    .stdout.decode()
                    .splitlines()
                )
            )
            if references != tuple(sorted(info.references)):
                raise RuntimeError(f"Nix references differ for {store_path}")
            realized_hash = run(
                [self.nix_store, "--query", "--hash", store_path],
                environment=self.environment,
            ).stdout.decode().strip()
            if canonical_sha256(realized_hash) != self.imported_nar_hashes[store_path]:
                raise RuntimeError(f"Nix registered another NAR hash for {store_path}")

    def export(self, roots: list[str], destination: pathlib.Path) -> None:
        """Exports the verified closure in guest-importable Nix wire format."""

        requisites = run(
            [self.nix_store, "--query", "--requisites", *roots],
            environment=self.environment,
        ).stdout.decode().splitlines()
        if set(requisites) != set(self.infos):
            raise RuntimeError("isolated store closure changed before export")
        with destination.open("xb") as output:
            result = subprocess.run(
                [self.nix_store, "--export", *requisites],
                env=self.environment,
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
                timeout=3600,
            )
        if result.returncode != 0:
            raise RuntimeError(
                "could not export imported qualification NARs: "
                + result.stderr[-64 * 1024 :].decode(errors="replace")
            )
        if destination.stat().st_size == 0:
            raise RuntimeError("isolated store produced an empty NAR export")
