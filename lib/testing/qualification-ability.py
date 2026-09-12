"""Runs one native ability contract or adapter cohort in a published AOS image.

The release coordinator has already authenticated and downloaded the complete
case object set. This runner binds the server/x86_64 image cell, its unsigned
assembly, and the published AOS command outputs before it imports an
executor-owned reference-provider fixture. The fleet body drives the published
guest through SSH and retains either contract checks or exact matrix probes.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.parse
from typing import Any


ROOT = pathlib.Path.cwd()
REQUEST = ROOT / "request.json"
OBJECTS = ROOT / "objects.json"
PREDECESSOR_OBJECTS = ROOT / "predecessor-objects.json"
REPORT = ROOT / "scenario-report.json"
SCENARIO_REGISTRY = ROOT / "scenario-registry.json"

PLATFORM = os.environ["AOS_QUALIFICATION_PLATFORM"]
SCENARIO_ID = os.environ["AOS_QUALIFICATION_SCENARIO_ID"]
EXPECTED_CHECKS = json.loads(os.environ["AOS_QUALIFICATION_CHECKS"])
STAGING_HUB_URL = os.environ["AOS_QUALIFICATION_STAGING_HUB_URL"]
FIXTURE_CONTRACT = os.environ["AOS_QUALIFICATION_FIXTURE_CONTRACT"]
FIXTURE_ARCHIVE = pathlib.Path(os.environ["AOS_QUALIFICATION_FIXTURE_ARCHIVE"])
RUNTIME_COMPANIONS = json.loads(
    os.environ["AOS_QUALIFICATION_CANDIDATE_RUNTIME_COMPANIONS"]
)
FIXTURE_SCRIPT = pathlib.Path(os.environ["AOS_QUALIFICATION_FIXTURE_SCRIPT"])
SETUP_MODULE = pathlib.Path(os.environ["AOS_QUALIFICATION_SETUP_MODULE"])
MATRIX_SPEC_NAME = os.environ["AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_SPEC"]
MATRIX_SPEC_PATH = pathlib.Path(MATRIX_SPEC_NAME) if MATRIX_SPEC_NAME else None
MATRIX_QUALIFIED_CELLS = json.loads(
    os.environ["AOS_QUALIFICATION_NATIVE_ADAPTER_QUALIFIED_CELLS"]
)
MATRIX_COHORTS = json.loads(
    os.environ["AOS_QUALIFICATION_NATIVE_ADAPTER_COHORTS"]
)
MATRIX_COHORT_SUPPORT_NAME = os.environ[
    "AOS_QUALIFICATION_NATIVE_ADAPTER_COHORT_SUPPORT"
]
MATRIX_COHORT_SUPPORT = (
    pathlib.Path(MATRIX_COHORT_SUPPORT_NAME) if MATRIX_COHORT_SUPPORT_NAME else None
)
IMAGE_SUPPORT = pathlib.Path(os.environ["AOS_QUALIFICATION_IMAGE_SUPPORT"])
NAR_SUPPORT = pathlib.Path(os.environ["AOS_QUALIFICATION_NAR_SUPPORT"])

IMAGE_VARIANT = "server"
MANIFEST_OBJECT = "control/release-manifest-envelope"
ASSEMBLY_MEDIA_TYPE = "application/vnd.aos.image.unsigned-assembly.v2+json"
FINALIZED_SET_MEDIA_TYPE = "application/vnd.aos.image.finalized-set.v1+json"
INITRD_STATIC_CONTRACT = "lib/aos/initrd/static-ability-contract.json"
INITRD_ACTIVATION_SELECTION = "etc/aos/initrd-ability-activation.json"
HOST_STATIC_CONTRACT = "/usr/lib/aos/host/static-ability-contract.json"


def load_support(name: str, path: pathlib.Path) -> Any:
    """Loads one immutable qualification support module."""

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load qualification support {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


IMAGE = load_support("aos_qualification_image_support", IMAGE_SUPPORT)
NAR = load_support("aos_qualification_nar_support", NAR_SUPPORT)
MATRIX_COHORT = (
    load_support("aos_qualification_native_adapter_cohort", MATRIX_COHORT_SUPPORT)
    if MATRIX_COHORT_SUPPORT is not None
    else None
)


def canonical(value: Any) -> bytes:
    """Encodes the canonical JSON form used by release evidence."""

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


def raw_digest(value: Any) -> str:
    """Computes raw SHA-256 over one canonical value."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: pathlib.Path) -> Any:
    """Reads one JSON document from an already bounded local path."""

    with path.open("rb") as source:
        return json.load(source)


def sha256_file(path: pathlib.Path) -> str:
    """Hashes one retained release object without loading it into memory."""

    hashed = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            hashed.update(block)
    return "sha256:" + hashed.hexdigest()


def one(values: list[Any], label: str) -> Any:
    """Selects one structurally unique value or rejects the input."""

    if len(values) != 1:
        raise RuntimeError(f"expected one {label}, found {len(values)}")
    return values[0]


def local_artifact_id(identity: str) -> str:
    """Returns the stable finalizer-local suffix of an artifact identity."""

    return identity.rsplit("/", 1)[-1]


def require_distinct_predecessor_runtime(
    predecessor_runtime: str, candidate_runtime: str
) -> None:
    """Rejects a bootstrap fixture backed by the candidate under test."""

    if predecessor_runtime == candidate_runtime:
        raise RuntimeError(
            "candidate runtime is not distinct from its qualification predecessor"
        )


class PublishedImageMachine(IMAGE.VirtualMachine):
    """Adapts the published-image VM to the fleet test machine interface."""

    boot = "published-image"

    def __init__(self, *args: Any, scenario: "Scenario", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.scenario = scenario
        self.metadata_attached = True
        self.native_tools: dict[str, str] = {}
        self.native_package_runtime = ""
        self.hard_power_cycles = 0
        self.metadata_free_reboots = 0
        self.expected_image_role = "candidate"
        self.rollout_branch = ""

    def _arguments(self) -> list[str]:
        arguments = super()._arguments()
        if self.metadata_attached:
            return arguments

        index = arguments.index("-fw_cfg")
        del arguments[index : index + 2]
        return arguments

    def _ssh_arguments(self, command: str) -> list[str]:
        return [
            IMAGE.SSH,
            "-i",
            str(self.ssh_key),
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "root@127.0.0.1",
            command,
        ]

    def execute(self, command: str, timeout: float = 600) -> tuple[int, str, str]:
        print(f"[{self.name}] {command.splitlines()[0][:160]}", flush=True)
        result = subprocess.run(
            self._ssh_arguments(command),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr

    def succeed(self, *commands: str, timeout: float = 600) -> str:
        output = ""
        for command in commands:
            status, output, error = self.execute(command, timeout=timeout)
            if status != 0:
                raise RuntimeError(
                    f"guest command failed ({status}): {command}\n"
                    + output
                    + error
                )
        return output

    def fail(self, *commands: str, timeout: float = 600) -> str:
        output = ""
        for command in commands:
            status, output, error = self.execute(command, timeout=timeout)
            if status == 0:
                raise RuntimeError(f"guest command unexpectedly succeeded: {command}")
            if status == 255:
                raise RuntimeError(
                    f"SSH transport failed while expecting guest rejection: {command}\n"
                    + output
                    + error
                )
        return output

    def wait_until_succeeds(
        self, command: str, timeout: float = 60, poll: float = 0.5
    ) -> str:
        deadline = time.monotonic() + timeout
        last = (1, "", "")
        while time.monotonic() < deadline:
            try:
                last = self.execute(command, timeout=min(30, timeout))
            except (OSError, subprocess.TimeoutExpired) as error:
                last = (1, "", str(error))
            if last[0] == 0:
                return last[1]
            time.sleep(poll)
        raise RuntimeError(
            f"guest command did not succeed within {timeout}s: {command}\n"
            + last[1]
            + last[2]
        )

    def wait_for_unit(
        self, unit: str, state: str = "active", timeout: float = 60
    ) -> None:
        self.wait_until_succeeds(
            f"systemctl is-active --quiet {unit}", timeout=timeout
        )

    def guest_tool(self, name: str) -> str:
        try:
            return self.native_tools[name]
        except KeyError as error:
            raise RuntimeError(f"published guest tool {name!r} was not bound") from error

    def guest_package_runtime(self) -> str:
        if not self.native_package_runtime:
            raise RuntimeError("published package runtime was not bound")
        return self.native_package_runtime

    def candidate_handler_packages(
        self, packages: list[dict[str, str]]
    ) -> list[dict[str, str]]:
        """Substitutes candidate-bound signed ability companions."""

        package_abilities = {entry["abilities"] for entry in packages}
        expected = {
            (entry["name"], entry["primary"], entry["abilities"])
            for entry in RUNTIME_COMPANIONS
            if entry["abilities"] in package_abilities
        }
        observed = {
            (entry["name"], entry["package"], entry["abilities"])
            for entry in packages
            if entry["abilities"] in self.scenario.candidate_companions
        }
        if observed != expected:
            raise RuntimeError("fleet package list differs from candidate runtime bindings")
        self.scenario.used_candidate_companions.update(
            package_abilities & set(self.scenario.candidate_companions)
        )

        bound = []
        for entry in packages:
            replacement = dict(entry)
            if entry["abilities"] in self.scenario.candidate_companions:
                replacement["abilities"] = self.scenario.candidate_companions[
                    entry["abilities"]
                ]
            bound.append(replacement)
        return bound

    def published_boot_identity(self) -> str:
        return self.scenario.boot_identity

    def expect_published_image(self, role: str) -> None:
        """Selects the exact release image expected at the next observation."""

        if role not in {"candidate", "predecessor"}:
            raise RuntimeError(f"unknown published image role {role!r}")
        self.expected_image_role = role

    def assert_published_image(self, role: str) -> None:
        """Checks that the guest runs the selected finalized image subject."""

        self.expect_published_image(role)
        self.scenario.assert_running_published_boot(self)

    def stage_published_candidate(self) -> None:
        """Pins and fetches the exact candidate from the authenticated staging Hub."""

        self.scenario.stage_candidate_registry(self)

    def assert_published_boot_contract(self, expected: str) -> tuple[str, bytes]:
        if expected != self.scenario.boot_identity:
            raise RuntimeError("fleet scenario expected another published boot identity")
        self.scenario.assert_running_published_boot(self)
        return self.scenario.boot_identity, canonical(self.scenario.initrd_contract)

    def _stop_after_exit(self) -> None:
        if self.serial is not None:
            self.serial.close()
            self.serial = None
        if self.swtpm is not None and self.swtpm.poll() is None:
            self.swtpm.terminate()
            try:
                self.swtpm.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.swtpm.kill()
                self.swtpm.wait(timeout=20)
        self.qemu = None
        self.swtpm = None

    def reboot_without_metadata(self, timeout: float = 600) -> None:
        self.metadata_attached = False
        self.ssh("systemctl poweroff", timeout=30, check=False)
        self._wait_exit(int(timeout))
        self._stop_after_exit()
        self.start()
        self.metadata_free_reboots += 1
        self.counts.reboot_cycles += 1
        self.scenario.assert_running_published_boot(self)

    def power_cycle(self, timeout: float = 600) -> None:
        if self.qemu is None or self.qemu.poll() is not None:
            raise RuntimeError("hard power cycle requires a running QEMU process")

        previous = self.qemu
        if self.serial is not None:
            self.serial.close()
            self.serial = None
        previous.kill()
        try:
            previous.wait(timeout=min(timeout, 30))
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("QEMU survived the hard power cut") from error
        self._stop_after_exit()
        self.start()
        self.hard_power_cycles += 1
        self.counts.cold_boot_cycles += 1
        self.scenario.assert_running_published_boot(self)


class Scenario:
    """Validates release bindings, executes the fleet body, and reports it."""

    def __init__(self) -> None:
        self.request = read_json(REQUEST)
        self.case = self.request["qualification_case"]
        self.objects: dict[str, str] = read_json(OBJECTS)
        self.predecessor_objects: dict[str, str] = read_json(PREDECESSOR_OBJECTS)
        self.started = time.time()
        self.started_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started)
        )
        self.machine: PublishedImageMachine | None = None
        self.boot_assertions = 0
        self.boot_ids: set[str] = set()
        self.rollout_boot_ids: dict[str, set[str]] = {
            "candidate": set(),
            "predecessor": set(),
        }
        self.handoff_assertions = 0
        self.handoff_boot_ids: set[str] = set()
        self.candidate_closure: Any | None = None
        self.candidate_companions: dict[str, str] = {}
        self.used_candidate_companions: set[str] = set()
        self.guest_initially_absent: list[str] = []
        self.total_warm_reboots = 0
        self.total_hard_power_cycles = 0
        self.total_metadata_free_reboots = 0
        self.fixture_namespace: dict[str, Any] = {}
        self.fixture_namespaces: dict[str, dict[str, Any]] = {}
        self.matrix_spec = (
            read_json(MATRIX_SPEC_PATH) if MATRIX_SPEC_PATH is not None else None
        )

        self.work = ROOT / "ability-work"
        self.work.mkdir()
        self.candidate_export = self.work / "candidate-tools.export"
        self.candidate_companion_export = self.work / "candidate-companions.export"
        self.key = self.work / "ssh-key"
        IMAGE.run(
            [IMAGE.SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)]
        )
        public_key = self.key.with_suffix(".pub").read_text(encoding="ascii").strip()
        self.host_config = self.work / "host.nix"
        self.host_config.write_text(self._host_config(public_key), encoding="utf-8")

    @staticmethod
    def _host_config(public_key: str) -> str:
        return f'''{{ ... }}: {{
  aos.roles.server.enable = true;
  aos.services.ssh.enable = true;
  aos.services.ssh.permitRootLogin = "prohibit-password";
  aos.networking.hostName = "ability-qualification";
  environment.etc."ssh/authorized_keys/root".text = "{public_key}";
}}
'''

    def validate_inputs(self) -> None:
        matrix_case = SCENARIO_ID == "ability-native-adapter-matrix"
        rollout_case = SCENARIO_ID == "ability-native-image-rollout"
        if PLATFORM != "x86_64-linux" or self.request["platform"] != PLATFORM:
            raise RuntimeError("native ability qualification requires x86_64 Linux")
        if (
            self.case.get("schema_version") != "aos.release.qualification-case/v2"
            or self.case["id"] != f"{SCENARIO_ID}/release"
            or self.case["requirement_id"] != SCENARIO_ID
            or self.case["phase"] != "staging"
            or self.case.get("platform") is not None
            or self.case.get("target") is not None
            or self.case.get("claim") is not None
            or self.case["checks"] != EXPECTED_CHECKS
        ):
            raise RuntimeError("ability case differs from the implemented native scenario")
        if matrix_case != (self.matrix_spec is not None):
            raise RuntimeError("matrix specification is inapplicable to this native scenario")
        if matrix_case:
            matrix_checks = [
                check
                for check in EXPECTED_CHECKS
                if check.startswith("native-adapter-matrix-v1-sha256-")
            ]
            if (
                not self.case.get("predecessor")
                or len(matrix_checks) != 1
                or matrix_checks[0]
                != "native-adapter-matrix-v1-sha256-"
                + raw_digest(self.matrix_spec).removeprefix("sha256:")
            ):
                raise RuntimeError("matrix specification differs from the exact case")
        elif rollout_case:
            if not self.case.get("predecessor") or not self.predecessor_objects:
                raise RuntimeError("image rollout case lacks its verified predecessor")
        elif self.case.get("predecessor") is not None or self.predecessor_objects:
            raise RuntimeError("ordinary ability scenario unexpectedly names a predecessor")

        manifest = read_json(pathlib.Path(self.objects[MANIFEST_OBJECT]))
        payload = manifest["payload"]
        if (
            payload["registry"] != self.request["registry"]
            or payload["release_id"] != self.request["release_id"]
            or manifest["payload_digest"] != self.request["manifest_digest"]
            or digest("aos.release.manifest/v1", payload)
            != self.request["manifest_digest"]
        ):
            raise RuntimeError("release manifest differs from the executor request")
        self.manifest = manifest
        self.payload = payload
        manifest_artifacts = payload["artifacts"]
        self.artifacts = {artifact["id"]: artifact for artifact in manifest_artifacts}
        if len(self.artifacts) != len(manifest_artifacts):
            raise RuntimeError("release manifest repeats an artifact identity")

        image = one(
            [
                entry
                for entry in payload["images"]
                if entry["system_variant"] == IMAGE_VARIANT
            ],
            "server image",
        )
        cell = one(
            [entry for entry in image["platforms"] if entry["platform"] == PLATFORM],
            "server x86_64 image cell",
        )
        if cell["decision"].get("state") != "artifact":
            raise RuntimeError("server x86_64 image cell is not a finalized artifact")
        self.image_ids = cell["decision"]["artifact"]["artifact_ids"]
        if any(
            identity not in self.case["subjects"] or identity not in self.objects
            for identity in self.image_ids
        ):
            raise RuntimeError("published server image artifacts are outside the case subjects")

        self.qcow2_artifact = self._cell_artifact("qcow2-image", "qcow2")
        self.uki_artifact = self._cell_artifact("uki", "uki-a")
        self.uki_b_artifact = self._cell_artifact("uki", "uki-b")
        self.metadata_artifact = self._cell_artifact("image-metadata", "metadata")
        self.qcow2_path = pathlib.Path(self.objects[self.qcow2_artifact["id"]])
        self.uki_path = pathlib.Path(self.objects[self.uki_artifact["id"]])
        self.metadata = read_json(pathlib.Path(self.objects[self.metadata_artifact["id"]]))
        self._validate_object(self.qcow2_artifact)
        self._validate_object(self.uki_artifact)
        self._validate_object(self.uki_b_artifact)
        self._validate_object(self.metadata_artifact)

        self.assembly_artifact = self._provenance_artifact(ASSEMBLY_MEDIA_TYPE)
        self.finalized_artifact = self._provenance_artifact(FINALIZED_SET_MEDIA_TYPE)
        self.assembly = read_json(pathlib.Path(self.objects[self.assembly_artifact["id"]]))
        self.finalized = read_json(pathlib.Path(self.objects[self.finalized_artifact["id"]]))
        self._validate_object(self.assembly_artifact)
        self._validate_object(self.finalized_artifact)
        self._validate_image_controls()
        if rollout_case:
            self._bind_predecessor_image()
        self._bind_published_package_outputs()
        self._prepare_candidate_handler_companions()

        self.boot_identity = "+".join(
            [
                self.qcow2_artifact["id"],
                self.uki_artifact["id"],
                self.assembly_artifact["id"],
            ]
        )

    def _bind_predecessor_image(self) -> None:
        """Binds the verified predecessor bundle to its finalized server image."""

        manifest_path = self.predecessor_objects.get(MANIFEST_OBJECT)
        if manifest_path is None:
            raise RuntimeError("predecessor bundle lacks its manifest envelope")
        manifest = read_json(pathlib.Path(manifest_path))
        expected = self.case["predecessor"]
        payload = manifest["payload"]
        if (
            payload["registry"] != expected["registry"]
            or payload["release_id"] != expected["release_id"]
            or manifest["payload_digest"] != expected["manifest_digest"]
            or digest("aos.release.manifest/v1", payload)
            != expected["manifest_digest"]
        ):
            raise RuntimeError("predecessor manifest differs from the frozen case")

        artifacts = {entry["id"]: entry for entry in payload["artifacts"]}
        if len(artifacts) != len(payload["artifacts"]):
            raise RuntimeError("predecessor manifest repeats an artifact identity")
        image = one(
            [
                entry
                for entry in payload["images"]
                if entry["system_variant"] == IMAGE_VARIANT
            ],
            "predecessor server image",
        )
        cell = one(
            [entry for entry in image["platforms"] if entry["platform"] == PLATFORM],
            "predecessor server x86_64 image cell",
        )
        if cell["decision"].get("state") != "artifact":
            raise RuntimeError("predecessor server image cell is not finalized")
        image_ids = cell["decision"]["artifact"]["artifact_ids"]
        if any(
            identity not in artifacts
            or identity not in self.predecessor_objects
            for identity in image_ids
        ):
            raise RuntimeError("predecessor image is outside its frozen object bundle")

        def cell_artifact(kind: str, suffix: str) -> dict[str, Any]:
            return one(
                [
                    artifacts[identity]
                    for identity in image_ids
                    if artifacts[identity]["kind"] == kind
                    and local_artifact_id(identity) == suffix
                ],
                f"predecessor {suffix} artifact",
            )

        def provenance(media_type: str) -> dict[str, Any]:
            return one(
                [
                    artifact
                    for artifact in artifacts.values()
                    if artifact["kind"] == "provenance"
                    and artifact["platform"] == PLATFORM
                    and artifact["media_type"] == media_type
                    and f"/images/{IMAGE_VARIANT}/{PLATFORM}/"
                    in f"/{artifact['path']}"
                    and artifact["id"] in self.predecessor_objects
                ],
                f"predecessor {media_type} provenance",
            )

        def validate_object(artifact: dict[str, Any]) -> pathlib.Path:
            path = pathlib.Path(self.predecessor_objects[artifact["id"]])
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("predecessor image object is not a regular file")
            if (
                path.stat().st_size != artifact["size_bytes"]
                or sha256_file(path) != artifact["sha256"]
            ):
                raise RuntimeError(
                    f"predecessor object differs from {artifact['id']}"
                )
            return path

        qcow2 = cell_artifact("qcow2-image", "qcow2")
        uki = cell_artifact("uki", "uki-a")
        uki_b = cell_artifact("uki", "uki-b")
        metadata_artifact = cell_artifact("image-metadata", "metadata")
        assembly_artifact = provenance(ASSEMBLY_MEDIA_TYPE)
        finalized_artifact = provenance(FINALIZED_SET_MEDIA_TYPE)
        qcow2_path = validate_object(qcow2)
        uki_path = validate_object(uki)
        validate_object(uki_b)
        metadata = read_json(validate_object(metadata_artifact))
        assembly = read_json(validate_object(assembly_artifact))
        finalized = read_json(validate_object(finalized_artifact))
        assembly_digest = digest(assembly["schema_version"], assembly)
        finalized_facts = {entry["id"]: entry for entry in finalized["artifacts"]}
        files = {entry["kind"]: entry for entry in assembly["files"]}
        if (
            assembly["schema_version"] != "aos.image.unsigned-assembly/v4"
            or assembly["release_id"] != expected["release_id"]
            or assembly["platform"] != PLATFORM
            or assembly["system_variant"] != IMAGE_VARIANT
            or finalized["schema_version"] != "aos.image.finalized-set/v1"
            or finalized["assembly_digest"] != assembly_digest
            or finalized["platform"] != PLATFORM
            or finalized["system_variant"] != IMAGE_VARIANT
            or len(finalized_facts) != len(finalized["artifacts"])
            or metadata.get("schema_version") != "aos.image.metadata/v2"
            or metadata["assembly_digest"] != assembly_digest
            or metadata["release_id"] != expected["release_id"]
            or metadata["version"] != assembly["version"]
            or metadata["efi"]["normal_a"]["artifact"]["sha256"] != uki["sha256"]
            or metadata["efi"]["normal_a"]["artifact"]["size_bytes"]
            != uki["size_bytes"]
            or metadata["efi"]["normal_b"]["artifact"]["sha256"]
            != uki_b["sha256"]
            or metadata["efi"]["normal_b"]["artifact"]["size_bytes"]
            != uki_b["size_bytes"]
            or "host-static-ability-contract" not in files
        ):
            raise RuntimeError("predecessor finalized image controls disagree")
        for local_id, kind, artifact in (
            ("qcow2", "qcow2", qcow2),
            ("uki-a", "uki-a", uki),
            ("uki-b", "uki-b", uki_b),
            ("metadata", "metadata", metadata_artifact),
        ):
            fact = finalized_facts.get(local_id, {})
            if (
                fact.get("kind") != kind
                or fact.get("sha256") != artifact["sha256"]
                or fact.get("size_bytes") != artifact["size_bytes"]
            ):
                raise RuntimeError(
                    f"predecessor finalized {local_id} differs from its manifest"
                )

        self.predecessor_image = {
            "assembly": assembly,
            "assembly_artifact": assembly_artifact,
            "finalized_artifact": finalized_artifact,
            "host_static_contract": files["host-static-ability-contract"],
            "metadata": metadata,
            "metadata_artifact": metadata_artifact,
            "qcow2_artifact": qcow2,
            "qcow2_path": qcow2_path,
            "uki_artifact": uki,
            "uki_b_artifact": uki_b,
            "uki_path": uki_path,
            "version": payload["version"],
        }

    def _candidate_runtime_artifact(self) -> dict[str, str]:
        if self.candidate_closure is None:
            raise RuntimeError("candidate NAR closure was not validated")
        root = self.package_outputs["packageRuntime"]["store_path"]
        pending = [root]
        reachable: set[str] = set()
        while pending:
            store_path = pending.pop()
            if store_path in reachable:
                continue
            info = self.candidate_closure.infos.get(store_path)
            if info is None:
                raise RuntimeError("candidate runtime closure is incomplete")
            reachable.add(store_path)
            pending.extend(
                reference
                for reference in info.references
                if reference != store_path
            )

        members = []
        for store_path in sorted(reachable):
            info = self.candidate_closure.infos[store_path]
            references = sorted(
                {
                    pathlib.PurePosixPath(reference).name.split("-", 1)[0]
                    for reference in info.references
                    if reference != store_path
                }
            )
            member: dict[str, Any] = {
                "store_path": store_path,
                "nar_hash": self.candidate_closure.imported_nar_hashes[store_path],
                "nar_size": info.nar_size,
            }
            if references:
                member["references"] = references
            members.append(member)

        nar_hash = self.candidate_closure.imported_nar_hashes[root]
        content = digest(
            "aos.ability.artifact/v1",
            {"store_path": root, "nar_hash": nar_hash},
        )
        return {
            "content": content,
            "store_path": root,
            "nar_hash": nar_hash,
            "closure": digest("aos.ability.closure/v1", members),
        }

    @staticmethod
    def _replace_artifact(
        value: Any, old_runtime: str, artifact: dict[str, str]
    ) -> tuple[Any, int]:
        artifact_keys = {"content", "store_path", "nar_hash", "closure"}
        if (
            isinstance(value, dict)
            and set(value) == artifact_keys
            and value.get("store_path") == old_runtime
        ):
            return dict(artifact), 1
        if isinstance(value, dict):
            replaced: dict[str, Any] = {}
            count = 0
            for key, child in value.items():
                replaced[key], child_count = Scenario._replace_artifact(
                    child, old_runtime, artifact
                )
                count += child_count
            return replaced, count
        if isinstance(value, list):
            replaced_list = []
            count = 0
            for child in value:
                replacement, child_count = Scenario._replace_artifact(
                    child, old_runtime, artifact
                )
                replaced_list.append(replacement)
                count += child_count
            return replaced_list, count
        return value, 0

    def _patch_companion(
        self,
        binding: dict[str, str],
        artifact: dict[str, str],
        destination: pathlib.Path,
    ) -> None:
        source = pathlib.Path(binding["abilities"])
        document = read_json(source / "package.json")
        providers_before = document["implementation"]["providers"]
        patched, replacements = self._replace_artifact(
            document, binding["originalRuntime"], artifact
        )
        if replacements == 0:
            raise RuntimeError(
                f"{binding['name']} does not declare the executor runtime artifact"
            )

        providers_after = patched["implementation"]["providers"]
        for before, after in zip(providers_before, providers_after, strict=True):
            if before == after:
                continue
            implementation = digest(
                "aos.ability.provider-implementation/v1", after
            )
            exports = [
                export
                for export in patched["exports"]
                if export["interface"] == after["interface"]
            ]
            one(exports, f"candidate-bound export in {binding['name']}")[
                "implementation"
            ] = implementation

        artifacts = {entry["content"]: entry for entry in patched["artifacts"]}
        if len(artifacts) != len(patched["artifacts"]):
            raise RuntimeError("candidate-bound companion repeats an artifact identity")
        patched["artifacts"] = [artifacts[key] for key in sorted(artifacts)]

        destination.mkdir()
        interfaces = source / "interfaces"
        if interfaces.is_symlink() or not interfaces.is_dir():
            raise RuntimeError("ability companion interface root is not a directory")
        shutil.copytree(interfaces, destination / "interfaces")
        (destination / "package.json").write_bytes(canonical(patched))

    def _prepare_candidate_handler_companions(self) -> None:
        if self.candidate_closure is None:
            raise RuntimeError("candidate NAR closure was not validated")
        if not isinstance(RUNTIME_COMPANIONS, list) or not RUNTIME_COMPANIONS:
            raise RuntimeError("native ability scenario lacks candidate runtime bindings")

        with FIXTURE_ARCHIVE.open("rb") as source:
            result = subprocess.run(
                [self.candidate_closure.nix_store, "--import"],
                env=self.candidate_closure.environment,
                check=False,
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3600,
            )
        if result.returncode != 0:
            raise RuntimeError(
                "isolated store rejected the fixture closure: "
                + result.stderr[-64 * 1024 :].decode(errors="replace")
            )

        artifact = self._candidate_runtime_artifact()
        patch_root = self.work / "candidate-companions"
        patch_root.mkdir()
        patched_paths = []
        seen_names: set[str] = set()
        for binding in RUNTIME_COMPANIONS:
            required = {"name", "primary", "abilities", "originalRuntime"}
            if set(binding) != required or binding["name"] in seen_names:
                raise RuntimeError("candidate runtime companion binding is malformed")
            seen_names.add(binding["name"])
            require_distinct_predecessor_runtime(
                binding["originalRuntime"], artifact["store_path"]
            )

            destination = patch_root / f"{binding['name']}-candidate-abilities"
            self._patch_companion(binding, artifact, destination)
            added = NAR.run(
                [self.candidate_closure.nix_store, "--add", str(destination)],
                environment=self.candidate_closure.environment,
            ).stdout.decode().strip()
            if not NAR.STORE_PATH.fullmatch(added):
                raise RuntimeError("isolated store returned an invalid companion path")
            references = NAR.run(
                [self.candidate_closure.nix_store, "--query", "--references", added],
                environment=self.candidate_closure.environment,
            ).stdout.decode().splitlines()
            if artifact["store_path"] not in references:
                raise RuntimeError("candidate-bound companion does not retain its runtime")
            self.candidate_companions[binding["abilities"]] = added
            patched_paths.append(added)

        with self.candidate_companion_export.open("xb") as destination:
            result = subprocess.run(
                [self.candidate_closure.nix_store, "--export", *patched_paths],
                env=self.candidate_closure.environment,
                check=False,
                stdout=destination,
                stderr=subprocess.PIPE,
                timeout=3600,
            )
        if result.returncode != 0:
            self.candidate_companion_export.unlink(missing_ok=True)
            raise RuntimeError(
                "could not export candidate-bound companions: "
                + result.stderr[-64 * 1024 :].decode(errors="replace")
            )

    def _cell_artifact(self, kind: str, suffix: str) -> dict[str, Any]:
        artifact = one(
            [
                self.artifacts[identity]
                for identity in self.image_ids
                if self.artifacts[identity]["kind"] == kind
                and local_artifact_id(identity) == suffix
            ],
            f"{IMAGE_VARIANT}/{PLATFORM} {suffix} artifact",
        )
        if (
            artifact.get("platform") != PLATFORM
            or artifact.get("system_variant") != IMAGE_VARIANT
        ):
            raise RuntimeError(f"published image artifact {suffix} names another target")
        return artifact

    def _provenance_artifact(self, media_type: str) -> dict[str, Any]:
        artifact = one(
            [
                value
                for value in self.artifacts.values()
                if value["kind"] == "provenance"
                and value["platform"] == PLATFORM
                and value["media_type"] == media_type
                and f"/images/{IMAGE_VARIANT}/{PLATFORM}/" in f"/{value['path']}"
            ],
            f"{IMAGE_VARIANT}/{PLATFORM} {media_type} provenance",
        )
        if artifact["id"] not in self.case["subjects"] or artifact["id"] not in self.objects:
            raise RuntimeError("image provenance is outside the release-scoped case")
        return artifact

    def _validate_object(self, artifact: dict[str, Any]) -> None:
        identity = artifact["id"]
        object_path = self.objects.get(identity)
        if object_path is None:
            raise RuntimeError(f"downloaded object {identity} is missing")
        path = pathlib.Path(object_path)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"downloaded object {identity} is not a regular file")
        if (
            path.stat().st_size != artifact["size_bytes"]
            or sha256_file(path) != artifact["sha256"]
        ):
            raise RuntimeError(f"downloaded object differs from {artifact['id']}")

    def _validate_image_controls(self) -> None:
        if (
            self.assembly["schema_version"] != "aos.image.unsigned-assembly/v4"
            or self.assembly["release_id"] != self.request["release_id"]
            or self.assembly["platform"] != PLATFORM
            or self.assembly["system_variant"] != IMAGE_VARIANT
        ):
            raise RuntimeError("unsigned image assembly lacks the native ability contracts")
        assembly_digest = digest(self.assembly["schema_version"], self.assembly)
        if (
            self.finalized["schema_version"] != "aos.image.finalized-set/v1"
            or self.finalized["assembly_digest"] != assembly_digest
            or self.finalized["platform"] != PLATFORM
            or self.finalized["system_variant"] != IMAGE_VARIANT
            or self.metadata.get("schema_version") != "aos.image.metadata/v2"
            or self.metadata["assembly_digest"] != assembly_digest
            or self.metadata["release_id"] != self.request["release_id"]
            or self.metadata["version"] != self.assembly["version"]
            or self.metadata["platform"] != PLATFORM
            or self.metadata["system_variant"] != IMAGE_VARIANT
        ):
            raise RuntimeError("finalized image controls differ from their exact assembly")

        finalized = {entry["id"]: entry for entry in self.finalized["artifacts"]}
        if len(finalized) != len(self.finalized["artifacts"]):
            raise RuntimeError("finalized image set repeats an artifact identity")
        for local_id, kind, artifact in (
            ("qcow2", "qcow2", self.qcow2_artifact),
            ("uki-a", "uki-a", self.uki_artifact),
            ("uki-b", "uki-b", self.uki_b_artifact),
            ("metadata", "metadata", self.metadata_artifact),
        ):
            fact = finalized[local_id]
            if (
                fact["kind"] != kind
                or fact["sha256"] != artifact["sha256"]
                or fact["size_bytes"] != artifact["size_bytes"]
            ):
                raise RuntimeError(f"finalized {local_id} fact differs from the manifest")

        metadata_uki = self.metadata["efi"]["normal_a"]["artifact"]
        metadata_uki_b = self.metadata["efi"]["normal_b"]["artifact"]
        if (
            metadata_uki["sha256"] != self.uki_artifact["sha256"]
            or metadata_uki["size_bytes"] != self.uki_artifact["size_bytes"]
            or metadata_uki_b["sha256"] != self.uki_b_artifact["sha256"]
            or metadata_uki_b["size_bytes"] != self.uki_b_artifact["size_bytes"]
        ):
            raise RuntimeError("image metadata differs from the published slot UKIs")
        self.initrd_contract = self.assembly["initrd_contract"]
        files = {entry["kind"]: entry for entry in self.assembly["files"]}
        required_files = {
            "host-static-ability-contract",
            "initrd",
            "initrd-static-ability-contract",
        }
        if (
            len(files) != len(self.assembly["files"])
            or not required_files <= files.keys()
        ):
            raise RuntimeError("unsigned image assembly repeats or omits a handoff file")
        if self.initrd_contract["schema_version"] != "aos.boot.initrd-stage-contract/v1":
            raise RuntimeError("published initrd omits its stage handoff contract")
        if files["initrd"]["sha256"] != self.initrd_contract["artifact"]["sha256"]:
            raise RuntimeError("initrd stage contract differs from its assembly file")

        extracted = self.work / "published-slot-a.initrd.zst"
        IMAGE.run(
            [
                IMAGE.OBJCOPY,
                "-O",
                "binary",
                "--only-section=.initrd",
                str(self.uki_path),
                str(extracted),
            ]
        )
        if (
            extracted.stat().st_size != self.initrd_contract["artifact"]["size_bytes"]
            or sha256_file(extracted) != self.initrd_contract["artifact"]["sha256"]
        ):
            raise RuntimeError("published UKI embeds another initrd")

        archive = self.work / "published-slot-a.initrd.cpio"
        IMAGE.decode_zstd_bounded(extracted, archive)
        entries = IMAGE.read_newc_entries(
            archive,
            {INITRD_ACTIVATION_SELECTION, INITRD_STATIC_CONTRACT},
        )
        mode, contents = entries[INITRD_STATIC_CONTRACT]
        static_file = files["initrd-static-ability-contract"]
        static_digest = "sha256:" + hashlib.sha256(contents).hexdigest()
        if mode & 0o170000 != 0o100000 or static_digest != static_file["sha256"]:
            raise RuntimeError("published initrd static ability contract differs from its assembly")

        selection_mode, selection_bytes = entries[INITRD_ACTIVATION_SELECTION]
        selection = json.loads(selection_bytes)
        if (
            selection_mode & 0o170000 != 0o100000
            or canonical(selection) != selection_bytes
            or selection.get("schema")
            != "aos.ability.initrd-activation-selection/v1"
            or selection.get("execution_stage") != "initrd"
            or selection.get("disposition") != "none"
            or selection.get("activation") is not None
            or selection.get("static_ability_contract_sha256") != static_digest
        ):
            raise RuntimeError("published initrd activation selection is not canonical no-work input")

        self.initrd_selection = selection
        self.initrd_selection_bytes = selection_bytes
        self.initrd_static_contract = static_file
        self.host_static_contract = files["host-static-ability-contract"]

    def _bind_published_package_outputs(self) -> None:
        package = one(
            [entry for entry in self.payload["packages"] if entry["name"] == "aos"],
            "published aos package",
        )
        cell = one(
            [entry for entry in package["platforms"] if entry["platform"] == PLATFORM],
            "published aos x86_64 package cell",
        )
        if cell["decision"].get("state") != "artifact":
            raise RuntimeError("published aos package cell is not an artifact")
        package_ids = cell["decision"]["artifact"]["artifact_ids"]
        if any(
            identity not in self.case["subjects"]
            or identity not in self.artifacts
            or identity not in self.objects
            for identity in package_ids
        ):
            raise RuntimeError("published aos outputs are outside the release-scoped case")
        direct = [self.artifacts[identity] for identity in package_ids]
        if any(
            artifact.get("kind") != "package-nar"
            or artifact.get("platform") != PLATFORM
            for artifact in direct
        ):
            raise RuntimeError("published aos cell contains a non-NAR output")
        outputs = {artifact.get("output"): artifact for artifact in direct}
        if len(outputs) != len(direct) or None in outputs:
            raise RuntimeError("published aos package repeats or omits an output name")
        required = {"out", "apm", "apr", "packageRuntime"}
        if not required <= outputs.keys():
            raise RuntimeError("published aos package lacks a required command output")
        self.package_outputs = {name: outputs[name] for name in sorted(required)}
        root_ids = [artifact["id"] for artifact in self.package_outputs.values()]
        roots = [artifact["store_path"] for artifact in self.package_outputs.values()]
        closure = NAR.NarClosure(
            self.artifacts,
            self.objects,
            IMAGE.NIX_STORE,
            IMAGE.ZSTD,
            self.work / "candidate-nix-store",
            self._validate_object,
        )
        closure.resolve(root_ids)
        closure.import_roots(roots)
        closure.export(roots, self.candidate_export)
        apr_path = self.package_outputs["apr"]["store_path"]
        if apr_path not in closure.initially_absent:
            raise RuntimeError("candidate apr was present before isolated import")
        self.candidate_closure = closure

    def assert_running_published_boot(self, machine: PublishedImageMachine) -> None:
        if machine.expected_image_role == "predecessor":
            image = self.predecessor_image
        else:
            image = {
                "assembly": self.assembly,
                "host_static_contract": self.host_static_contract,
                "metadata": self.metadata,
                "qcow2_artifact": self.qcow2_artifact,
                "uki_artifact": self.uki_artifact,
                "uki_b_artifact": self.uki_b_artifact,
            }

        boot_id = machine.ssh("cat /proc/sys/kernel/random/boot_id").strip()
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            boot_id,
        ) is None:
            raise RuntimeError("running guest returned an invalid boot ID")

        state = json.loads(machine.ssh("cat /var/lib/profiles/image/state.json"))
        running = state["running"]
        generation = one(
            [entry for entry in state["generations"] if entry["number"] == running],
            "running image generation",
        )
        if generation["slot"] not in {"A", "B"}:
            raise RuntimeError("native ability scenario booted outside a published slot")
        uki_path = generation["uki_path"]
        if re.fullmatch(r"EFI/Linux/[A-Za-z0-9+._-]+[.]efi", uki_path) is None:
            raise RuntimeError("running image records an unsafe UKI path")
        installed = machine.ssh(
            f"sha256sum /boot/{uki_path} | cut -d ' ' -f1"
        ).strip()
        expected_uki = (
            image["uki_artifact"]
            if generation["slot"] == "A"
            else image["uki_b_artifact"]
        )
        if "sha256:" + installed != expected_uki["sha256"]:
            raise RuntimeError("running guest did not boot the exact published slot UKI")
        kernel = machine.ssh("uname -r").strip()
        if (
            kernel != image["assembly"]["kernel_release"]
            or kernel != image["metadata"]["capabilities"]["kernel_release"]
        ):
            raise RuntimeError("running kernel differs from the published image contract")
        root_hash = image["metadata"]["root"]["root_hash"]
        machine.ssh(f"grep -Eq '(^| )roothash={re.escape(root_hash)}($| )' /proc/cmdline")
        host_contract = machine.ssh(
            f"sha256sum {HOST_STATIC_CONTRACT} | cut -d ' ' -f1"
        ).strip()
        if "sha256:" + host_contract != image["host_static_contract"]["sha256"]:
            raise RuntimeError("running root differs from its host static ability contract")
        if machine.native_package_runtime and machine.expected_image_role == "candidate":
            self.assert_initrd_handoff(machine, boot_id)

        self.boot_ids.add(boot_id)
        self.rollout_boot_ids[machine.expected_image_role].add(boot_id)
        self.boot_assertions = len(self.boot_ids)

    def assert_initrd_handoff(
        self, machine: PublishedImageMachine, boot_id: str
    ) -> None:
        """Checks the selected initrd work and its durable host receipt."""

        if boot_id in self.handoff_boot_ids:
            return

        checkpoint_text = machine.ssh(
            "cat /run/aos/ability-stage-handoff/initrd.json"
        )
        checkpoint = json.loads(checkpoint_text)
        state = json.loads(machine.ssh("cat /var/lib/profiles/image/state.json"))
        running = one(
            [
                generation
                for generation in state["generations"]
                if generation["number"] == state["running"]
            ],
            "running image generation for initrd handoff",
        )
        contract_sha256 = "sha256:" + machine.ssh(
            "sha256sum /usr/lib/aos/initrd/static-ability-contract.json "
            "| cut -d ' ' -f1"
        ).strip()
        selection_sha256 = "sha256:" + hashlib.sha256(
            self.initrd_selection_bytes
        ).hexdigest()
        transaction = checkpoint.get("transaction", "")
        expected_transaction = "initrd-" + boot_id.replace("-", "")

        if (
            contract_sha256 != self.initrd_static_contract["sha256"]
            or self.initrd_selection.get("static_ability_contract_sha256")
            != contract_sha256
        ):
            raise RuntimeError("running root differs from the published initrd selection")
        expected_image = {
            "generation": running["number"],
            "toplevel": running["toplevel"],
            "module_abi": running["module_abi"],
            "baselib_digest": running["baselib_digest"],
            "root_verity_roothash": running.get("root_verity_roothash"),
        }
        if (
            checkpoint.get("schema")
            != "aos.ability.stage-handoff-checkpoint/v1"
            or checkpoint.get("source_stage") != "initrd"
            or checkpoint.get("receiver_stage") != "host"
            or checkpoint.get("boot_id") != boot_id
            or transaction != expected_transaction
            or checkpoint.get("image") != expected_image
            or checkpoint.get("selection_sha256") != selection_sha256
            or checkpoint.get("static_ability_contract_sha256") != contract_sha256
            or checkpoint.get("disposition") != "none"
            or checkpoint.get("activation_sha256") is not None
            or checkpoint.get("status") != "ownership-released"
            or re.fullmatch(r"sha256:[0-9a-f]{64}", checkpoint.get("journal_head", ""))
            is None
        ):
            raise RuntimeError("initrd ownership checkpoint differs from the running image")

        journal = (
            "/var/lib/profiles/image/ability-stage-transactions/initrd/"
            f"{transaction}/execution.journal"
        )
        machine.succeed(
            "systemctl is-active --quiet aos-ability-host-receiver.service && "
            f"test -f {journal} && test ! -L {journal} && "
            f"test $(stat -c %u {journal}) -eq 0 && "
            f"test $(stat -c %h {journal}) -eq 1 && "
            f"test $((0$(stat -c %a {journal}) & 022)) -eq 0"
        )
        before = machine.ssh(
            f"stat -c '%s' {journal}; sha256sum {journal} | cut -d ' ' -f1"
        )
        machine.succeed(
            f"{machine.guest_package_runtime()} __ability-stage-receive "
            "--from-stage initrd --image-profile /var/lib/profiles/image"
        )
        after = machine.ssh(
            f"stat -c '%s' {journal}; sha256sum {journal} | cut -d ' ' -f1"
        )
        if before != after:
            raise RuntimeError("idempotent host receipt changed the initrd handoff journal")
        self.handoff_boot_ids.add(boot_id)
        self.handoff_assertions += 1

    def bind_native_package_runtime(self, machine: PublishedImageMachine) -> None:
        """Binds and verifies the candidate runtime already owned by the image."""

        runtime_path = self.package_outputs["packageRuntime"]["store_path"]
        machine.native_package_runtime = (
            f"{runtime_path}/bin/.aos-package-runtime-unwrapped"
        )
        machine.succeed(
            f"test -x {machine.native_package_runtime} && "
            f"nix-store --verify-path {runtime_path}",
            timeout=1200,
        )
        if machine.expected_image_role == "candidate":
            self.verify_native_package_runtime_service(machine)

    def verify_native_package_runtime_service(
        self, machine: PublishedImageMachine
    ) -> None:
        """Confirms that system activation selected the candidate runtime."""

        runtime_path = self.package_outputs["packageRuntime"]["store_path"]
        machine.succeed(
            "unit=$(systemctl show aos-activate.service -p ExecStart --value) && "
            "script=$(printf '%s' \"$unit\" | sed -n "
            "'s/.*path=\\([^ ;}}]*\\).*/\\1/p') && "
            "test -n \"$script\" && "
            f"grep -F {runtime_path} \"$script\"",
            timeout=1200,
        )

    def bind_native_guest_tools(self, machine: PublishedImageMachine) -> None:
        output_tools = {"aos": "out", "apm": "apm", "apr": "apr"}
        for tool, output in output_tools.items():
            store_path = self.package_outputs[output]["store_path"]
            executable = f"{store_path}/bin/{tool}"
            machine.succeed(
                f"test -x {executable} && nix-store --verify-path {store_path}",
                timeout=1200,
            )
            machine.native_tools[tool] = executable

        self.bind_native_package_runtime(machine)

    def stage_candidate_registry(self, machine: PublishedImageMachine) -> None:
        """Pins the guest registry to the exact candidate release in staging."""

        registry_name = self.request["registry"]
        registry_client = (
            "andyl"
            if registry_name == "andyl/main"
            else registry_name.replace("/", "-")
        )
        if re.fullmatch(r"[A-Za-z0-9_-]+", registry_client) is None:
            raise RuntimeError("request registry does not map to a safe client name")
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

        config_path = f"/etc/apm/registries.d/{registry_client}.toml"
        source = machine.succeed(f"cat {shlex.quote(config_path)}")
        config = tomllib.loads(source)
        registry = config.get("registry", {})
        signing = registry.get("signing", {})
        if (
            registry.get("name") != registry_client
            or signing.get("required") is not True
            or not isinstance(signing.get("public_key"), str)
            or not signing["public_key"].startswith(registry_client + ":Ed25519:")
        ):
            raise RuntimeError("baked registry does not carry the required trust anchor")

        lines = source.splitlines()
        url_lines = [
            index for index, line in enumerate(lines) if line.startswith("url = ")
        ]
        channel_lines = [
            index for index, line in enumerate(lines) if line.startswith("channel = ")
        ]
        tag_lines = [
            index for index, line in enumerate(lines) if line.startswith("tag = ")
        ]
        if len(url_lines) != 1 or len(channel_lines) != 1 or tag_lines:
            raise RuntimeError(
                "baked registry does not have the expected URL and channel selector"
            )

        registry_path = urllib.parse.quote(registry_name, safe="/")
        staging_url = STAGING_HUB_URL.rstrip("/") + f"/{registry_path}/"
        lines[url_lines[0]] = f"url = {json.dumps(staging_url)}"
        lines[channel_lines[0]] = f"tag = {json.dumps(self.payload['version'])}"

        overlay = self.work / f"{machine.name}-{registry_client}.toml"
        overlay.write_text("\n".join(lines) + "\n", encoding="utf-8")
        destination = f"/var/lib/apm/config/registries.d/{registry_client}.toml"
        machine.succeed("install -d -m 0755 /var/lib/apm/config/registries.d")
        machine.copy_to(overlay, destination + ".new")
        machine.succeed(
            f"set -eu; install -m 0644 {shlex.quote(destination + '.new')} "
            f"{shlex.quote(destination)}; "
            f"rm {shlex.quote(destination + '.new')}; "
            f"{machine.guest_tool('apm')} update --system "
            f"--registry {shlex.quote(registry_client)}",
            timeout=600,
        )

    def import_candidate_tools(self, machine: PublishedImageMachine) -> None:
        if self.candidate_closure is None:
            raise RuntimeError("candidate NAR closure was not validated")
        roots = sorted(
            artifact["store_path"] for artifact in self.package_outputs.values()
        )
        for store_path in roots:
            status, _, error = machine.execute(
                f"nix-store --check-validity {store_path}", timeout=120
            )
            if status == 255:
                raise RuntimeError(
                    "SSH transport failed while inspecting the guest store: " + error
                )
            if status == 1:
                self.guest_initially_absent.append(store_path)
            elif status != 0:
                raise RuntimeError(
                    f"guest store inspection failed with status {status}: {error}"
                )

        apr_path = self.package_outputs["apr"]["store_path"]
        if apr_path not in self.guest_initially_absent:
            raise RuntimeError("published apr was present before guest import")

        destination = "/var/lib/aos/qualification-candidate-tools.export"
        machine.succeed("install -d -m 0700 /var/lib/aos")
        machine.copy_to(self.candidate_export, destination)
        machine.succeed(f"nix-store --import < {destination}", timeout=3600)

        observed = set(
            machine.succeed(
                "nix-store --query --requisites " + " ".join(roots),
                timeout=1200,
            ).splitlines()
        )
        if observed != set(self.candidate_closure.infos):
            raise RuntimeError("guest candidate closure differs from isolated import")
        self._verify_guest_candidate_closure(machine)

    def _verify_guest_candidate_closure(
        self, machine: PublishedImageMachine
    ) -> None:
        if self.candidate_closure is None:
            raise RuntimeError("candidate NAR closure was not validated")
        paths = sorted(self.candidate_closure.infos)
        for offset in range(0, len(paths), 100):
            chunk = paths[offset : offset + 100]
            machine.succeed(
                "nix-store --verify-path " + " ".join(chunk), timeout=3600
            )
            statements = ["set -eu"]
            for store_path in chunk:
                statements.extend(
                    [
                        f"printf '%s\\n' '@@PATH {store_path}'",
                        f"nix-store --query --hash {store_path}",
                        f"nix-store --query --references {store_path}",
                        "printf '%s\\n' '@@END'",
                    ]
                )
            output = machine.succeed("\n".join(statements), timeout=1200)
            self._compare_guest_candidate_records(chunk, output)

    def _compare_guest_candidate_records(
        self, paths: list[str], output: str
    ) -> None:
        if self.candidate_closure is None:
            raise RuntimeError("candidate NAR closure was not validated")
        lines = output.splitlines()
        cursor = 0
        for store_path in paths:
            if cursor >= len(lines) or lines[cursor] != f"@@PATH {store_path}":
                raise RuntimeError("guest candidate identity output is malformed")
            cursor += 1
            if cursor >= len(lines):
                raise RuntimeError("guest candidate hash output is absent")
            observed_hash = NAR.canonical_sha256(lines[cursor])
            cursor += 1
            references: list[str] = []
            while cursor < len(lines) and lines[cursor] != "@@END":
                references.append(lines[cursor])
                cursor += 1
            if cursor >= len(lines):
                raise RuntimeError("guest candidate reference output is truncated")
            cursor += 1

            info = self.candidate_closure.infos[store_path]
            if observed_hash != self.candidate_closure.imported_nar_hashes[store_path]:
                raise RuntimeError(f"guest registered another NAR hash for {store_path}")
            if tuple(sorted(references)) != tuple(sorted(info.references)):
                raise RuntimeError(f"guest registered other references for {store_path}")
        if cursor != len(lines):
            raise RuntimeError("guest candidate identity output has trailing records")

    def enroll(self, machine: PublishedImageMachine) -> None:
        machine.start()
        machine.ssh(
            "test $(od -An -tu1 -j4 -N1 "
            "/sys/firmware/efi/efivars/"
            "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c) -eq 1"
        )
        machine.ssh("test -e /dev/tpm0 && test -e /sys/class/tpm/tpm0")
        if machine.expected_image_role == "candidate":
            self.bind_native_package_runtime(machine)
        self.assert_running_published_boot(machine)
        machine.ssh("PATH=/usr/bin:/usr/sbin:/bin:/sbin aos-sb-enroll", timeout=300)
        machine.reboot()
        machine.ssh(
            "test $(od -An -tu1 -j4 -N1 "
            "/sys/firmware/efi/efivars/"
            "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c) -eq 1"
        )
        self.assert_running_published_boot(machine)

    def import_fixture(
        self, machine: PublishedImageMachine, setup_module: pathlib.Path = SETUP_MODULE
    ) -> None:
        destination = "/var/lib/aos/qualification-ability-fixture.export"
        machine.ssh("install -d -m 0700 /var/lib/aos")
        machine.copy_to(FIXTURE_ARCHIVE, destination)
        machine.succeed(f"nix-store --import < {destination}", timeout=3600)
        companion_destination = "/var/lib/aos/qualification-candidate-companions.export"
        machine.copy_to(self.candidate_companion_export, companion_destination)
        machine.succeed(
            f"nix-store --import < {companion_destination}", timeout=3600
        )
        machine.succeed(
            f"{machine.guest_tool('apm')} switch "
            f"--from {setup_module} "
            f"--eval-root /run/qualification-ability-setup-{SCENARIO_ID}",
            timeout=1800,
        )
        machine.succeed("systemd-tmpfiles --create", timeout=600)
        self.verify_native_package_runtime_service(machine)

    def execute_fixture(
        self, machine: PublishedImageMachine, fixture_script: pathlib.Path = FIXTURE_SCRIPT
    ) -> dict[str, Any]:
        source = fixture_script.read_text(encoding="utf-8")
        namespace = {"__name__": "__main__", "runtime": machine}
        exec(compile(source, str(fixture_script), "exec"), namespace)
        self.fixture_namespace = namespace
        return namespace

    def build_matrix_report(self, guest_kernel_release: str) -> bytes:
        """Builds partial matrix evidence from the executed cohort probes."""

        if self.matrix_spec is None or MATRIX_COHORT is None:
            raise RuntimeError("matrix report lacks its immutable specification")
        submissions: dict[str, Any] = {}
        cohort_subjects: dict[str, Any] = {}
        cohort_evidence: dict[str, bytes] = {}
        authority_audit: dict[str, Any] | None = None
        for cohort_id, namespace in self.fixture_namespaces.items():
            cohort_input = one(
                [entry for entry in MATRIX_COHORTS if entry["id"] == cohort_id],
                f"matrix cohort {cohort_id}",
            )
            cohort_probes = namespace.get("NATIVE_ADAPTER_MATRIX_PROBES")
            subject_map = namespace.get("NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS")
            evidence_map = namespace.get("NATIVE_ADAPTER_MATRIX_COHORT_EVIDENCE")
            if evidence_map is None:
                evidence_map = namespace.get(
                    "NATIVE_ADAPTER_MATRIX_COHORT_PLAN_BUNDLES"
                )
            cohort_authority_audit = namespace.get(
                "NATIVE_ADAPTER_MATRIX_AUTHORITY_AUDIT"
            )
            authority_cells: dict[str, Any] = {}
            if cohort_authority_audit is not None:
                if not isinstance(cohort_authority_audit, dict) or not isinstance(
                    cohort_authority_audit.get("cells"), dict
                ):
                    raise RuntimeError("matrix cohort retained a malformed authority audit")
                authority_cells = cohort_authority_audit["cells"]
            if subject_map is None and isinstance(cohort_probes, dict):
                legacy_subject = namespace.get("NATIVE_ADAPTER_MATRIX_COHORT_SUBJECT")
                legacy_bundle = namespace.get("NATIVE_ADAPTER_MATRIX_COHORT_PLAN_BUNDLE")
                if len(cohort_probes) == 1:
                    cell_id = next(iter(cohort_probes))
                    subject_map = {cell_id: legacy_subject}
                    evidence_map = {cell_id: legacy_bundle}
            if (
                not isinstance(cohort_probes, dict)
                or not isinstance(subject_map, dict)
                or not isinstance(evidence_map, dict)
                or any(not isinstance(value, bytes) for value in evidence_map.values())
                or set(cohort_probes) & set(authority_cells)
            ):
                raise RuntimeError(
                    f"matrix cohort {cohort_id!r} did not retain exact production evidence"
                )
            if set(cohort_probes) | set(authority_cells) != set(
                cohort_input["qualifiedCells"]
            ):
                raise RuntimeError(
                    f"matrix cohort {cohort_id!r} differs from its declared cells"
                )
            if (
                set(submissions) & set(cohort_probes)
                or set(cohort_subjects) & set(subject_map)
                or set(cohort_evidence) & set(evidence_map)
            ):
                raise RuntimeError("matrix production cohorts repeat a cell identity")
            submissions.update(cohort_probes)
            cohort_subjects.update(subject_map)
            cohort_evidence.update(evidence_map)
            if cohort_authority_audit is not None:
                if authority_audit is not None or not isinstance(
                    cohort_authority_audit, dict
                ):
                    raise RuntimeError("matrix cohorts repeat or malformed authority audit")
                authority_audit = cohort_authority_audit

        if authority_audit is None:
            raise RuntimeError("matrix cohort did not retain its authority audit")

        qemu_output = IMAGE.run([IMAGE.QEMU, "--version"]).stdout.splitlines()[0]
        qemu_match = re.search(r"version ([0-9][A-Za-z0-9.+_-]*)", qemu_output)
        if qemu_match is None:
            raise RuntimeError("QEMU returned an unsupported version identity")
        spec_digest = raw_digest(self.matrix_spec)
        scenario_registry_digest = raw_digest(read_json(SCENARIO_REGISTRY))
        environment = {
            "schema_version": "aos.release.native-adapter-matrix-environment/v1",
            "status": "production",
            "platform": PLATFORM,
            "spec_digest": spec_digest,
            "scenario_registry_digest": scenario_registry_digest,
            "candidate_subjects_digest": self.case["subjects_digest"],
            "predecessor_manifest_digest": self.case["predecessor"][
                "manifest_digest"
            ],
            "cohort": "host-resource-provider-replacement-v3",
            "qemu": {
                "name": "qemu",
                "version": "qemu-" + qemu_match.group(1),
                "digest": sha256_file(pathlib.Path(IMAGE.QEMU)),
            },
            "firmware": {
                "name": "ovmf",
                "version": "edk2-ovmf",
                "digest": raw_digest(
                    {
                        "code": sha256_file(pathlib.Path(IMAGE.FIRMWARE_CODE)),
                        "variables": sha256_file(
                            pathlib.Path(IMAGE.FIRMWARE_VARS)
                        ),
                    }
                ),
            },
            "guest_kernel": {
                "name": "guest-kernel",
                "version": guest_kernel_release,
                "digest": self.uki_artifact["sha256"],
            },
            "fault_injection_tool": {
                "name": "native-adapter-cohort-faults",
                "version": "cohort-v2",
                "digest": sha256_file(FIXTURE_ARCHIVE),
            },
            "harness": {
                "name": "native-adapter-host-resource-cohort",
                "version": "cohort-v2",
                "digest": sha256_file(FIXTURE_ARCHIVE),
            },
        }
        environment_digest = raw_digest(environment)
        cells, postcondition_count = MATRIX_COHORT.build_cells(
            self.matrix_spec,
            submissions,
            MATRIX_QUALIFIED_CELLS,
            cohort_subjects,
            cohort_evidence,
            self.case["subjects_digest"],
            environment_digest,
            authority_audit,
        )

        finished = time.time()
        report = {
            "schema_version": "aos.release.qualification-scenario-report/v1",
            "registry": self.request["registry"],
            "release_id": self.request["release_id"],
            "staging_receipt_digest": self.request["staging_receipt_digest"],
            "manifest_digest": self.request["manifest_digest"],
            "case_digest": digest("aos.release.qualification-case/v2", self.case),
            "started_at": self.started_at,
            "finished_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)
            ),
            "observed_seconds": int(finished - self.started),
            "checks": {
                check: {"passed": True, "detail": CHECK_DETAILS[check]}
                for check in self.case["checks"]
                if not check.startswith("native-adapter-matrix-v1-sha256-")
            },
            "operations": {
                "matrix_cells_reported": len(cells),
                "matrix_postconditions_reported": postcondition_count,
            },
            "environment": environment,
            "native_adapter_matrix": {
                "schema_version": "aos.release.native-adapter-matrix-observation/v1",
                "spec": self.matrix_spec,
                "spec_digest": spec_digest,
                "environment": environment,
                "cells": cells,
            },
        }
        return canonical(report)

    def build_report(self, guest_kernel_release: str) -> bytes:
        if self.machine is None or self.candidate_closure is None:
            raise RuntimeError("ability scenario has no executed published guest")
        machine = self.machine
        if self.matrix_spec is not None:
            return self.build_matrix_report(guest_kernel_release)

        rollout_case = SCENARIO_ID == "ability-native-image-rollout"
        if rollout_case:
            branch_evidence = {
                cohort_id: namespace.get("ROLLOUT_BRANCH_EVIDENCE")
                for cohort_id, namespace in self.fixture_namespaces.items()
            }
            if (
                set(branch_evidence) != {"healthy", "fallback"}
                or branch_evidence["healthy"]
                != {
                    "branch": "healthy",
                    "outcome": "candidate-healthy",
                    "retired": True,
                }
                or branch_evidence["fallback"]
                != {
                    "branch": "fallback",
                    "outcome": "predecessor-fallback",
                    "retired": False,
                }
                or not self.rollout_boot_ids["candidate"]
                or not self.rollout_boot_ids["predecessor"]
                or self.handoff_boot_ids != self.rollout_boot_ids["candidate"]
                or self.boot_ids
                != self.rollout_boot_ids["candidate"]
                | self.rollout_boot_ids["predecessor"]
            ):
                raise RuntimeError("published image rollout branch evidence is incomplete")
        else:
            expected_boots = (
                1 + machine.counts.reboot_cycles + machine.hard_power_cycles
            )
            if (
                self.boot_ids != self.handoff_boot_ids
                or self.boot_assertions != len(self.boot_ids)
                or self.handoff_assertions != len(self.handoff_boot_ids)
                or len(self.boot_ids) != expected_boots
            ):
                raise RuntimeError("unique boot and initrd handoff coverage is incomplete")

        details = {
            check: {"passed": True, "detail": CHECK_DETAILS[check]}
            for check in self.case["checks"]
        }
        qemu_version = IMAGE.run([IMAGE.QEMU, "--version"]).stdout.splitlines()[0]
        environment = {
            "schema_version": "aos.release.ability-execution-environment/v1",
            "platform": PLATFORM,
            "backend": {
                "kind": "qemu",
                "machine": "q35",
                "accelerator": "kvm",
                "version": qemu_version,
            },
            "boot": {
                "kind": "systemd-boot-uki",
                "qcow2_artifact": self.qcow2_artifact["id"],
                "uki_artifact": self.uki_artifact["id"],
                "assembly_artifact": self.assembly_artifact["id"],
                "metadata_artifact": self.metadata_artifact["id"],
                "assertions": (
                    len(self.rollout_boot_ids["candidate"])
                    if rollout_case
                    else self.boot_assertions
                ),
            },
            "published_tools": {
                name: artifact["id"] for name, artifact in self.package_outputs.items()
            },
            "candidate_nar_import": {
                "closure_paths": len(self.candidate_closure.infos),
                "isolated_store_initially_absent": sorted(
                    self.candidate_closure.initially_absent
                ),
                "guest_initially_absent": sorted(self.guest_initially_absent),
            },
            "fixture": {
                "kind": "candidate-runtime-bound-reference-provider-closure",
                "contract_digest": FIXTURE_CONTRACT,
                "candidate_runtime": self.package_outputs["packageRuntime"]["store_path"],
                "differs_from_executor": all(
                    entry["originalRuntime"]
                    != self.package_outputs["packageRuntime"]["store_path"]
                    for entry in RUNTIME_COMPANIONS
                ),
                "companions": sorted(self.candidate_companions.values()),
            },
            "guest_kernel_release": guest_kernel_release,
            "host_kernel_release": os.uname().release,
        }
        if rollout_case:
            environment["boot"]["predecessor"] = {
                "release_id": self.case["predecessor"]["release_id"],
                "manifest_digest": self.case["predecessor"]["manifest_digest"],
                "qcow2_artifact": self.predecessor_image["qcow2_artifact"]["id"],
                "uki_artifact": self.predecessor_image["uki_artifact"]["id"],
                "assembly_artifact": self.predecessor_image["assembly_artifact"]["id"],
                "metadata_artifact": self.predecessor_image["metadata_artifact"]["id"],
                "assertions": len(self.rollout_boot_ids["predecessor"]),
            }
            environment["production_rollout"] = {
                "schema_version": "aos.release.native-image-rollout-environment/v1",
                "status": "production",
                "staging_hub_origin": STAGING_HUB_URL,
                "registry": self.request["registry"],
                "candidate_version": self.payload["version"],
                "branches": {
                    cohort_id: namespace["ROLLOUT_BRANCH_EVIDENCE"]
                    for cohort_id, namespace in sorted(self.fixture_namespaces.items())
                },
            }
        finished = time.time()
        report = {
            "schema_version": "aos.release.qualification-scenario-report/v1",
            "registry": self.request["registry"],
            "release_id": self.request["release_id"],
            "staging_receipt_digest": self.request["staging_receipt_digest"],
            "manifest_digest": self.request["manifest_digest"],
            "case_digest": digest("aos.release.qualification-case/v2", self.case),
            "started_at": self.started_at,
            "finished_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)
            ),
            "observed_seconds": int(finished - self.started),
            "checks": details,
            "operations": {
                "published_boot_assertions": self.boot_assertions,
                "initrd_handoff_assertions": self.handoff_assertions,
                "warm_reboots": self.total_warm_reboots,
                "hard_power_cycles": self.total_hard_power_cycles,
                "metadata_free_reboots": self.total_metadata_free_reboots,
                "rollout_branches": len(self.fixture_namespaces) if rollout_case else 0,
            },
            "environment": environment,
        }
        return canonical(report)

    def run(self) -> None:
        guest_kernel_release: str | None = None
        try:
            self.validate_inputs()
            if self.matrix_spec is not None:
                cohorts = MATRIX_COHORTS
            elif SCENARIO_ID == "ability-native-image-rollout":
                cohorts = [
                    {
                        "id": branch,
                        "script": str(FIXTURE_SCRIPT),
                        "setup": str(SETUP_MODULE),
                        "qualifiedCells": [],
                    }
                    for branch in ("healthy", "fallback")
                ]
            else:
                cohorts = [
                    {
                        "id": "ability",
                        "script": str(FIXTURE_SCRIPT),
                        "setup": str(SETUP_MODULE),
                        "qualifiedCells": [],
                    }
                ]
            if not isinstance(cohorts, list) or not cohorts:
                raise RuntimeError("matrix qualification lacks a production cohort")
            qualified_cells = [
                cell_id
                for cohort in cohorts
                if isinstance(cohort, dict)
                for cell_id in cohort.get("qualifiedCells", [])
            ]
            if (
                qualified_cells != MATRIX_QUALIFIED_CELLS
                or len(set(qualified_cells)) != len(qualified_cells)
            ):
                raise RuntimeError(
                    "matrix cohort inputs differ from the exact qualification scope"
                )

            for index, cohort in enumerate(cohorts):
                if (
                    not isinstance(cohort, dict)
                    or set(cohort) != {"id", "script", "setup", "qualifiedCells"}
                    or not isinstance(cohort["id"], str)
                    or not cohort["id"]
                    or not isinstance(cohort["qualifiedCells"], list)
                ):
                    raise RuntimeError("matrix production cohort input is malformed")

                rollout_case = SCENARIO_ID == "ability-native-image-rollout"
                image_path = (
                    self.predecessor_image["qcow2_path"]
                    if rollout_case
                    else self.qcow2_path
                )
                machine = PublishedImageMachine(
                    f"ability-{cohort['id']}-{index}",
                    image_path,
                    self.host_config,
                    self.key,
                    IMAGE.Counts(),
                    scenario=self,
                )
                if rollout_case:
                    machine.expect_published_image("predecessor")
                    machine.rollout_branch = cohort["id"]
                self.machine = machine
                try:
                    self.enroll(machine)
                    self.import_candidate_tools(machine)
                    self.bind_native_guest_tools(machine)
                    self.import_fixture(machine, pathlib.Path(cohort["setup"]))
                    namespace = self.execute_fixture(
                        machine, pathlib.Path(cohort["script"])
                    )
                    self.fixture_namespaces[cohort["id"]] = namespace
                    self.assert_running_published_boot(machine)
                    observed_kernel = machine.ssh("uname -r").strip()
                    if rollout_case and cohort["id"] == "fallback":
                        pass
                    elif guest_kernel_release is None:
                        guest_kernel_release = observed_kernel
                    elif guest_kernel_release != observed_kernel:
                        raise RuntimeError(
                            "matrix cohorts observed different guest kernels"
                        )
                    self.total_warm_reboots += machine.counts.reboot_cycles
                    self.total_hard_power_cycles += machine.hard_power_cycles
                    self.total_metadata_free_reboots += machine.metadata_free_reboots
                finally:
                    machine.stop_processes()
            if self.used_candidate_companions != set(self.candidate_companions):
                raise RuntimeError(
                    "production cohorts did not exercise every candidate runtime companion"
                )
        finally:
            if self.machine is not None and self.machine.qemu is not None:
                # Cleanup exceptions propagate, so an unclosed VM cannot leave
                # a successful report behind.
                self.machine.stop_processes()
        if guest_kernel_release is None:
            raise RuntimeError("ability scenario completed without a report")
        REPORT.write_bytes(self.build_report(guest_kernel_release))


CHECK_DETAILS = {
    "connected-generic-markers-before-selected-interruption": (
        "The production ability adapter emitted the existing generic assertion, event, "
        "coverage, and lifecycle markers before the selected interruption was released."
    ),
    "retained-boundary-selection-and-digest-bound-adapter-acknowledgement": (
        "The protected controller retained the exact operation boundary, fault selection, "
        "canonical event digest, and matching production-adapter acknowledgement."
    ),
    "reproduced-reconciliation-through-production-executor": (
        "A second selected effect-return boundary survived hard power loss and reopened as "
        "the same production reconciliation opportunity before completing."
    ),
    "inspector-explains-retained-crucible-recovery-finding": (
        "The AOS inspector joined the retained plan and operation to its interrupted effect "
        "and successful reconciliation timeline."
    ),
    "disabled-production-executor-has-no-crucible-closure": (
        "The same production executor configuration without the opt-in profile retained no "
        "ability adapter or Crucible guest emitter in its realized closure."
    ),
    "native-adapter-matrix-v1-sha256-595ccc8e10dbc95631f6b3155b1502e11bcf0dd2f70e988e6cd77af482bd224b": (
        "The closed native-adapter matrix bound every durability and authority "
        "cell to the exact adapter interface name, ABI, and descriptor."
    ),
    "authenticated-package-policy-and-operator-authority": (
        "The published AOS activation engine admitted only authenticated "
        "reference packages and explicit operator authority."
    ),
    "exact-interface-binding-effect-plan-and-artifact-identities": (
        "Native plans retained exact interface, provider, handler, plan, and "
        "artifact identities inside the published guest."
    ),
    "consumer-scoped-access-and-independent-service-observation": (
        "Independent HTTP observations proved each consumer-scoped service result."
    ),
    "aggregate-publication-reload-and-unchanged-input-no-op": (
        "Aggregate updates reloaded their owning services and unchanged desired "
        "input produced a verified no-op."
    ),
    "post-publication-reload-failure-retains-new-configuration-and-old-or-unknown-consumer-state": (
        "A forced reload failure retained the published configuration and "
        "recorded the consumer as old or unknown."
    ),
    "rollback-revalidates-and-retains-transaction-evidence": (
        "Rollback revalidated authority, restored observations, and retained "
        "canonical transaction evidence."
    ),
    "advisory-exact-candidate-staging-without-selection-or-reboot": (
        "Advisory image staging retained the exact candidate generation without "
        "changing boot selection, creating rollout authority, or rebooting."
    ),
    "authenticated-rollout-plan-and-exact-native-request": (
        "The authenticated rollout package lowered one exact image request into "
        "the complete built-in native lifecycle graph."
    ),
    "booted-candidate-health-hook-before-config-generation-commit": (
        "The candidate image's distinct health hook ran while the configuration "
        "profile still named its prior committed generation."
    ),
    "healthy-provider-and-journal-evidence-before-physical-commit": (
        "Candidate health and the successful native journal were durable before "
        "boot commit finalized firmware and image state."
    ),
    "failed-health-mark-reboot-and-predecessor-retention": (
        "Failed health was durable before reboot, and the transaction retained "
        "the predecessor only after it booted."
    ),
    "exact-generation-roots-and-uki-retention": (
        "Both exact generation roots and signed UKIs remained retained across "
        "the healthy and fallback branches."
    ),
    "post-expiry-rollout-root-retirement": (
        "A separately admitted transition removed rollout-specific roots only "
        "after the retention deadline and physical finalization."
    ),
    "stage-specific-manager-and-foreground-contracts-with-unqualified-container-cells": (
        "Host and container execution strategies selected their exact manager or foreground "
        "contracts, while unqualified stage cells remained absent from the support matrix."
    ),
    "typed-opaque-tls-credential-version-delivery-and-validation-binding": (
        "An opaque TLS content version selected a protected credential view, and native "
        "nginx validation authenticated its exact resource, path, version, and content digest."
    ),
    "independent-served-certificate-observation-matches-declared-version": (
        "Independent TLS clients observed the certificate fingerprint from the credential "
        "bundle whose declared opaque version was delivered to each nginx instance."
    ),
    "missing-credential-and-invalid-certificate-reject-with-live-target-preserved": (
        "A missing credential source and malformed replacement certificate both rejected "
        "activation while the previously selected service remained independently reachable."
    ),
    "tls-private-key-sentinel-absent-from-durable-and-rendered-records": (
        "A private-key body sentinel was absent from retained plans, journals, terminal "
        "records, native nginx records, and rendered nginx configuration."
    ),
    "credential-renewal-reloads-and-serves-new-version": (
        "TLS credential renewal delivered a distinct opaque version and the reloaded nginx "
        "service presented the renewed certificate to an independent client."
    ),
    "selected-tls-generation-and-credential-view-survive-gc-and-reboot": (
        "Garbage collection followed by a metadata-free reboot retained the selected TLS "
        "generation, its protected credential view, and its independently observed certificate."
    ),
    "tls-disable-and-cleartext-transition-release-credential-views-after-service-change": (
        "Disabling one TLS owner stopped its service and removed its view, while removing TLS "
        "from a retained owner closed its TLS listener, served cleartext, and released its view."
    ),
    "endpoint-and-ingress-policy-precede-service-readiness-and-release-in-reverse-order": (
        "Authenticated transition edges placed each loopback endpoint before its ingress policy, "
        "placed policy before service convergence and readiness, and reversed that order on removal."
    ),
    "authenticated-nginx-storage-ownership-lifetime-and-service-ordering": (
        "Each nginx instance consumed authenticated root-owned runtime, state, and log paths; "
        "storage preparation preceded validation, service stop preceded release, instance "
        "runtime storage was removed, and persistent state and logs were retained."
    ),
    "authenticated-k3s-bootstrap-and-provider-authority": (
        "The published guest bootstrapped K3s only from authenticated packages "
        "and provider authority."
    ),
    "exact-service-and-kubernetes-object-resource-mapping": (
        "Service and Kubernetes-object effects matched their exact native resource map."
    ),
    "consumer-observed-kubernetes-readiness": (
        "Kubernetes API observations independently proved the declared consumer readiness."
    ),
    "forged-mapping-grant-and-namespace-rejected-without-mutation": (
        "Forged mapping, grant, and namespace inputs were rejected without "
        "changing the running cluster."
    ),
    "object-update-removal-and-retained-owner-evidence": (
        "Object updates and removals converged while retaining exact owner evidence."
    ),
    "bounded-bootstrap-planning-rejections-before-effect-construction": (
        "Missing Available bootstrap authority and cyclic K3s provider lineage were "
        "rejected with bounded exact planning traces before effect construction."
    ),
    "authenticated-provider-bindings-and-exact-handler-artifacts": (
        "The published guest admitted only authenticated PostgreSQL provider "
        "bindings and release-bound handler artifacts."
    ),
    "exact-seven-operation-ten-edge-provisioning-graph": (
        "PostgreSQL provisioning executed its exact seven-operation, ten-edge "
        "graph with required-success ordering."
    ),
    "runtime-output-data-flow-and-schema-valid-observations": (
        "Runtime outputs flowed through typed resource state whose observations "
        "matched every declared schema."
    ),
    "loopback-sql-readiness-and-enforced-non-loopback-denial": (
        "Independent SQL probes passed through IPv4 and IPv6 loopback brokers "
        "while non-loopback traffic remained denied."
    ),
    "stopped-divergent-and-child-drift-reconciliation": (
        "Stopped, divergent, and child-resource drift was authenticated and "
        "reconciled before PostgreSQL effects resumed."
    ),
    "exact-six-operation-five-edge-teardown-and-persistent-retention": (
        "Teardown executed its exact six-operation, five-edge graph and retained "
        "the persistent PostgreSQL storage identity."
    ),
    "exact-boot-initrd-artifact-and-static-stage-handoff-contract": (
        "The exact published QCOW2 and slot-A UKI booted with its assembly-bound "
        "initrd, static stage contracts, initrd selection, and durable host receipt."
    ),
    "process-loss-after-external-effect-reconciles-before-retry": (
        "Process loss after an external effect reconciled the retained operation before any retry."
    ),
    "power-loss-after-external-effect-reconciles-after-boot": (
        "A SIGKILL power cut preserved the published disk and reconciled the "
        "partial effect after a fresh boot."
    ),
    "fresh-receiving-authority-and-resource-incarnations": (
        "The fresh boot reacquired receiving authority and new resource incarnations."
    ),
    "retained-plan-journal-and-independent-service-observation": (
        "Plan and journal bytes survived recovery, cleanup, and GC while an "
        "independent service observation passed."
    ),
    "gc-after-crashed-unlocked-partial-activation-retains-recovery-set": (
        "Unlocked collection during a crashed partial activation retained the "
        "complete recovery set and the same activation resumed afterward."
    ),
}


if __name__ == "__main__":
    Scenario().run()
