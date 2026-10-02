"""Exercises authenticated physical image transitions through native user APIs.

The Nix fixture supplies immutable candidate artifacts and explicit site hooks.
This harness never edits image indices, native receipts, or activation journals.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
import textwrap
from typing import Any


IMAGE_STATE = "/var/lib/profiles/image/state.json"
IMAGE_RECEIPT = "/var/lib/profiles/image/active-native-rollout.json"
BOOT_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def read_json(path: str) -> dict[str, Any]:
    """Reads a bounded guest document through the retained inspection toolkit."""
    document = runtime.succeed(f"{COREUTILS}/head --bytes=1048577 {shlex.quote(path)}")
    if len(document.encode()) > 1048576:
        raise RuntimeError("image acceptance document exceeds its boundary")
    value = json.loads(document)
    if not isinstance(value, dict):
        raise RuntimeError("image acceptance expected a document object")
    return value


def image_state() -> dict[str, Any]:
    """Requires the native image index, never a synthesized physical state."""
    state = read_json(IMAGE_STATE)
    if state.get("schema") != "aos.image-generation-state/v1":
        raise RuntimeError("unexpected native image index")
    return state


def generation(state: dict[str, Any], number: int) -> dict[str, Any]:
    """Selects one exact retained image generation."""
    matches = [record for record in state["generations"] if record["number"] == number]
    if len(matches) != 1:
        raise RuntimeError("image generation is absent or repeated")
    return matches[0]


def assert_identity(record: dict[str, Any]) -> None:
    """Checks live boot selection against immutable retained image metadata."""
    actual = runtime.succeed(f"{COREUTILS}/readlink /run/current-system").strip()
    if actual != record["toplevel"]:
        raise RuntimeError("live boot differs from the retained native image")
    for name, expected in (
        ("native-executor-ref", record["native_executor_ref"]),
        ("boot-artifact-contract", record["boot_artifact_contract"]),
        ("state-version", record["state_version"]),
        ("evaluation-descriptor", record["evaluation_descriptor"]),
    ):
        actual = runtime.succeed(f"{COREUTILS}/cat {shlex.quote(record['toplevel'] + '/meta/' + name)}").strip()
        if actual != expected:
            raise RuntimeError(f"immutable native image differs at {name}")
    library = read_json(record["toplevel"] + "/meta/module-library.json")
    if library != record["module_library"]:
        raise RuntimeError("image native library identity differs")
    evidence = record["boot_provider_state"]["evidence"]
    cmdline = runtime.succeed(f"{COREUTILS}/cat /proc/cmdline")
    if f"systemd.verity_root_data=/dev/disk/by-partlabel/root-{evidence['slot'].lower()}" not in cmdline.split():
        raise RuntimeError("actual boot is outside the retained physical slot")


def secure_boot() -> None:
    """Enrolls explicit fixture keys and proves firmware enforcement after boot."""
    def variable(name: str) -> int:
        path = f"/sys/firmware/efi/efivars/{name}-{BOOT_GUID}"
        return int(runtime.succeed(f"{OD} -An -tu1 -j4 -N1 {shlex.quote(path)}").strip())

    if variable("SetupMode") == 1:
        for name in ("db", "KEK", "PK"):
            runtime.succeed(f"PATH={UTIL_LINUX}:$PATH {EFI_UPDATEVAR} -f {shlex.quote(SECURE_BOOT_KEYS + '/' + name + '.auth')} {name}")
        runtime.reboot(timeout=600)
    if variable("SecureBoot") != 1:
        raise RuntimeError("physical fixture did not enable Secure Boot")


def publish_candidate() -> None:
    """Publishes the exact measured candidate through a signed release registry."""
    runtime.succeed(textwrap.dedent(f"""
        set -eu
        export HOME=/tmp/native-image-release
        export GIT_AUTHOR_NAME=Fixture GIT_AUTHOR_EMAIL=fixture@example.test
        export GIT_COMMITTER_NAME=Fixture GIT_COMMITTER_EMAIL=fixture@example.test
        export NIX_REMOTE=""
        export NIX_CONF_DIR=/tmp/native-image-nix-conf
        export PATH={GIT_BIN}:{NIX_BIN}:$PATH
        mkdir -p "$HOME" "$NIX_CONF_DIR"
        printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' > "$NIX_CONF_DIR/nix.conf"
        keygen=$({APR} keys generate release --registry native-image 2>&1)
        public=$(printf '%s\\n' "$keygen" | {JQ} -Rr 'select(startswith("Public key:")) | split(" ") | last')
        test -n "$public"
        key="$HOME/.config/apm/keys/native-image-release.key"
        {APR} create native-image --trust-key "$public" --trust-key-id release --key "$key"
        registry="$HOME/.local/share/apm/registries/native-image"
        mkdir -p "$HOME/.config/apm/registries.d"
        printf '[registry]\\nname = "native-image"\\nurl = "file://%s"\\n\\n[registry.signing_keys]\\nrelease = "%s"\\n' "$registry" "$key" > "$HOME/.config/apm/registries.d/native-image.toml"
        {APR} --json publish {shlex.quote(CANDIDATE_TOP)} --name aos \\
          --version 9999.0.0-image-rollback --description 'Native physical image acceptance' \\
          --license Apache-2.0 --maintainer fixture --sysroot \\
          --image-payload {shlex.quote(CANDIDATE_IMAGE)} --image-disk {shlex.quote(CANDIDATE_IMAGE_DISK)} \\
          --image-info {shlex.quote(CANDIDATE_IMAGE_INFO)} --image-format raw \\
          --image-contract-schema aos.image.metadata/v1 \\
          --no-ca --registry native-image --key-id release --no-commit > /tmp/native-image-publication.json
        {GIT_BIN}/git -C "$registry" add -A
        {GIT_BIN}/git -C "$registry" commit -m 'release: native physical image fixture'
        {GIT_BIN}/git -C "$registry" tag v1.0.0
        {APM} registry --system add "file://$registry" --name native-image --tag 1.0.0 --trust-key "$public" --no-clone
        {APM} update --system --registry native-image
    """), timeout=1800)
    publication = read_json("/tmp/native-image-publication.json")
    images = publication["images"]
    if len(images) != 1:
        raise RuntimeError("signed publication lacks one exact physical image")
    contract = images[0]["delivery"]["artifact_contract"]
    if contract["schema"] != "aos.image.metadata/v1" or contract["document"]["store_path"] != CANDIDATE_IMAGE_INFO:
        raise RuntimeError("signed publication names another provider contract")
    document = contract["document"]
    actual_digest = runtime.succeed(f"{SHA256SUM} {shlex.quote(CANDIDATE_IMAGE_INFO)}").split()[0]
    actual_size = int(runtime.succeed(f"{COREUTILS}/stat -c %s {shlex.quote(CANDIDATE_IMAGE_INFO)}").strip())
    if actual_digest != document["sha256"] or actual_size != document["byte_size"]:
        raise RuntimeError("published provider document differs from its exact authenticated bytes")
    metadata = read_json(CANDIDATE_IMAGE_INFO)
    if metadata["schema_version"] != contract["schema"]:
        raise RuntimeError("physical metadata differs from its declared contract")
    for slot in ("a", "b"):
        normal = metadata["efi"]["normal_" + slot]
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", normal["expected_ready_pcr11"]):
            raise RuntimeError("signed provider contract lacks both measured physical slots")


def invoke_reboot(arguments: str, label: str) -> None:
    """Runs the ordinary native CLI and requires a real subsequent boot."""
    before = runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip()
    runtime.succeed(f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(label)} --property=Type=exec {APM} {arguments}")
    runtime.wait_until_succeeds(f"test \"$({COREUTILS}/cat /proc/sys/kernel/random/boot_id)\" != {shlex.quote(before)}", timeout=1800)
    runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet aos-image-boot-commit.service", timeout=900)
    runtime.wait_until_succeeds(f"{JQ} -e '.pending == null and .active_rollout == null' {IMAGE_STATE}", timeout=900)


def counted_boot_fallback(original: dict[str, Any]) -> None:
    """Exhausts three real candidate boots before native activation or health."""
    runtime.succeed(f"printf '%s\\n' {shlex.quote(CANDIDATE_TOP)} > /var/lib/aos-test/blocked-image-toplevel")
    runtime.succeed(f"{SYSTEMD_RUN} --quiet --unit=native-image-counted-failure --property=Type=exec {APM} upgrade --system --yes --drain --reboot")
    boot_ids = set()
    for left, done in ((2, 1), (1, 2), (0, 3)):
        runtime.wait_until_succeeds(f"test \"$({COREUTILS}/readlink /run/current-system)\" = {shlex.quote(CANDIDATE_TOP)}", timeout=1800)
        runtime.wait_until_succeeds(f"{SYSTEMCTL} is-failed --quiet aos-activate.service", timeout=900)
        state = image_state()
        candidate = generation(state, state["pending"])
        stem = candidate["boot_provider_state"]["evidence"]["installed-entry"].rsplit("/", 1)[1].split("+", 1)[0]
        actual_entry = f"/boot/EFI/Linux/{stem}+{left}-{done}.efi"
        runtime.succeed(f"test -f {shlex.quote(actual_entry)}")
        boot_id = runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip()
        if boot_id in boot_ids:
            raise RuntimeError("counted failure did not perform a new physical boot")
        boot_ids.add(boot_id)
        if runtime.execute(f"test -f /var/lib/aos-test/health-observations && {COREUTILS}/cat /var/lib/aos-test/health-observations")[0] == 0:
            observations = runtime.succeed(f"{COREUTILS}/cat /var/lib/aos-test/health-observations")
            if CANDIDATE_TOP in observations:
                raise RuntimeError("blocked candidate unexpectedly ran site health")
        runtime.reboot(timeout=600)
    runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet aos-image-boot-commit.service", timeout=900)
    runtime.wait_until_succeeds(f"{JQ} -e '.running == {original['number']} and .pending == null and .active_rollout == null and .last_rollout.status == \"boot_failed\"' {IMAGE_STATE}", timeout=900)
    assert_identity(original)
    runtime.succeed(f"{COREUTILS}/rm /var/lib/aos-test/blocked-image-toplevel")


def assert_candidate(record: dict[str, Any]) -> None:
    """Requires exact authenticated candidate identity and installed payload bytes."""
    if record["toplevel"] != CANDIDATE_TOP or record["native_executor_ref"] != CANDIDATE_EXECUTOR or record["boot_artifact_contract"] != CANDIDATE_BOOT_CONTRACT:
        raise RuntimeError("physical candidate differs from its signed immutable fixture")
    evidence = record["boot_provider_state"]["evidence"]
    source = "/boot/" + evidence["uki-source-path"]
    actual = runtime.succeed(f"{SHA256SUM} {shlex.quote(source)}").split()[0]
    if actual != evidence["uki-sha256"].removeprefix("sha256:"):
        raise RuntimeError("installed UKI payload differs from its authenticated receipt")
    metadata = read_json(CANDIDATE_IMAGE_INFO)
    expected = metadata["efi"]["normal_" + evidence["slot"].lower()]["artifact"]
    if actual != expected["sha256"].removeprefix("sha256:"):
        raise RuntimeError("installed UKI differs from the independently published slot bytes")
    actual_size = int(runtime.succeed(f"{COREUTILS}/stat -c %s {shlex.quote(source)}").strip())
    if actual_size != expected["size_bytes"]:
        raise RuntimeError("installed UKI length differs from the published slot bytes")


def retire(request: dict[str, Any]) -> None:
    """Submits explicit expired lease retirement through ordinary operator source."""
    deadline = request["retention-expires-at-millis"] // 1000 + 1
    runtime.succeed(f"{DATE} -s @{deadline}")
    worktree = "/var/lib/aos-test/native-image-retirement"
    runtime.succeed(f"{COREUTILS}/mkdir -p {worktree}; {COREUTILS}/chmod 0700 {worktree}")
    source = "{ ... }: { aos.imageRollout.retiredRequests = [ (builtins.fromJSON " + json.dumps(json.dumps(request)) + ") ]; }"
    encoded = base64.b64encode(source.encode()).decode()
    runtime.succeed(f"printf %s {shlex.quote(encoded)} | {COREUTILS}/base64 -d > {worktree}/configuration.nix")
    runtime.succeed(f"{APM} switch --worktree {worktree} --eval-root /var/lib/aos-test/native-image-retirement-eval", timeout=1800)


def run() -> None:
    """Checks executor handoff, real rollback, health fallback, and slot retirement."""
    runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet aos-image-boot-commit.service", timeout=600)
    secure_boot()
    original = generation(image_state(), image_state()["running"])
    assert_identity(original)
    publish_candidate()
    counted_boot_fallback(original)

    invoke_reboot("upgrade --system --yes --drain --reboot", "native-image-upgrade")
    selected = image_state()
    candidate = generation(selected, selected["running"])
    assert_candidate(candidate)
    assert_identity(candidate)
    if candidate["native_executor_ref"] == original["native_executor_ref"]:
        raise RuntimeError("qualified transition did not exercise executor ownership handoff")
    before = image_state()
    runtime.succeed(f"{SYSTEMCTL} restart aos-image-boot-commit.service", timeout=300)
    if image_state() != before:
        raise RuntimeError("native boot-commit replay changed settled image authority")

    invoke_reboot(f"rollback --system --image --generation {original['number']} --drain --reboot", "native-image-rollback")
    assert_identity(generation(image_state(), image_state()["running"]))
    if image_state()["running"] != original["number"]:
        raise RuntimeError("native rollback did not restore the retained predecessor")

    runtime.succeed(f"printf '%s\\n' {shlex.quote(candidate['toplevel'])} > /var/lib/aos-test/unhealthy-image-toplevel; {COREUTILS}/touch /var/lib/aos-test/rollout-health-fail")
    invoke_reboot("upgrade --system --yes --drain --reboot", "native-image-health-failure")
    runtime.wait_until_succeeds(f"{JQ} -e '.running == {original['number']} and .pending == null and .active_rollout == null' {IMAGE_STATE}", timeout=1800)
    assert_identity(original)
    receipt = read_json(IMAGE_RECEIPT)
    retire(receipt["input"]["rollout"])
    retired = generation(image_state(), candidate["number"])
    if retired["boot_provider_state"]["evidence"].get("retired") is not True:
        raise RuntimeError("admitted expired retirement did not release the inactive slot")
    if image_state()["running"] != original["number"]:
        raise RuntimeError("retirement changed the live image")
    if retired["module_library"] != candidate["module_library"] or retired["native_executor_ref"] != candidate["native_executor_ref"]:
        raise RuntimeError("physical retirement discarded historical native identity")
