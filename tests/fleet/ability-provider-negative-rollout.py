"""Runs one real A/B image rollout dependency and foreign-map flight.

The surrounding Nix cohort supplies a signed alternate image and the ordinary
published-image qualification runtime. Each cohort VM handles both negative
cells for one method so rebooting and fallback cannot leak across methods.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
import textwrap
from typing import Any


IMAGE_STATE = "/var/lib/profiles/image/state.json"
SECURE_BOOT_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def image_state() -> dict[str, Any]:
    """Loads the physical image-generation state."""

    return json.loads(runtime.succeed(f"{COREUTILS}/cat {IMAGE_STATE}"))


def generation(state: dict[str, Any], number: int) -> dict[str, Any]:
    """Returns one exact image generation."""

    matches = [entry for entry in state["generations"] if entry["number"] == number]
    if len(matches) != 1:
        raise RuntimeError(f"image generation {number} is absent or repeated")
    return matches[0]


def efivar_byte(name: str) -> int:
    """Reads one authenticated UEFI variable byte."""

    path = f"/sys/firmware/efi/efivars/{name}-{SECURE_BOOT_GUID}"
    return int(runtime.succeed(f"{OD} -An -tu1 -j4 -N1 {shlex.quote(path)}").strip())


def bootstrap_rollout_host() -> None:
    """Enables test Secure Boot keys and checks the initial image authority."""

    runtime.wait_until_succeeds(
        f"{SYSTEMCTL} is-active --quiet aos-image-boot-commit.service", timeout=420
    )
    runtime.wait_until_succeeds(
        f"{SYSTEMCTL} is-active --quiet multi-user.target", timeout=420
    )
    if efivar_byte("SetupMode") == 1:
        update = f"PATH={UTIL_LINUX}:$PATH {EFI_UPDATEVAR}"
        for variable in ("db", "KEK", "PK"):
            runtime.succeed(
                f"{update} -f {shlex.quote(SECURE_BOOT_KEYS + '/' + variable + '.auth')} "
                f"{variable} 2>&1"
            )
        runtime.reboot(timeout=600)
        runtime.wait_until_succeeds(
            f"{SYSTEMCTL} is-active --quiet aos-image-boot-commit.service",
            timeout=420,
        )
        runtime.wait_until_succeeds(
            f"{SYSTEMCTL} is-active --quiet multi-user.target", timeout=420
        )
    if efivar_byte("SecureBoot") != 1:
        raise RuntimeError("rollout matrix host did not enter Secure Boot mode")


def publish_system_candidate() -> None:
    """Publishes the signed alternate image from exact retained store paths."""

    runtime.succeed(
        textwrap.dedent(
            f"""
            set -eu
            export HOME=/tmp/rollout-system-registry
            export GIT_AUTHOR_NAME='Rollout Matrix Fixture'
            export GIT_AUTHOR_EMAIL=rollout-matrix@example.test
            export GIT_COMMITTER_NAME='Rollout Matrix Fixture'
            export GIT_COMMITTER_EMAIL=rollout-matrix@example.test
            export NIX_REMOTE=""
            export NIX_CONF_DIR=/tmp/rollout-system-nix-conf
            export PATH={GIT_BIN}:{NIX_BIN}:$PATH
            mkdir -p "$HOME" "$NIX_CONF_DIR"
            printf 'experimental-features = nix-command\\nsandbox = false\\n' \
              > "$NIX_CONF_DIR/nix.conf"

            {APR_BASE} create rollout-system
            registry="$HOME/.local/share/apm/registries/rollout-system"
            mkdir -p "$registry/sb-certs"
            cp {shlex.quote(SECURE_BOOT_KEYS + '/db.crt')} "$registry/sb-certs/db.pem"
            set -- {CANDIDATE_UKI}/*.efi
            test "$#" -eq 1
            {APR_BASE} --json publish {shlex.quote(CANDIDATE_TOP)} \
              --name aos \
              --version 9999.0.0-effect-matrix \
              --description 'native rollout effect matrix candidate' \
              --license Apache-2.0 \
              --maintainer test \
              --sysroot \
              --image-payload {shlex.quote(CANDIDATE_IMAGE)} \
              --image-disk {shlex.quote(CANDIDATE_IMAGE_DISK)} \
              --image-info {shlex.quote(CANDIDATE_IMAGE_INFO)} \
              --image-format raw \
              --image-uki "$1" \
              --no-ca \
              --registry rollout-system \
              --no-commit > /tmp/rollout-system-publication.json
            signer=$({JQ} -er '.images[0].ukis[0].sb_signer_cert_sha256' \
              /tmp/rollout-system-publication.json)
            {APR_BASE} sb-certs add rollout-db \
              --cert-sha256 "$signer" --registry rollout-system --no-commit
            {GIT_BIN}/git -C "$registry" add -A
            {GIT_BIN}/git -C "$registry" commit -m 'release: rollout matrix image'
            {GIT_BIN}/git -C "$registry" tag v1.0.0
            {APM_BASE} registry --system add --no-verify \
              "file://$registry" --name rollout-system --no-clone
            {APM_BASE} update --system --registry rollout-system
            """
        ),
        timeout=1800,
    )
    publication = json.loads(
        runtime.succeed(f"{COREUTILS}/cat /tmp/rollout-system-publication.json")
    )
    ukis = publication["images"][0]["ukis"]
    if {entry["slot"] for entry in ukis} != {"a", "b"}:
        raise RuntimeError(f"rollout candidate did not publish both slots: {ukis!r}")
    if not all(re.fullmatch(r"[0-9a-f]{64}", entry["expected_pcr11"]) for entry in ukis):
        raise RuntimeError("rollout candidate lacks bounded PCR11 identities")


def stage_candidate() -> dict[str, Any]:
    """Stages the signed image without selecting or rebooting it."""

    before = image_state()
    if before["running"] != before["default"]:
        raise RuntimeError("rollout matrix did not start from its default image")
    boot_id = runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip()
    runtime.succeed(
        f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM_BASE} upgrade --system --yes",
        timeout=1800,
    )
    staged = image_state()
    candidate = generation(staged, staged["pending"])
    if staged["running"] != before["running"] or staged["default"] != before["default"]:
        raise RuntimeError("advisory image staging changed active boot authority")
    if runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip() != boot_id:
        raise RuntimeError("advisory image staging rebooted the host")
    return candidate


def rollout_request(candidate: dict[str, Any]) -> dict[str, Any]:
    """Builds the exact authenticated A/B request from physical generations."""

    state = image_state()
    predecessor = generation(state, state["running"])

    def identity(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "toplevel": record["toplevel"],
            "uki": record.get("uki_source_path") or record["uki_path"],
            "executor": record["native_executor_ref"],
            "state_format": record["state_version"],
        }

    now = int(runtime.succeed(f"{DATE} +%s%3N").strip())
    return {
        "strategy": "single-host-ab-v1",
        "concurrency": 1,
        "predecessor": identity(predecessor),
        "candidate": identity(candidate),
        "retention_expires_at_millis": now + 600000,
    }


def rollout_host(request: dict[str, Any], mode: str, label: str) -> str:
    """Writes an authenticated candidate host that retains the observer."""

    activation = generate_rollout_activation(request, mode, label)
    path = f"/var/lib/aos/ability-boundary-test/rollout-host-{label}.nix"
    write_rollout_host(path, activation, OBSERVER_HOST_MODULE)
    runtime.succeed(f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(path)}")
    return path


def settle_initial_rollout(request: dict[str, Any], label: str) -> None:
    """Completes one healthy rollout so a later retirement is authorized."""

    host = rollout_host(request, "rollout", label)
    boot_id = runtime.succeed(f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id").strip()
    try:
        runtime.succeed(
            f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM_BASE} switch "
            f"--from {shlex.quote(host)} --eval-root /run/{shlex.quote(label)}",
            timeout=1800,
        )
    except Exception:
        pass
    runtime.wait_until_succeeds(
        f"test \"$({COREUTILS}/cat /proc/sys/kernel/random/boot_id)\" != "
        f"{shlex.quote(boot_id)}",
        timeout=900,
    )
    runtime.wait_until_succeeds(
        f"{JQ} -e '.active_rollout == null and .last_rollout.status == \"succeeded\"' "
        f"{IMAGE_STATE}",
        timeout=900,
    )


def policy_document(activation: dict[str, Any]) -> dict[str, Any]:
    """Loads the exact retained policy sidecar used by activation."""

    sidecar = activation["authenticated_policy_set"]
    path = sidecar["store_path"] + "/" + sidecar["document"]
    return json.loads(runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}"))


def sentinel_snapshot() -> dict[str, Any]:
    """Reads the independent live unit retained across the rollout flight."""

    runtime.wait_until_succeeds(
        f"{SYSTEMCTL} is-active --quiet aos-rollout-matrix-foreign.service",
        timeout=120,
    )
    return {
        "unit": "aos-rollout-matrix-foreign.service",
        "properties": runtime.succeed(
            f"{SYSTEMCTL} show aos-rollout-matrix-foreign.service "
            "-p Id -p LoadState -p ActiveState -p SubState -p InvocationID"
        ),
    }


def sentinel_resource(provider: dict[str, Any]) -> dict[str, Any]:
    """Names the independently owned systemd unit used as a foreign sentinel."""

    return {
        "provider": provider | {"key": "rollout-foreign"},
        "key": "rollout-foreign-service",
    }


def machine_snapshot() -> dict[str, Any]:
    """Reads the physical boot-slot and provider state without journal input."""

    return PROVIDER_ORACLES.rollout_snapshot({"inputs": {}}, [])


def request_path(request: dict[str, Any], label: str) -> str:
    """Writes one canonical request for the production map audit."""

    path = f"/var/lib/aos/ability-boundary-test/{label}-request.json"
    payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.b64encode(payload).decode()
    runtime.succeed(
        f"{COREUTILS}/printf '%s' {shlex.quote(encoded)} | "
        f"{COREUTILS}/base64 -d > {shlex.quote(path)}"
    )
    return path


def run_rollout_method(method: str, evidence_builder: Any) -> None:
    """Runs both exact negative scenarios for one production rollout method."""

    interface = "aos.ab-image-rollout-effects"
    bootstrap_rollout_host()
    publish_system_candidate()
    publish_rollout_package()
    candidate = stage_candidate()
    request = rollout_request(candidate)
    label = "rollout-" + method.replace("-", "_")

    if method == "retire":
        settle_initial_rollout(request, label + "-baseline")
        deadline = request["retention_expires_at_millis"] // 1000 + 1
        runtime.succeed(f"{DATE} -s @{deadline}")
        mode = "retire"
    else:
        if method in {"hold", "withdraw"}:
            runtime.succeed(f"{COREUTILS}/touch /var/lib/aos-test/rollout-health-fail")
        mode = "rollout"

    activation = generate_rollout_activation(request, mode, label)
    host = f"/var/lib/aos/ability-boundary-test/rollout-host-{label}.nix"
    write_rollout_host(host, activation, OBSERVER_HOST_MODULE)
    runtime.succeed(f"{OBSERVER_CONTROLLER} persist-file {shlex.quote(host)}")
    policy = policy_document(activation)
    mapping = policy["native_resource_map"]
    [real_mapping] = mapping["entries"]
    resource = real_mapping["resource"]

    foreign_before = sentinel_snapshot()
    machine_before = machine_snapshot()
    audit_path = f"/var/lib/aos/ability-boundary-test/{label}-foreign-map.json"
    runtime.succeed(
        f"{FIXTURE} rollout-foreign-map-audit {shlex.quote(audit_path)} "
        f"{shlex.quote(request_path(request, label))} {shlex.quote(method)}"
    )
    audit_bytes = runtime.succeed(f"{COREUTILS}/cat {shlex.quote(audit_path)}").encode()
    foreign_after = sentinel_snapshot()
    machine_after = machine_snapshot()
    evidence_builder.retain_rollout_foreign(
        method,
        audit_bytes,
        foreign_before,
        foreign_after,
        sentinel_resource(resource["provider"]),
        machine_before,
        machine_after,
    )

    flight = PROVIDER_FLIGHT.ProviderFlight(
        adapter="image-rollout",
        interface=interface,
        method=method,
        provider_key="image-rollout",
        resource_key="machine",
        label=label + "-dependency",
        observation=method in {"observe-boot", "observe-health"},
        mapping=mapping,
    )
    PROVIDER_FLIGHT.run_rollout_dependency_flight(
        flight,
        host,
        evidence_builder,
        sentinel_snapshot,
    )
