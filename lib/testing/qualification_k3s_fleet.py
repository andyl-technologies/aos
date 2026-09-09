"""Exercises staged K3s packages in two copies of the bound published image.

Package NAR and ordinary APM evidence is produced first by the package adapter.
This scenario adds authenticated guest installation, typed role activation,
cluster membership, credential rejection, and the staged OCI workload. A final
report is written only after removal and generation recovery succeed as well.
"""

import calendar
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import time
import urllib.parse

import qualification_image as image
from k3s_lifecycle import (
    assert_k3s_addon_services,
    assert_k3s_cluster,
    assert_k3s_default_addons,
    assert_k3s_workload,
    import_k3s_workload,
)
from qualification_k3s_bindings import bind_k3s_fleet, verify_role_configuration_binding
from qualification_k3s_oci import assemble_workload


class FleetMachine(image.VirtualMachine):
    """Adds an isolated loopback datagram link beside each guest's SSH uplink."""

    def __init__(self, *args, local_port, peer_port, mac, **kwargs):
        self.local_port = local_port
        self.peer_port = peer_port
        self.mac = mac
        super().__init__(*args, **kwargs)

    def _arguments(self):
        return super()._arguments() + [
            "-netdev",
            f"socket,id=fleet,udp=127.0.0.1:{self.peer_port},localaddr=127.0.0.1:{self.local_port}",
            "-device", f"virtio-net-pci,netdev=fleet,mac={self.mac}",
        ]

    def succeed(self, command, timeout=600):
        return self.ssh(command, timeout=timeout)

    def wait_until_succeeds(self, command, timeout):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"{self.name} timed out waiting for {command}")
            try:
                return self.ssh(command, timeout=max(1, min(30, int(remaining))))
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)


class FleetScenario:
    """Owns one complete topology exercise and its final package report."""

    def __init__(self):
        self.request = image.read_json(image.REQUEST)
        self.case = self.request["qualification_case"]
        self.objects = image.read_json(image.OBJECTS)
        manifest_path = pathlib.Path(self.objects["control/release-manifest-envelope"])
        self.envelope = image.read_json(manifest_path)
        self.payload = self.envelope["payload"]
        self.topology = os.environ["AOS_QUALIFICATION_BOUND_K3S_TOPOLOGY"]
        self.variant = os.environ["AOS_QUALIFICATION_BOUND_IMAGE_VARIANT"]
        self.report = image.read_json(image.REPORT)
        self.work = image.ROOT / "k3s-work"
        self.machines = []
        self.counts = image.Counts()
        self.workloads = []
        self.configured = set()
        self.cluster_identity = None
        self.recovered_generations = {}

    def validate(self):
        """Checks the complete case and prepares its authenticated workload."""

        parts = self.case["id"].split("/")
        if len(parts) != 3 or parts[0] != "package-function" or parts[2] != image.PLATFORM:
            raise ValueError("K3s scenario received an unrelated package case")
        self.package = parts[1]
        self.bindings = bind_k3s_fleet(
            self.payload, image.PLATFORM, self.package, self.variant, self.topology
        )
        if (
            self.case["subjects"] != self.bindings.subjects
            or self.case.get("predecessor") is not None
            or self.case["phase"] != "staging"
            or set(self.case["checks"]) != image.PACKAGE_CHECKS
            or self.request["platform"] != image.PLATFORM
            or self.envelope["payload_digest"] != self.request["manifest_digest"]
            or image.digest("aos.release.manifest/v1", self.payload)
            != self.request["manifest_digest"]
            or self.payload["registry"] != self.request["registry"]
            or self.payload["release_id"] != self.request["release_id"]
        ):
            raise ValueError("K3s scenario differs from its authenticated request")

        expected_machine = {
            "x86_64-linux": "x86_64",
            "aarch64-linux": "aarch64",
        }[image.PLATFORM]
        if os.uname().machine != expected_machine:
            raise ValueError("K3s fleet must execute on the native release platform")
        self.validate_package_report()
        self.configure_registry()

        image_objects = {
            identity: self.objects[identity]
            for identity in self.bindings.image_artifacts
        }
        self.disk_id, self.disk = image.object_with_suffix(image_objects, "logical-disk")
        self.metadata_id, metadata_path = image.object_with_suffix(image_objects, "metadata")
        self.metadata = image.read_json(metadata_path)

        self.work.mkdir()
        self.archive, self.workload_image = assemble_workload(
            self.payload, self.objects, self.bindings, image.PLATFORM, self.work / "oci"
        )

    def validate_package_report(self):
        """Requires the successful package stage for this exact request."""

        for field in ("registry", "release_id", "staging_receipt_digest", "manifest_digest"):
            if self.report[field] != self.request[field]:
                raise ValueError("K3s package report belongs to another request")
        if (
            self.report.get("schema_version")
            != "aos.release.qualification-scenario-report/v1"
            or self.report["case_digest"] != image.digest(self.case["schema_version"], self.case)
            or set(self.report["checks"]) != image.PACKAGE_CHECKS
            or any(check.get("passed") is not True for check in self.report["checks"].values())
        ):
            raise ValueError("K3s package lifecycle did not finish successfully")

    def configure_registry(self):
        """Selects the candidate tag at the executor's pinned staging origin."""

        self.candidate_version = self.payload["version"]
        registry = self.request["registry"]
        self.registry_client = "andyl" if registry == "andyl/main" else registry.replace("/", "-")
        if re.fullmatch(r"[A-Za-z0-9_-]+", self.registry_client) is None:
            raise ValueError("K3s registry does not map to a safe client name")
        origin = urllib.parse.urlsplit(image.STAGING_HUB_URL)
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username is not None
            or origin.password is not None
            or origin.query
            or origin.fragment
            or origin.path not in {"", "/"}
        ):
            raise ValueError("K3s staging registry requires a bounded HTTPS origin")
        registry_path = urllib.parse.quote(registry, safe="/")
        self.staging_url = image.STAGING_HUB_URL.rstrip("/") + f"/{registry_path}/"

    def host_config(self, name, mac, address, public_key):
        config = self.work / f"{name}-host.nix"
        # Match MAC addresses without renaming interfaces: first-boot host
        # configuration arrives after udev has already named the NICs.
        config.write_text(f'''{{ ... }}: {{
  aos.roles.server.enable = true;
  aos.services.ssh.enable = true;
  aos.services.ssh.permitRootLogin = "prohibit-password";
  aos.networking.hostName = "{name}";
  environment.etc."ssh/authorized_keys/root".text = {json.dumps(public_key)};
  environment.etc."systemd/network/05-qualification-uplink.network".text = ''
    [Match]
    MACAddress=52:54:00:12:34:56
    [Network]
    DHCP=yes
  '';
  environment.etc."systemd/network/05-qualification-fleet.network".text = ''
    [Match]
    MACAddress={mac}
    [Network]
    Address={address}/24
  '';
}}
''')
        return config

    def create_machines(self):
        key = self.work / "ssh-key"
        image.run([image.SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        public_key = key.with_suffix(".pub").read_text().strip()
        # Reserve both endpoints together; release them only when QEMU is ready
        # to bind. Datagram peers survive either guest's process restart.
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second,
        ):
            first.bind(("127.0.0.1", 0))
            second.bind(("127.0.0.1", 0))
            ports = [first.getsockname()[1], second.getsockname()[1]]
            for index, name in enumerate(("server", "worker")):
                mac = f"52:54:00:44:00:{index + 1:02x}"
                config = self.host_config(name, mac, f"192.168.77.{10 + index}", public_key)
                machine = FleetMachine(
                    "k3s-" + name,
                    self.disk,
                    config,
                    key,
                    self.counts,
                    local_port=ports[index],
                    peer_port=ports[1 - index],
                    mac=mac,
                )
                self.machines.append(machine)
        for machine in self.machines:
            image.Scenario.enroll(self, machine)
            if machine.ssh("uname -r").strip() != self.metadata["capabilities"]["kernel_release"]:
                raise ValueError("K3s guest kernel differs from bound image metadata")
            image.Scenario._stage_registry(self, machine)
            links = json.loads(machine.ssh("ip -j link"))
            matches = [
                link["ifname"] for link in links
                if link.get("address") == machine.mac
            ]
            if len(matches) != 1:
                raise ValueError("K3s guest does not expose its exact fleet network device")
            machine.fleet_interface = matches[0]

    def role_module(self, machine, role, enabled=True):
        """Applies typed role options through APM's configuration transaction."""

        worker = role == "k3s-worker"
        node_name = "worker" if worker else "server"
        node_address = "192.168.77.11" if worker else "192.168.77.10"
        server_url = 'serverUrl = "https://192.168.77.10:6443";' if worker else ""
        module = self.work / (machine.name + "-role.nix")
        module.write_text(f'''{{
  aos.apm.desiredPackages = [ "k3s" "{role}" ];
  k3s = {{
    enable = {"true" if enabled else "false"};
    token.ref = "system-credential:k3s-token";
    node.name = "{node_name}";
    node.ip = "{node_address}";
    networking.flannelInterface = {json.dumps(machine.fleet_interface)};
    {server_url}
  }};
}}
''')
        machine.copy_to(module, "/run/qualification-k3s.nix")
        if machine.name in self.configured:
            machine.ssh("apm config replace qualification-k3s.nix /run/qualification-k3s.nix")
        else:
            machine.ssh("apm config add /run/qualification-k3s.nix --name qualification-k3s.nix")
            self.configured.add(machine.name)
        machine.ssh("apm config apply --eval-root /run/qualification-k3s-eval", timeout=1200)
        self.verify_role_configuration(machine, role)

    def verify_role_configuration(self, machine, role):
        """Requires activation to consume the candidate's exact role module."""

        manifest = image.read_remote_json(machine, "/run/aos/manifest.json")
        expected = verify_role_configuration_binding(
            manifest, self.bindings, role, self.registry_client, self.candidate_version
        )
        machine.ssh(shlex.join(["nix-store", "--verify-path", expected]), timeout=600)

    def verify_outputs(self, machine, role, present=True):
        for package in ("k3s", role):
            output = self.bindings.package_outputs[package]["out"]
            store_hash = pathlib.Path(output).name.split("-", 1)[0]
            root = "/var/lib/profiles/system-packages/current/usr/" + store_hash
            if present:
                resolved = machine.ssh("readlink -f " + shlex.quote(root)).strip()
                if resolved != output:
                    raise ValueError("K3s guest profile resolves to a different staged output")
                machine.ssh(shlex.join(["nix-store", "--verify-path", output]), timeout=600)
            else:
                machine.ssh("test ! -e " + shlex.quote(root))

    def install(self, machine, role):
        self.reconcile_packages(machine, ["k3s", role])
        self.verify_outputs(machine, role)

    def reconcile_packages(self, machine, packages):
        desired = self.work / (machine.name + "-desired.toml")
        desired.write_text("packages = " + json.dumps(packages) + "\n")
        machine.copy_to(desired, "/run/qualification-k3s-desired.toml")
        machine.ssh(
            "apm install --system --from /run/qualification-k3s-desired.toml --yes", timeout=1800,
        )

    def credential(self, machine, token):
        # Copy the secret as a private file so command failures cannot print it.
        source = self.work / (machine.name + "-token")
        source.write_text(token)
        source.chmod(0o600)
        machine.ssh("install -d -m 0700 /run/credentials/@system")
        machine.copy_to(source, "/run/credentials/@system/k3s-token")
        machine.ssh("chmod 0600 /run/credentials/@system/k3s-token")
        source.unlink()

    def assert_cluster(self):
        combined = self.topology == "combined-worker"
        observed = assert_k3s_cluster(
            self.machines[0], self.kubectl, ["server", "worker"] if combined else ["worker"],
            combined_node="server" if combined else None,
        )
        assert_k3s_default_addons(self.machines[0], self.kubectl)
        if self.cluster_identity is not None and observed != self.cluster_identity:
            raise ValueError("K3s API object identities changed during lifecycle recovery")
        self.cluster_identity = observed

    def reject_bad_credential(self):
        worker = self.machines[1]
        source = self.work / "rejected-token"
        source.write_text(secrets.token_hex(24))
        source.chmod(0o600)
        worker.copy_to(source, "/run/qualification-rejected-token")
        source.unlink()
        command = shlex.join([
            "timeout", "60s", self.k3s + "/bin/k3s", "agent",
            "--server", "https://192.168.77.10:6443",
            "--token-file", "/run/qualification-rejected-token",
            "--node-name", "rejected-worker", "--data-dir", "/run/qualification-rejected-agent",
        ])
        # A distinct data directory and node identity prevent an existing
        # enrolled node's certificate from bypassing the bad-token check.
        worker.ssh(
            command + " >/run/qualification-rejected-agent.log 2>&1; "
            "status=$?; test $status -ne 0 && "
            "grep -Ei 'token.*(invalid|mismatch)|unauthorized|401' /run/qualification-rejected-agent.log",
            timeout=90,
        )
        worker.ssh("rm /run/qualification-rejected-token")
        self.assert_cluster()

    def exercise_workloads(self, stage):
        assert_k3s_addon_services(
            self.machines[0],
            self.kubectl,
            self.k3s + "/share/k3s/aos-addon-images.json",
            "worker",
            "qualification-addons-" + stage,
        )
        nodes = list(zip(("server", "worker"), self.machines))
        if self.topology == "control-plane-worker":
            nodes = nodes[1:]
        for node, machine in nodes:
            machine.copy_to(self.archive, "/run/qualification-workload.oci.tar")
            import_k3s_workload(
                machine, self.k3s + "/bin/ctr", self.k3s + "/bin/crictl",
                "/run/qualification-workload.oci.tar", self.workload_image,
            )
            self.workloads.append(assert_k3s_workload(
                self.machines[0], self.kubectl, self.workload_image,
                ["/usr/bin/printf", "staged-k3s-workload-passed\n"],
                "staged-k3s-workload-passed\n", node, f"qualification-{stage}-{node}",
            ))

    def execute(self):
        self.validate()
        try:
            self.create_machines()
            server, worker = self.machines
            role = "k3s-combined" if self.topology == "combined-worker" else "k3s-control-plane"
            self.k3s = self.bindings.package_outputs["k3s"]["out"]
            self.kubectl = self.k3s + "/bin/kubectl"
            token = secrets.token_hex(24)
            for machine, package in ((server, role), (worker, "k3s-worker")):
                self.install(machine, package)
                self.credential(machine, token)
                self.role_module(machine, package)

            server.wait_until_succeeds("systemctl is-active --quiet k3s.service", timeout=300)
            self.assert_cluster()
            self.reject_bad_credential()
            self.exercise_workloads("installed")

            for machine, package in ((server, role), (worker, "k3s-worker")):
                source = f"/run/credstore/{package}/token"
                machine.ssh(f"test -s {source} && test $(stat -c %a {source}) = 600")
                if token in machine.ssh("cat /run/aos/manifest.json"):
                    raise ValueError("K3s join credential leaked into the public activation manifest")
                self.verify_outputs(machine, package)
                machine.ssh("systemctl restart k3s.service", timeout=300)
                self.verify_role_configuration(machine, package)
            self.assert_cluster()
            self.exercise_workloads("restarted")

            for machine, package in ((worker, "k3s-worker"), (server, role)):
                generation = image.read_remote_json(machine, "/var/lib/profiles/system/state.json")["current"]
                if not isinstance(generation, int) or generation < 1:
                    raise ValueError("K3s activated profile lacks a recovery generation")
                self.role_module(machine, package, enabled=False)
                machine.ssh("apm config remove qualification-k3s.nix")
                self.configured.remove(machine.name)
                machine.ssh("apm config apply --eval-root /run/qualification-k3s-remove", timeout=1200)
                self.reconcile_packages(machine, [])
                self.verify_outputs(machine, package, present=False)
                machine.ssh("! systemctl is-active --quiet k3s.service")
                machine.ssh(f"apm rollback --system --generation {generation}", timeout=1200)
                restored = image.read_remote_json(
                    machine, "/var/lib/profiles/system/state.json"
                )["current"]
                if restored != generation:
                    raise ValueError("K3s rollback did not restore the selected configuration generation")
                self.reconcile_packages(machine, ["k3s", package])
                self.verify_outputs(machine, package)
                self.verify_role_configuration(machine, package)
                machine.ssh("systemctl restart k3s.service", timeout=300)
                self.recovered_generations[machine.name] = generation
            self.assert_cluster()
            self.exercise_workloads("recovered")
            self.write_report()
        finally:
            for machine in self.machines:
                machine.stop_processes()

    def write_report(self):
        finished = time.time()
        started = calendar.timegm(time.strptime(self.report["started_at"], "%Y-%m-%dT%H:%M:%SZ"))
        self.report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished))
        self.report["observed_seconds"] = max(0, int(finished - started))
        self.report["checks"]["functional-behavior"]["detail"] += (
            " The bound image booted both K3s roles; the cluster rejected a wrong token and "
            "executed the exact published OCI workload after install, restart, and generation recovery."
        )
        self.report["operations"].update({
            "fleet_guests": 2, "fleet_workloads": len(self.workloads),
            "fleet_credential_rejections": 1, "fleet_generation_recoveries": 2,
        })
        self.report["environment"]["k3s_fleet"] = {
            "topology": self.topology, "system_variant": self.variant,
            "logical_disk_artifact": self.disk_id, "metadata_artifact": self.metadata_id,
            "packages": self.bindings.package_outputs, "workloads": self.workloads,
            "cluster": self.cluster_identity,
            "recovered_generations": self.recovered_generations,
            "qemu_version": image.run([image.QEMU, "--version"]).stdout.splitlines()[0],
            "guest_kernel": self.metadata["capabilities"]["kernel_release"],
        }
        image.REPORT.write_bytes(image.canonical(self.report) + b"\n")


if __name__ == "__main__":
    FleetScenario().execute()
