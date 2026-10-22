# Exercises signed DATA delivery through the genuine production owner and MAC.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  preparation = import ./sandbox-nix-offline-key-preparation.nix {
    inherit lib pkgs systems;
  };
  operator = import ./_nix-offline-approval-fixture.nix {inherit lib pkgs;};
  invocation = command: let
    system = preparation.machines.vm.system.extendModules {
      modules = [{aos.sandbox.nixOfflinePrepare.command = command;}];
    };
    service = system.config.systemd.services.aos-sandbox-nix-floor-provision.serviceConfig;
  in {
    profile = builtins.head (lib.splitString ":" (builtins.elemAt service.OpenFile 1));
    unit = pkgs.writeTextFile {
      name = "sandbox-nix-offline-${command}-unit";
      destination = "/lib/systemd/system/aos-sandbox-nix-floor-provision.service";
      text = system.config.systemd.units."aos-sandbox-nix-floor-provision.service".text;
    };
  };
  initialize = invocation "initialize";
  delivery = invocation "import-initialize-v6";
  inspection = invocation "inspect-approved-job";
  system = preparation.machines.vm.system.extendModules {
    modules = [
      {
        # Canonical inventory aliases label the unchanged immutable fragments.
        # They have no activation links and cannot satisfy the fixed owner name.
        environment.etc = {
          "systemd/system/aos-offline-delivery-reference.service".source = "${delivery.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service";
          "systemd/system/aos-offline-inspection-reference.service".source = "${inspection.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service";
        };
      }
    ];
  };
in {
  name = "sandbox-nix-offline-approval-delivery";
  timeout = 1800;
  inherit (preparation) bootTimeout;
  machines.vm = preparation.machines.vm // {inherit system;};

  testScript =
    preparation.testScript
    + ''
      import json
      import pathlib
      import subprocess
      import tempfile
      import uuid

      def install_credential(host_path, name):
          target = "/etc/credstore/" + name
          code = (
              "import os; "
              f"fd = os.open({target!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400); "
              f"data = bytes.fromhex({host_path.read_bytes().hex()!r}); "
              "assert os.write(fd, data) == len(data); os.fsync(fd); os.close(fd)"
          )
          vm.succeed(f"{python} -c {shlex.quote(code)}")

      def select_invocation(unit_path):
          vm.succeed(f"systemctl link --force {unit_path}")
          vm.succeed("systemctl daemon-reload")
          fragment = vm.succeed(f"systemctl show {unit} --property=FragmentPath --value").strip()
          assert vm.succeed(f"readlink -f {shlex.quote(fragment)}").strip() == unit_path
          assert vm.succeed(f"systemctl show {unit} --property=DropInPaths --value").strip() == ""
          assert vm.succeed(f"systemctl show {unit} --property=Transient --value").strip() == "no"

      def run_offline(status):
          vm.execute(f"systemctl reset-failed {unit}")
          vm.execute(f"systemctl start {unit}")
          state = "inactive" if status == 0 else "failed"
          vm.wait_until_succeeds(
              f"test $(systemctl show {unit} --property=ExecMainStatus --value) = {status} && "
              f"test $(systemctl show {unit} --property=ActiveState --value) = {state}",
              timeout=180,
          )

      with tempfile.TemporaryDirectory(prefix="sandbox-offline-delivery-") as scratch:
          scratch = pathlib.Path(scratch)
          public = scratch / "public"
          public.write_bytes(original[0])
          key = scratch / "operator-key"
          key.write_bytes(bytes([0x51]) * 16 + bytes.fromhex(
              "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
          ))
          key.chmod(0o600)
          domain = scratch / "domain"
          domain.write_text(json.dumps({
              "version": 2,
              "identities": [811, 811, 819, 819],
              "node": str(uuid.UUID(bytes=bytes([0x41]) * 16)),
              "deployment": "sha256:" + "71" * 32,
              "endpoint": str(uuid.UUID(bytes=bytes([0x72]) * 16)),
              "domain": str(uuid.UUID(bytes=bytes([0x73]) * 16)),
              "domain_commitment": "sha256:" + "74" * 32,
              "disclosure": "sha256:" + "75" * 32,
          }, separators=(",", ":")))
          approved = scratch / "approved"
          subprocess.run([
              "${operator}/bin/aos-sandbox-nix-offline-approval-vm-fixture",
              "initialize", str(public), str(domain), "${initialize.profile}", str(key), str(approved),
          ], check=True)
          install_credential(approved / "approved-job-v3", "nix-floor-provision-approved-job-v6")
          install_credential(approved / "approved-effect-v4", "nix-floor-provision-approved-effect-v6")

          select_invocation("${delivery.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service")
          run_offline(0)
          assert_candidate_reads_denied()
          run_offline(1)
          assert_candidate_reads_denied()

          # The legacy inspector independently validates the delivered static job
          # against the real private/public candidate pair. No generic-root state
          # read or copied receipt stands in for this actual owner.
          select_invocation("${inspection.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service")
          run_offline(0)
          assert_candidate_reads_denied()
          assert public_candidate_exports() == []
    '';
}
