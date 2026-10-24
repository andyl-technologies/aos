# Exercises the actual offline hardware owner with host approvals and one vTPM.
{
  lib,
  pkgs,
  systems,
  rejectHierarchyAuthorization ? false,
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
  recover = invocation "recover";
  importInitialize = invocation "import-initialize-v6";
  importRecovery = invocation "import-recovery-v6";
  exportHistory = invocation "export-history-v7";
  variants = {inherit initialize recover importInitialize importRecovery exportHistory;};
  system = preparation.machines.vm.system.extendModules {
    modules = [
      {
        # Inactive inventory aliases label unchanged immutable fragment inodes.
        # Their names cannot pass the genuine startup's fixed-unit comparison.
        environment.etc = lib.mapAttrs' (name: variant:
          lib.nameValuePair "systemd/system/aos-offline-${name}-reference.service" {
            source = "${variant.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service";
          })
        variants;
      }
    ];
  };
in {
  name =
    if rejectHierarchyAuthorization
    then "sandbox-nix-offline-hardware-failed-history"
    else "sandbox-nix-offline-hardware-provisioning";
  timeout = 1800;
  inherit (preparation) bootTimeout;
  machines.vm =
    preparation.machines.vm
    // {
      inherit system;
      tpm = true;
    };

  testScript =
    preparation.testScript
    + ''
      import hashlib
      import json
      import pathlib
      import subprocess
      import tempfile
      import time
      import uuid

      hardware_succeeds = ${
        if rejectHierarchyAuthorization
        then "False"
        else "True"
      }

      def install_credential(host_path, name, *, replace=False):
          target = "/etc/credstore/" + name
          temporary = target + ".new" if replace else target
          code = (
              "import os; "
              f"fd = os.open({temporary!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400); "
              f"data = bytes.fromhex({host_path.read_bytes().hex()!r}); "
              "assert os.write(fd, data) == len(data); os.fsync(fd); os.close(fd); "
          )
          if replace:
              code += f"os.replace({temporary!r}, {target!r}); "
          code += "fd = os.open('/etc/credstore', os.O_RDONLY | os.O_DIRECTORY); os.fsync(fd); os.close(fd)"
          vm.succeed(f"{python} -c {shlex.quote(code)}")

      def select_invocation(unit_path, profile_path):
          vm.succeed(f"systemctl link --force {unit_path}")
          vm.succeed("systemctl daemon-reload")
          fragment = vm.succeed(f"systemctl show {unit} --property=FragmentPath --value").strip()
          assert vm.succeed(f"readlink -f {shlex.quote(fragment)}").strip() == unit_path
          assert vm.succeed(f"systemctl show {unit} --property=DropInPaths --value").strip() == ""
          assert vm.succeed(f"systemctl show {unit} --property=Transient --value").strip() == "no"
          assert profile_path in vm.succeed(f"systemctl show {unit} --property=OpenFile --value")

      def run_offline(status):
          vm.execute(f"systemctl reset-failed {unit}")
          vm.execute(f"systemctl start {unit}")
          state = "inactive" if status == 0 else "failed"
          vm.wait_until_succeeds(
              f"test $(systemctl show {unit} --property=ExecMainStatus --value) = {status} && "
              f"test $(systemctl show {unit} --property=ActiveState --value) = {state}",
              timeout=180,
          )

      def public_histories():
          journal = vm.succeed(f"journalctl --boot=0 --unit={unit} --output=cat --no-pager")
          exports = []
          current = bytearray()
          extent = None
          for line in journal.splitlines():
              if line.startswith("AOS_NIX_OFFLINE_HISTORY_V5="):
                  total, offset, encoded = line.split("=", 1)[1].split(":")
                  total, offset = int(total), int(offset)
                  assert 0 < total <= 4 * 1024 * 1024
                  assert offset == len(current)
                  assert extent is None or extent == total
                  extent = total
                  data = bytes.fromhex(encoded)
                  assert data.hex() == encoded and 0 < len(data) <= 1024
                  current.extend(data)
                  assert len(current) <= extent
              elif line.startswith("AOS_NIX_OFFLINE_HISTORY_V5_END="):
                  assert extent == len(current) and current
                  assert hashlib.sha256(current).hexdigest() == line.split("=", 1)[1]
                  exports.append(bytes(current))
                  current = bytearray()
                  extent = None
          assert not current and extent is None, "incomplete public history export"
          return exports

      def assert_history_reads_denied():
          code = (
              "import pathlib\n"
              "for name in ('approved-job-v3', 'approved-effect-v4', 'provisioning-v4.journal'):\n"
              "    try:\n"
              f"        pathlib.Path({root!r}, name).read_bytes()\n"
              "    except PermissionError:\n"
              "        continue\n"
              "    raise AssertionError(name + ' was readable by generic root')\n"
          )
          vm.succeed(f"{python} -c {shlex.quote(code)}")

      with tempfile.TemporaryDirectory(prefix="sandbox-offline-hardware-") as scratch:
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
          hierarchy = scratch / "hierarchy-auth"
          hierarchy.write_bytes(bytes([0x76]) * 32)
          hierarchy.chmod(0o600)

          # The external operator provisions the same persistent software TPM
          # while QEMU and its backend are stopped. No state is copied, cleared
          # or replaced; generic guest root never receives TPM device access.
          vm._stop_runtime_for_relaunch(120)
          assert vm.qemu_proc.poll() is not None
          assert vm.swtpm_proc.poll() is not None
          data = scratch / "tpm.sock"
          control = scratch / "tpm.sock.ctrl"
          with (scratch / "external-tpm.log").open("wb") as log:
              backend = subprocess.Popen([
                  vm.swtpm_bin, "socket", "--tpm2", f"--tpmstate=dir={vm.tpm_state_dir}",
                  f"--server=type=unixio,path={data}", f"--ctrl=type=unixio,path={control}",
                  "--flags=not-need-init,startup-clear",
              ], stdout=log, stderr=log)
              try:
                  deadline = time.monotonic() + 5
                  while not data.exists() or not control.exists():
                      assert backend.poll() is None, "external TPM backend exited"
                      assert time.monotonic() < deadline, "external TPM socket timeout"
                      time.sleep(0.02)
                  subprocess.run([
                      "${pkgs.tpm2-tools}/bin/tpm2_changeauth", "-T", f"swtpm:path={data}",
                      "-c", "owner", f"file:{hierarchy}",
                  ], check=True)
                  subprocess.run([
                      "${pkgs.tpm2-tools}/bin/tpm2_shutdown", "-T", f"swtpm:path={data}", "-c",
                  ], check=True)
              finally:
                  backend.terminate()
                  try:
                      backend.wait(timeout=5)
                  except subprocess.TimeoutExpired:
                      backend.kill()
                      backend.wait(timeout=5)
          vm._launch()
          vm.agent.wait_ready(time.monotonic() + 300)
          vm.wait_for_unit("multi-user.target", timeout=300)
          vm.wait_for_unit("aos-offline-controller-reference.target")
          vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
          assert_candidate_reads_denied()

          install_credential(domain, "nix-fixed-domain-pins-v2")
          delivered_hierarchy = scratch / "delivered-hierarchy-auth"
          delivered_hierarchy.write_bytes(
              hierarchy.read_bytes() if hardware_succeeds else bytes([0x77]) * 32
          )
          delivered_hierarchy.chmod(0o600)
          install_credential(delivered_hierarchy, "nix-floor-owner-hierarchy-auth-v4")
          initialized = scratch / "initialize"
          subprocess.run([
              "${operator}/bin/aos-sandbox-nix-offline-approval-vm-fixture",
              "initialize", str(public), str(domain), "${initialize.profile}", str(key), str(initialized),
          ], check=True)
          install_credential(initialized / "approved-job-v3", "nix-floor-provision-approved-job-v6")
          install_credential(initialized / "approved-effect-v4", "nix-floor-provision-approved-effect-v6")
          select_invocation(
              "${importInitialize.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${importInitialize.profile}",
          )
          run_offline(0)
          run_offline(1)
          select_invocation(
              "${exportHistory.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${exportHistory.profile}",
          )
          run_offline(1)
          assert public_histories() == []
          select_invocation(
              "${initialize.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${initialize.profile}",
          )
          boot = vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          run_offline(0 if hardware_succeeds else 1)
          histories = public_histories()
          assert len(histories) == (1 if hardware_succeeds else 0)
          assert_history_reads_denied()
          select_invocation(
              "${exportHistory.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${exportHistory.profile}",
          )
          run_offline(0)
          exported = public_histories()
          assert len(exported) == len(histories) + 1
          if hardware_succeeds:
              assert exported == histories + histories
          assert_history_reads_denied()
          history = scratch / "history"
          history.write_bytes(exported[-1])

          completed = exported
          if hardware_succeeds:
              recovered = scratch / "recover"
              subprocess.run([
                  "${operator}/bin/aos-sandbox-nix-offline-approval-vm-fixture",
                  "recover", str(public), str(domain), "${recover.profile}", str(key), str(recovered), str(history),
              ], check=True)
              assert (recovered / "approved-job-v3").read_bytes() == (initialized / "approved-job-v3").read_bytes()
              install_credential(recovered / "approved-recovery-v4", "nix-floor-provision-approved-effect-v6", replace=True)
              select_invocation(
                  "${importRecovery.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
                  "${importRecovery.profile}",
              )
              run_offline(0)
              run_offline(1)
              select_invocation(
                  "${recover.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
                  "${recover.profile}",
              )
              assert vm.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot
              run_offline(0)
              completed = public_histories()
              assert len(completed) == 3 and completed[:2] == histories + histories
              assert len(completed[2]) > len(completed[0])
              assert_history_reads_denied()
              run_offline(1)
              assert public_histories() == completed

          # Reboot cannot renew the original job. Its public DATA remains
          # exportable independently, including after failed hardware admission.
          select_invocation(
              "${initialize.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${initialize.profile}",
          )
          vm.reboot()
          vm.wait_for_unit("multi-user.target", timeout=300)
          run_offline(1)
          assert public_histories() == []
          assert_history_reads_denied()
          assert_candidate_reads_denied()
          select_invocation(
              "${exportHistory.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${exportHistory.profile}",
          )
          run_offline(0)
          assert public_histories() == [completed[-1]]
          assert_history_reads_denied()
          select_invocation(
              "${initialize.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${initialize.profile}",
          )
          run_offline(1)
          assert public_histories() == [completed[-1]]
          vm.power_cycle()
          vm.wait_for_unit("multi-user.target", timeout=300)
          run_offline(1)
          assert public_histories() == []
          assert_history_reads_denied()
          assert_candidate_reads_denied()
          select_invocation(
              "${exportHistory.unit}/lib/systemd/system/aos-sandbox-nix-floor-provision.service",
              "${exportHistory.profile}",
          )
          run_offline(0)
          assert public_histories() == [completed[-1]]
          assert_history_reads_denied()
          vm.fail("systemctl is-active --quiet aos-sandboxd.service")
          vm.fail("systemctl is-active --quiet aos-sandbox-nixd.service")
    '';
}
