# Exercises the manual production candidate owner without granting hardware effects.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  runtimeSystem = import ./_sandbox-funded-system.nix {inherit lib pkgs systems;};
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
  controllerReference = pkgs.writeTextFile {
    name = "sandbox-nix-offline-controller-reference";
    text = runtimeSystem.config.systemd.units."aos-sandboxd.service".text;
  };
  publicInputs =
    pkgs.runCommand "sandbox-nix-offline-preparation-public-inputs" {
      buildDeps = [pkgs.python3];
    } ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 - "$out" <<'PY'
      import pathlib
      import sys

      output = pathlib.Path(sys.argv[1])
      output.joinpath("node-id").write_bytes(bytes([0x41]) * 16)
      # RFC 8032's first public vector is test data. This image carries no
      # approval signing key and cannot approve the generated candidates.
      public = bytes.fromhex(
          "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
      )
      output.joinpath("approval-public-key").write_bytes(bytes([0x51]) * 16 + public)
      PY
    '';
  # Provisioning has its own immutable image. Online Resolve50 deliberately
  # rejects coexistence with the offline unit; keep that production assertion.
  system = systems.server-secureboot-lockdown.extendModules {
    modules = [
      ../../systems/_server-test-packages.nix
      ({config, ...}: {
        aos.security.selinux = {
          enable = true;
          bootMode = "immutable-stage0";
          mode = "enforcing";
          _qualificationAdmissionRelease = true;
        };
        aos.boot.initrd.stage0 = lib.mkForce (pkgs.aosSelinuxStage0With {
          aos-selinux-production-policy = config.aos.security.selinux._productionPolicy;
          aos-selinux-runtime-roots = config.aos.security.selinux._runtimeRootsProvisioner;
          admissionUnit = "";
          expectedPolicy = "${config.aos.security.selinux._canonicalReadback}/policy.33";
          expectedPolicyKernel = config.system.build.kernel;
        });
        aos.image = {
          erofsCompressionLevel = 1;
          rootPartitionMiB = 2048;
          budgets = {
            maxRuntimeClosureMiB = lib.mkForce 8192;
            maxRootMiB = 1536;
            maxDownloadMiB = 2048;
            maxConvertedDownloadMiB = 2048;
            maxInitrdMiB = 256;
            maxBootExecutableMiB = 288;
            maxFirmwarePartitionMiB = 832;
          };
        };
        aos.sandbox.nixOfflinePrepare.enable = true;
        # Install the genuine target-image Controller fragment unchanged,
        # without its activation links or external runtime credentials. The
        # reference target keeps the inactive unit loaded for PID1 readback;
        # ordering alone never starts it. The Nix owner remains uninstalled.
        environment.etc."systemd/system/aos-sandboxd.service".source = "${controllerReference}";
        systemd.targets.aos-offline-controller-reference = {
          description = "Retain the installed inactive Controller unit for provisioning";
          wantedBy = ["multi-user.target"];
          after = ["aos-sandboxd.service"];
        };
        environment.systemPackages = [pkgs.coreutils pkgs.python3 pkgs.systemd];
        environment.etc = {
          "credstore/node-id" = {
            source = "${publicInputs}/node-id";
            mode = "0400";
          };
          "credstore/nix-floor-provision-approval-public-key-v3" = {
            source = "${publicInputs}/approval-public-key";
            mode = "0400";
          };
        };
      })
    ];
  };
in {
  name = "sandbox-nix-offline-key-preparation";
  timeout = 1200;
  bootTimeout = 300;
  machines.vm = {
    inherit system;
    bootMode = "image";
    firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
    memoryMiB = 4096;
  };

  testScript = ''
    import shlex

    unit = "aos-sandbox-nix-floor-provision.service"
    root = "/var/lib/aos/sandbox-nix-floor-provision"
    python = "${pkgs.python3}/bin/python3"

    def public_candidate_exports():
        journal = vm.succeed(
            f"journalctl --boot=0 --unit={unit} --output=cat --no-pager"
        )
        prefix = "AOS_NIX_OFFLINE_PUBLIC_V3="
        exports = []
        for line in journal.splitlines():
            if not line.startswith(prefix):
                continue
            encoded = line[len(prefix):]
            assert len(encoded) == 536 and encoded == encoded.lower(), encoded
            public = bytes.fromhex(encoded)
            assert len(public) == 268 and public.hex() == encoded
            assert public[:12] == b'AOSNPC03\x03\0\0\0'
            assert public[28:44] == bytes([0x41]) * 16
            exports.append(public)
        return exports

    def assert_candidate_reads_denied():
        # The successful owner verifies originals before exporting public bytes.
        # Generic root has no authority to inspect either protected state file.
        check = r"""
    import pathlib

    root = pathlib.Path('/var/lib/aos/sandbox-nix-floor-provision')
    for name in ('candidate-private-v3', 'candidate-public-v3'):
        try:
            (root / name).read_bytes()
        except PermissionError:
            continue
        raise AssertionError(f'generic root read protected candidate {name}')
    """
        vm.succeed(f"{python} -c {shlex.quote(check)}")

    def reject_repeated_preparation(expected):
        vm.succeed(f"systemctl reset-failed {unit}")
        vm.execute(f"systemctl start {unit}")
        vm.wait_until_succeeds(
            f"test $(systemctl show {unit} --property=ExecMainStatus --value) = 1 && "
            f"test $(systemctl show {unit} --property=ActiveState --value) = failed",
            timeout=120,
        )
        assert public_candidate_exports() == expected
        assert_candidate_reads_denied()

    vm.wait_for_unit("multi-user.target", timeout=300)
    vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
    configuration_labels = r"""
    import os

    expected = b'system_u:object_r:etc_t'
    for path in ('/var/etc', '/var/etc/ssh', '/etc/ssh'):
        observed = os.getxattr(path, 'security.selinux').rstrip(b'\0')
        assert observed == expected, (path, observed)
    """
    vm.succeed(f"{python} -c {shlex.quote(configuration_labels)}")
    assert "[confidentiality]" in vm.succeed("cat /sys/kernel/security/lockdown")
    vm.wait_for_unit("aos-offline-controller-reference.target")
    assert vm.succeed("systemctl show aos-sandboxd.service --property=LoadState --value").strip() == "loaded"
    assert vm.succeed("systemctl show aos-sandboxd.service --property=ActiveState --value").strip() == "inactive"

    # The selected preparation image has no automatic candidate activation.
    vm.fail(f"systemctl is-active --quiet {unit}")
    vm.succeed(f"test ! -e {root}")

    # A real live unit with the fixed owner name must close preparation,
    # before any candidate directory exists. The actor grants no runtime
    # authority and is collected before the positive uninstalled-owner case.
    vm.succeed(
        "systemd-run --unit=aos-sandbox-nixd.service --collect "
        "--slice=aos-control.slice ${pkgs.coreutils}/bin/sleep infinity"
    )
    vm.execute(f"systemctl start {unit}")
    vm.wait_until_succeeds(
        f"test $(systemctl show {unit} --property=ExecMainStatus --value) = 1 && "
        f"test $(systemctl show {unit} --property=ActiveState --value) = failed",
        timeout=120,
    )
    vm.succeed(f"test ! -e {root}")
    vm.succeed("systemctl stop aos-sandbox-nixd.service")
    vm.wait_until_succeeds(
        "! ${pkgs.systemd}/bin/busctl call org.freedesktop.systemd1 "
        "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "
        "GetUnit s aos-sandbox-nixd.service",
        timeout=30,
    )

    vm.succeed(f"systemctl reset-failed {unit}")
    vm.succeed(f"systemctl start {unit}")
    vm.wait_until_succeeds(
        f"test $(systemctl show {unit} --property=ExecMainStatus --value) = 0 && "
        f"test $(systemctl show {unit} --property=ActiveState --value) = inactive",
        timeout=120,
    )
    original = public_candidate_exports()
    assert len(original) == 1, original
    assert_candidate_reads_denied()
    reject_repeated_preparation(original)

    # Reboot does not authorize replacement of the protected installation.
    # A rejected attempt must not export another public candidate.
    vm.reboot()
    vm.wait_for_unit("multi-user.target", timeout=300)
    vm.wait_for_unit("aos-offline-controller-reference.target")
    assert public_candidate_exports() == []
    assert_candidate_reads_denied()
    vm.fail(f"systemctl is-active --quiet {unit}")
    reject_repeated_preparation([])
  '';
}
