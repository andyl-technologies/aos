# Exercises the manual production candidate owner without granting hardware effects.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
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
          budgets = {
            maxRuntimeClosureMiB = lib.mkForce 2048;
            maxRootMiB = 1024;
            maxDownloadMiB = 1536;
            maxConvertedDownloadMiB = 1920;
            maxInitrdMiB = 256;
            maxBootExecutableMiB = 288;
            maxFirmwarePartitionMiB = 832;
          };
        };
        aos.sandbox.nixOfflinePrepare.enable = true;
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
    import json
    import shlex

    unit = "aos-sandbox-nix-floor-provision.service"
    root = "/var/lib/aos/sandbox-nix-floor-provision"
    python = "${pkgs.python3}/bin/python3"

    def candidate_snapshot():
        # Read secrets only inside the guest and return hashes and metadata.
        # The exact entry set also excludes an approval, hardware journal,
        # runtime publication or floor produced by this prepare-only step.
        check = r"""
    import hashlib
    import json
    import os
    import pathlib
    import stat

    root = pathlib.Path('/var/lib/aos/sandbox-nix-floor-provision')
    assert sorted(path.name for path in root.iterdir()) == [
        'candidate-private-v3', 'candidate-public-v3', 'installation.lock',
    ]
    result = {}
    entries = [(root, 0o700, None)] + [
        (root / 'candidate-private-v3', 0o600, 336),
        (root / 'candidate-public-v3', 0o400, 268),
        (root / 'installation.lock', 0o600, 0),
    ]
    for path, mode, size in entries:
        metadata = path.lstat()
        assert (metadata.st_uid, metadata.st_gid) == (0, 0)
        assert stat.S_IMODE(metadata.st_mode) == mode
        assert os.getxattr(path, 'security.selinux').rstrip(b'\0') == (
            b'system_u:object_r:aos_nix_offline_prepare_state_t'
        )
        digest = None
        if size is not None:
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            assert metadata.st_size == size
            content = path.read_bytes()
            if path.name == 'candidate-private-v3':
                assert content[:16] == b'AOSNPK03\x03\0' + bytes(6)
            if path.name == 'candidate-public-v3':
                assert content[:12] == b'AOSNPC03\x03\0\0\0'
                assert content[28:44] == bytes([0x41]) * 16
            digest = hashlib.sha256(content).hexdigest()
        else:
            assert stat.S_ISDIR(metadata.st_mode)
        result[path.name] = [metadata.st_ino, mode, size, digest]
    print(json.dumps(result, sort_keys=True))
    """
        return json.loads(vm.succeed(f"{python} -c {shlex.quote(check)}"))

    def reject_repeated_preparation(expected):
        vm.succeed(f"systemctl reset-failed {unit}")
        vm.execute(f"systemctl start {unit}")
        vm.wait_until_succeeds(
            f"test $(systemctl show {unit} --property=ExecMainStatus --value) = 1; "
            f"test $(systemctl show {unit} --property=ActiveState --value) = failed",
            timeout=120,
        )
        assert candidate_snapshot() == expected

    vm.wait_for_unit("multi-user.target", timeout=300)
    vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
    assert "[confidentiality]" in vm.succeed("cat /sys/kernel/security/lockdown")

    # The selected preparation image has no automatic candidate activation.
    vm.fail(f"systemctl is-active --quiet {unit}")
    vm.succeed(f"test ! -e {root}")
    vm.succeed(f"systemctl start {unit}")
    vm.wait_until_succeeds(
        f"test $(systemctl show {unit} --property=ExecMainStatus --value) = 0; "
        f"test $(systemctl show {unit} --property=ActiveState --value) = inactive",
        timeout=120,
    )
    original = candidate_snapshot()
    reject_repeated_preparation(original)

    # The persistent originals, rather than a fresh process or boot, fix
    # the attempt. The public delivery remains present in the same image.
    vm.reboot()
    vm.wait_for_unit("multi-user.target", timeout=300)
    assert candidate_snapshot() == original
    vm.fail(f"systemctl is-active --quiet {unit}")
    reject_repeated_preparation(original)
  '';
}
