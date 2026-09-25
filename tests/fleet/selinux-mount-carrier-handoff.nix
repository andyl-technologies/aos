# Signed-initrd Mount carrier custody across an enforcing switch-root.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
  carrier = pkgs.aosMountExecutableCarrierForKernel pkgs.linux;
  stage0Fixture = import ./_selinux-stage0-fixture.nix {inherit lib pkgs;};
  carrierRoot = "/run/aos/mount-executable-carrier";
  qualificationStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = "";
    mountExecutableCarrier = carrier;
  };

  # Only the stage0 binary consumes this deliberately wrong hash. The signed
  # initrd still embeds and verifies the genuine carrier, so this machine
  # must fail during the PID 1 warm handoff instead of accepting the mount.
  wrongHash = pkgs.runCommand "mount-carrier-wrong-stage0-hash" {} ''
    mkdir -p "$out"
    printf '%064d\n' 0 > "$out/carrier.root-hash"
  '';
  wrongHashStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = "";
    mountExecutableCarrier = wrongHash;
  };

  fixtureModule = stage0:
    lib.mkMerge [
      (stage0Fixture stage0)
      {
        aos.image.erofsCompressionLevel = 1;
        aos.image.budgets.maxEspMiB = 896;
        aos.image.budgets.maxDownloadMiB = 1056;
        aos.boot.initrd.extraPackages = [
          pkgs.attr
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.device-mapper
          pkgs.util-linux
        ];
        boot.initrd.systemd.mountExecutableCarrier = carrier;
        environment.systemPackages = [pkgs.attr pkgs.cryptsetup pkgs.util-linux];

        boot.initrd.systemd.services.aos-mount-carrier-qualification = {
          description = "Qualify the signed Mount carrier before switch-root";
          requiredBy = ["initrd-switch-root.target"];
          after = ["systemd-udev-settle.service"];
          before = ["initrd-switch-root.target"];
          unitConfig = {
            DefaultDependencies = "no";
            OnFailure = "aos-boot-identity-failure.target";
            OnFailureJobMode = "isolate";
          };
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            StandardOutput = "kmsg+console";
            StandardError = "kmsg+console";
          };
          script = ''
            set -eu

            carrier=/lib/aos/mount-executable-carrier
            test "$(cat /sys/fs/selinux/enforce)" = 1
            test -s "$carrier/carrier.ext4"
            test -s "$carrier/carrier.hash"
            root_hash=$(cat "$carrier/carrier.root-hash")
            test "''${#root_hash}" -eq 64

            data_loop=$(${pkgs.util-linux}/bin/losetup --find --show --read-only \
              "$carrier/carrier.ext4")
            hash_loop=$(${pkgs.util-linux}/bin/losetup --find --show --read-only \
              "$carrier/carrier.hash")
            ${pkgs.cryptsetup}/sbin/veritysetup verify \
              "$data_loop" "$hash_loop" "$root_hash"
            ${pkgs.cryptsetup}/sbin/veritysetup open \
              "$data_loop" aos-mount-carrier "$hash_loop" "$root_hash"

            ${pkgs.coreutils}/bin/mkdir -p ${carrierRoot}
            ${pkgs.util-linux}/bin/mount -t ext4 -o ro,nosuid,nodev \
              /dev/mapper/aos-mount-carrier ${carrierRoot}
            test "$(${pkgs.attr}/bin/getfattr --only-values -n security.selinux \
              ${carrierRoot})" = system_u:object_r:root_t
            test "$(${pkgs.attr}/bin/getfattr --only-values -n security.selinux \
              ${carrierRoot}/launcher)" = system_u:object_r:init_exec_t
            test "$(${pkgs.attr}/bin/getfattr --only-values -n security.selinux \
              ${carrierRoot}/daemon)" = system_u:object_r:bin_t

            ${pkgs.coreutils}/bin/stat -c '%d:%i:%s' \
              ${carrierRoot}/launcher > /run/aos/mount-carrier-launcher.before
            ${pkgs.coreutils}/bin/stat -c '%d:%i:%s' \
              ${carrierRoot}/daemon > /run/aos/mount-carrier-daemon.before
            echo 'AOS Mount carrier qualification: mounted signed dm-verity carrier before switch-root'
          '';
        };
      }
    ];

  systemFor = stage0:
    systems.server-secureboot-lockdown.extendModules {
      modules = [(fixtureModule stage0)];
    };
in {
  name = "selinux-mount-carrier-handoff";
  timeout = 1800;
  bootTimeout = 300;

  machines = {
    retained = {
      system = systemFor qualificationStage0;
      bootMode = "image";
      firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
    };
    wrongHash = {
      system = systemFor wrongHashStage0;
      bootMode = "image";
      firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
      expectAgent = false;
    };
  };

  testScript = ''
    import time
    from pathlib import Path

    retained.wait_for_unit("multi-user.target")
    retained.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
    marker = retained.succeed("cat /run/aos/selinux-root-handoff")
    assert "phase=switch-root" in marker, marker

    for name in ("launcher", "daemon"):
        before = retained.succeed(f"cat /run/aos/mount-carrier-{name}.before").strip()
        after = retained.succeed(f"stat -c '%d:%i:%s' ${carrierRoot}/{name}").strip()
        assert before == after, (name, before, after)
    retained.succeed("test $(getfattr --only-values -n security.selinux ${carrierRoot}) = system_u:object_r:root_t")
    retained.succeed("${carrierRoot}/launcher --version")
    status, output = retained.execute("${carrierRoot}/daemon --help")
    assert status != 0 and "aos-sandbox-mountd:" in output, (status, output)

    retained.succeed("systemctl daemon-reexec")
    retained.wait_for_unit("multi-user.target")
    marker = retained.succeed("cat /run/aos/selinux-root-handoff")
    assert "phase=reexec" in marker, marker
    for name in ("launcher", "daemon"):
        before = retained.succeed(f"cat /run/aos/mount-carrier-{name}.before").strip()
        after = retained.succeed(f"stat -c '%d:%i:%s' ${carrierRoot}/{name}").strip()
        assert before == after, (name, before, after)

    wrongHash.start()
    deadline = time.monotonic() + 180
    serial_path = Path(wrongHash.serial_log_path)
    while time.monotonic() < deadline:
        transcript = serial_path.read_text(errors="replace") if serial_path.exists() else ""
        if "Mount carrier dm-verity root hash differs from signed stage0" in transcript:
            break
        time.sleep(1)
    else:
        raise AssertionError(f"wrong-hash handoff did not fail closed:\n{transcript[-16000:]}")
    assert "Reached target Multi-User System" not in transcript
  '';
}
