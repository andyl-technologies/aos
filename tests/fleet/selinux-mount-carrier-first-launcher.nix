# Signed-initrd carrier as the first systemd inode under enforcing SELinux.
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
    mountCarrierFirstLauncher = true;
  };
  wrongHash = pkgs.runCommand "mount-carrier-wrong-first-launcher-hash" {} ''
    mkdir -p "$out"
    printf '%064d\n' 0 > "$out/carrier.root-hash"
  '';
  wrongHashStage0 = pkgs.aosSelinuxStage0With {
    admissionUnit = "";
    mountExecutableCarrier = wrongHash;
    mountCarrierFirstLauncher = true;
  };

  systemFor = stage0: let
    system = systems.server-secureboot-lockdown.extendModules {
      modules = [
        (stage0Fixture stage0)
        {
          aos.image.erofsCompressionLevel = 1;
          aos.image.budgets.maxEspMiB = 896;
          aos.image.budgets.maxRootMiB = 896;
          aos.image.budgets.maxInitrdMiB = 256;
          aos.image.budgets.maxUkiMiB = 288;
          aos.image.budgets.maxDownloadMiB = 1536;
          aos.image.budgets.maxRuntimeClosureMiB = 1024;
          boot.initrd.systemd.mountExecutableCarrier = carrier;
          environment.systemPackages = [pkgs.attr pkgs.cryptsetup pkgs.util-linux];
        }
      ];
    };
    cfg = system.config;
  in
    if
      toString cfg.aos.boot.initrd.stage0
      == toString stage0
      && toString cfg.boot.initrd.systemd.mountExecutableCarrier == toString carrier
      && cfg.aos.image.budgets.maxRootMiB == 896
      && cfg.aos.image.budgets.maxInitrdMiB == 256
      && cfg.aos.image.budgets.maxUkiMiB == 288
      && cfg.aos.image.budgets.maxDownloadMiB == 1536
      && cfg.aos.image.budgets.maxRuntimeClosureMiB == 1024
      && builtins.elem "selinux=1" cfg.aos.boot.kernelParams
      && builtins.elem "enforcing=1" cfg.aos.boot.kernelParams
      && builtins.elem "aos.selinux.root_handoff=1" cfg.aos.boot.kernelParams
    then system
    else throw "Mount first-launcher fixture lost its stage0, signed carrier, bounded image budgets, or enforcing kernel parameters";
in {
  name = "selinux-mount-carrier-first-launcher";
  timeout = 2400;
  bootTimeout = 300;

  machines = {
    retained = {
      system = systemFor qualificationStage0;
      bootMode = "image";
      imageDiskMiB = 16384;
      firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
    };
    wrongHash = {
      system = systemFor wrongHashStage0;
      bootMode = "image";
      imageDiskMiB = 16384;
      firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
      expectAgent = false;
    };
  };

  testScript = ''
    import time
    from pathlib import Path

    def assert_carrier_pid_one():
        retained.wait_for_unit("multi-user.target")
        retained.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
        marker_status, marker_output, marker_error = retained.execute("cat /run/aos/selinux-root-handoff")
        marker = marker_output.decode(errors="replace")
        if marker_status != 0:
            for command in (
                "cat /proc/cmdline",
                "readlink /proc/1/exe",
                "systemctl --failed --no-pager",
                "systemctl status initrd-switch-root.service --no-pager -l",
                "${pkgs.util-linux}/bin/findmnt -R /run/aos",
                "journalctl -b -n 120 --no-pager -o short-monotonic",
            ):
                status, output, error = retained.execute(command)
                print(
                    f"handoff diagnostic: {command}: status={status}\n"
                    f"{output.decode(errors='replace')}{error.decode(errors='replace')}"
                )
            raise AssertionError(
                f"switch-root handoff marker is absent: {marker_error.decode(errors='replace')}"
            )
        assert "phase=switch-root" in marker, marker
        assert "systemd=${carrierRoot}/launcher" in marker, marker

        launcher = retained.succeed("stat -c '%d:%i' ${carrierRoot}/launcher").strip()
        pid_one = retained.succeed("stat -Lc '%d:%i' /proc/1/exe").strip()
        assert launcher == pid_one, (launcher, pid_one)
        retained.succeed("test $(${pkgs.attr}/bin/getfattr --only-values -n security.selinux ${carrierRoot}) = system_u:object_r:root_t")
        retained.succeed("${carrierRoot}/launcher --version")
        status, output, error = retained.execute("${carrierRoot}/daemon --help")
        daemon_output = (output + error).decode(errors="replace")
        assert status != 0 and "aos-sandbox-mountd:" in daemon_output, (status, daemon_output)

        stable_artifact = (
            retained.succeed("stat -c '%i' ${carrierRoot}/launcher").strip(),
            retained.succeed("sha256sum ${carrierRoot}/launcher").split()[0],
            retained.succeed("sha256sum ${carrierRoot}/daemon").split()[0],
        )
        return launcher, stable_artifact

    first_boot_device_inode, first_boot_artifact = assert_carrier_pid_one()
    retained.succeed("systemctl daemon-reexec")
    retained.wait_for_unit("multi-user.target")
    assert retained.succeed("stat -Lc '%d:%i' /proc/1/exe").strip() == first_boot_device_inode

    retained.reboot(timeout=600)
    second_boot_device_inode, second_boot_artifact = assert_carrier_pid_one()
    print("carrier raw device:inode across boots:", first_boot_device_inode, second_boot_device_inode)
    assert first_boot_artifact == second_boot_artifact, (
        first_boot_artifact, second_boot_artifact
    )

    deadline = time.monotonic() + 180
    serial_path = Path(wrongHash.serial_log_path)
    while time.monotonic() < deadline:
        transcript = serial_path.read_text(errors="replace") if serial_path.exists() else ""
        if "signed stage1 carrier hash differs from stage0 executable authority" in transcript:
            break
        time.sleep(1)
    else:
        raise AssertionError(f"wrong-hash first launcher did not fail closed:\n{transcript[-16000:]}")
    assert "policy exact and enforcing" not in transcript
  '';
}
