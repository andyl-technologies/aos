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
  qualificationCredentials = "/run/aos/mount-carrier-qualification";
  credentialFixture = pkgs.mkCargoPackage {
    pname = "aos-mount-carrier-credential-fixture";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos-sandbox-mountd.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --features aos-sandbox-broker-session-security/kernel-tests"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    postBuild = ''
      mkdir -p credential-fixture
      count=0
      artifact_dir="''${CARGO_TARGET_DIR:-target}/debug/deps"
      for candidate in "$artifact_dir"/aos_sandbox_broker_session_security-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" credential-fixture/mount-carrier-credential-fixture
          count=$((count + 1))
        fi
      done
      if [ "$count" -ne 1 ]; then
        echo "expected exactly one Mount credential fixture, found $count" >&2
        exit 1
      fi
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 credential-fixture/mount-carrier-credential-fixture "$out/bin/"
    '';
  };
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

  systemFor = stage0: enableMountUnit: let
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
          aos.sandbox.mountBroker = lib.mkIf enableMountUnit {
            enable = true;
            useExecutableCarrier = true;
            credentials = {
              brokerPlanPolicy = "mount-carrier-plan-policy";
              brokerPlanPublicKey = "mount-carrier-plan-public-key";
              brokerRevocationScope = "mount-carrier-revocation-scope";
              ownershipLeasePolicy = "mount-carrier-lease-policy";
              ownershipLeasePublicKey = "mount-carrier-lease-public-key";
              nodeId = "mount-carrier-node-id";
              journalMacKey = "mount-carrier-journal-mac-key";
              brokerSessionManifest = "mount-carrier-session-manifest";
              brokerSessionHelloKey = "mount-carrier-session-hello-key";
              brokerSessionOutcomeKey = "mount-carrier-session-outcome-key";
            };
          };
          environment.systemPackages =
            lib.optional enableMountUnit credentialFixture
            ++ [pkgs.attr pkgs.cryptsetup pkgs.util-linux];
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
      && (!enableMountUnit || cfg.aos.sandbox.mountBroker.useExecutableCarrier)
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
      system = systemFor qualificationStage0 true;
      bootMode = "image";
      imageDiskMiB = 16384;
      firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
    };
    wrongHash = {
      system = systemFor wrongHashStage0 false;
      bootMode = "image";
      imageDiskMiB = 16384;
      firmwareVars = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
      expectAgent = false;
    };
  };

  testScript = ''
    import time
    from pathlib import Path

    mount_unit = "aos-sandbox-mountd.service"
    carrier_daemon = "${carrierRoot}/daemon"
    credential_root = "${qualificationCredentials}"

    def install_mount_credentials():
        selected = retained.succeed(
            "${credentialFixture}/bin/mount-carrier-credential-fixture "
            "--ignored --list "
            "handshake::qualification_credentials::"
            "provision_controller_broker_credentials_after_boot"
        )
        assert (
            "handshake::qualification_credentials::"
            "provision_controller_broker_credentials_after_boot: test"
        ) in selected, selected

        output = retained.succeed(
            f"AOS_BSA_QUALIFICATION_ROOT={credential_root} "
            "${credentialFixture}/bin/mount-carrier-credential-fixture "
            "--ignored --exact "
            "handshake::qualification_credentials::"
            "provision_controller_broker_credentials_after_boot "
            "--test-threads=1 --nocapture"
        )
        assert "CONTROLLER_BROKER_CREDENTIALS_STAGED" in output, output

        source = f"{credential_root}/mount-authority"
        session = f"{credential_root}/sessions/mount/broker"
        retained.succeed("install -d -m 0700 /run/credentials/@system")
        for installed, original in (
            ("mount-carrier-plan-policy", f"{source}/broker-plan-policy.cbor"),
            ("mount-carrier-plan-public-key", f"{source}/broker-plan-public-key"),
            ("mount-carrier-revocation-scope", f"{source}/broker-revocation-scope"),
            ("mount-carrier-lease-policy", f"{source}/ownership-lease-policy.cbor"),
            ("mount-carrier-lease-public-key", f"{source}/ownership-lease-public-key"),
            ("mount-carrier-node-id", f"{source}/node-id"),
            ("mount-carrier-journal-mac-key", f"{source}/journal-mac-key"),
            ("mount-carrier-session-manifest", f"{session}/broker-session-manifest"),
            ("mount-carrier-session-hello-key", f"{session}/broker-hello-signing-key"),
            ("mount-carrier-session-outcome-key", f"{session}/broker-outcome-signing-key"),
        ):
            retained.succeed(
                f"install -m 0400 {original} /run/credentials/@system/{installed}"
            )

    def assert_mount_unit_uses_carrier():
        retained.succeed(f"systemctl start {mount_unit}", timeout=60)
        retained.wait_for_unit(mount_unit)
        pid = retained.succeed(
            f"systemctl show -P MainPID {mount_unit}"
        ).strip()
        assert pid.isdecimal() and int(pid) > 1, pid

        daemon = retained.succeed(f"stat -c '%d:%i' {carrier_daemon}").strip()
        running = retained.succeed(f"stat -Lc '%d:%i' /proc/{pid}/exe").strip()
        store = retained.succeed(
            "stat -c '%d:%i' ${pkgs.aos-sandbox-mountd}/bin/aos-sandbox-mountd"
        ).strip()
        assert running == daemon and running != store, (running, daemon, store)
        return pid, daemon

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
    install_mount_credentials()
    first_mount_pid, first_mount_inode = assert_mount_unit_uses_carrier()
    retained.succeed(f"systemctl restart {mount_unit}", timeout=60)
    restarted_pid, restarted_inode = assert_mount_unit_uses_carrier()
    assert restarted_pid != first_mount_pid, (first_mount_pid, restarted_pid)
    assert restarted_inode == first_mount_inode, (first_mount_inode, restarted_inode)

    retained.succeed("systemctl daemon-reexec")
    retained.wait_for_unit("multi-user.target")
    assert retained.succeed("stat -Lc '%d:%i' /proc/1/exe").strip() == first_boot_device_inode
    _, reexec_inode = assert_mount_unit_uses_carrier()
    assert reexec_inode == first_mount_inode, (first_mount_inode, reexec_inode)

    retained.reboot(timeout=600)
    second_boot_device_inode, second_boot_artifact = assert_carrier_pid_one()
    install_mount_credentials()
    _, second_mount_inode = assert_mount_unit_uses_carrier()
    print("carrier raw device:inode across boots:", first_boot_device_inode, second_boot_device_inode)
    print("Mount daemon raw device:inode across boots:", first_mount_inode, second_mount_inode)
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
