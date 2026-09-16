# Protected sandbox Network runtime-root qualification.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  enrolledFirmwareVars = import ./_secure-boot-enrolled-vars.nix {
    inherit lib pkgs systems;
  };
  enrolledFirmwareVarsPath = "${enrolledFirmwareVars}/enroller-OVMF_VARS.fd";
  qualificationStage0 = pkgs.aosSelinuxStage0With {admissionUnit = "";};
  runtimeRoots = pkgs.aos-selinux-runtime-roots;
  runtimeRootsBasename = builtins.baseNameOf runtimeRoots;
  libselinuxBasename = builtins.baseNameOf pkgs.libselinux;
  policyBasename = builtins.baseNameOf pkgs.aos-selinux-production-policy;

  qualificationModule = mode: {
    aos.security.selinux = {
      enable = true;
      bootMode = "immutable-stage0";
      protectedSandboxNetworkRoots.enable = true;
      _qualificationAdmissionRelease = true;
    };
    aos.sandbox.networkBroker.enable = true;
    aos.services.dbus.enable = true;
    aos.boot.initrd.stage0 = lib.mkForce qualificationStage0;
    aos.image.erofsCompressionLevel = 1;

    boot.initrd.systemd.services.aos-protected-root-adversary = lib.mkIf (mode == "shadows") {
      description = "Shadow logical protected-root executables before switch-root";
      requiredBy = ["initrd-switch-root.target"];
      requires = [
        "mount-var.service"
        "nix-overlay-setup.service"
        "etc-overlay-setup.service"
      ];
      after = [
        "mount-var.service"
        "nix-overlay-setup.service"
        "etc-overlay-setup.service"
      ];
      before = ["initrd-switch-root.target"];
      serviceConfig = {
        Type = "oneshot";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        set -eu

        printf 'AOS_SHADOWED_RUNTIME_ROOTS\n' > /run/shadow-runtime-roots
        printf 'AOS_SHADOWED_LIBSELINUX\n' > /run/shadow-libselinux
        printf 'AOS_SHADOWED_POLICY\n' > /run/shadow-policy
        chmod 0555 /run/shadow-runtime-roots /run/shadow-libselinux
        chmod 0444 /run/shadow-policy

        ${pkgs.util-linux}/bin/mount --bind \
          /run/shadow-runtime-roots \
          /sysroot/nix/store/${runtimeRootsBasename}/bin/aos-selinux-runtime-roots
        ${pkgs.util-linux}/bin/mount --bind \
          /run/shadow-libselinux \
          /sysroot/nix/store/${libselinuxBasename}/lib/libselinux.so.1
        ${pkgs.util-linux}/bin/mount --bind \
          /run/shadow-policy \
          /sysroot/nix/store/${policyBasename}/etc/selinux/aos/policy/policy.33
        echo "AOS protected-root adversary: helper DSO and policy shadowed"
      '';
    };

    systemd.services.aos-protected-root-submount-adversary = lib.mkIf (mode == "submount") {
      description = "Replace /var/lib with a qualification-only submount";
      requiredBy = ["sysinit.target"];
      requires = ["var.mount"];
      after = ["var.mount"];
      before = ["aos-sandbox-network-roots.service" "sysinit.target"];
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        set -eu

        mkdir -p /run/aos-protected-root-submount
        ${pkgs.util-linux}/bin/mount --bind \
          /run/aos-protected-root-submount /var/lib
        echo "AOS protected-root adversary: /var/lib submount installed"
      '';
    };
  };

  systemFor = mode:
    systems.server-secureboot-lockdown.extendModules {
      modules = [(qualificationModule mode)];
    };
  protectedSystem = systemFor "shadows";
  submountSystem = systemFor "submount";
  protectedConfig = protectedSystem.config;
in
  assert protectedConfig.aos.security.selinux.protectedSandboxNetworkRoots.enable;
  assert protectedConfig.aos.security.selinux.bootMode == "immutable-stage0";
  assert protectedConfig.aos.security.selinux.mode == "enforcing";
  assert protectedConfig.aos.security.selinux.policy == "aos";
  assert protectedConfig.aos.sandbox.networkBroker.enable;
  assert protectedConfig.aos.boot.secureBoot.enable;
  assert protectedConfig.aos.boot.secureBoot.lockdown.enable;
  assert protectedConfig.aos.filesystems.rootFsType == "erofs";
  assert !protectedConfig.aos.filesystems.zfs.enable;
  assert protectedConfig.aos.boot.initrd.stage0 == qualificationStage0;
  assert protectedConfig.aos.boot.initrd.stage0.passthru.admissionUnit == "";
  assert protectedConfig.aos.boot.initrd.stage0.passthru.loadedPolicy == "${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  assert protectedConfig.aos.boot.initrd.stage0.passthru.runtimeRootsProvisioner == runtimeRoots;
  # `+` restores root credentials for this systemd-spawned preflight; the
  # labeled helper still performs the only SELinux domain transition.
  assert protectedConfig.systemd.services.aos-netd.serviceConfig.ExecStartPre
  == [
    "+/usr/lib/systemd/aos-selinux-root-handoff --launch-runtime-roots ${runtimeRoots}/bin/aos-selinux-runtime-roots --root / --prepare-sandbox-network-roots"
  ]; {
    name = "selinux-protected-network-roots";
    timeout = 2400;
    bootTimeout = 300;

    machines = {
      protected = {
        system = protectedSystem;
        bootMode = "image";
        firmwareVars = enrolledFirmwareVarsPath;
      };
      submount = {
        system = submountSystem;
        bootMode = "image";
        firmwareVars = enrolledFirmwareVarsPath;
        expectAgent = false;
      };
    };

    testScript =
      # python
      ''
        import time
        from pathlib import Path

        ROOTS = {
            "/var": ("755", "var_t"),
            "/var/lib": ("755", "var_lib_t"),
            "/var/lib/aos": ("755", "var_lib_t"),
            "/var/lib/aos/sandbox-network": (
                "700",
                "aos_sandbox_network_root_t",
            ),
            "/var/lib/aos/sandbox-network/broker-state": (
                "700",
                "aos_sandbox_network_state_t",
            ),
            "/var/lib/aos/sandbox-network/namespace-inspector": (
                "700",
                "aos_sandbox_network_store_t",
            ),
            "/var/lib/aos/sandbox-network/namespace-inspector/expected-staging": (
                "700",
                "aos_sandbox_network_expected_staging_t",
            ),
            "/var/lib/aos/sandbox-network/namespace-inspector/expected-final": (
                "700",
                "aos_sandbox_network_expected_final_t",
            ),
            "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging": (
                "700",
                "aos_sandbox_network_spent_staging_t",
            ),
            "/var/lib/aos/sandbox-network/namespace-inspector/spent-final": (
                "700",
                "aos_sandbox_network_spent_final_t",
            ),
        }

        def await_serial(machine, marker):
            deadline = time.monotonic() + 180
            transcript = ""
            stable_since = None
            serial_log = Path(machine.serial_log_path)

            while time.monotonic() < deadline:
                if serial_log.exists():
                    observed = serial_log.read_text(errors="replace")
                    if marker in observed:
                        if observed != transcript:
                            transcript = observed
                            stable_since = time.monotonic()
                        elif stable_since is not None and time.monotonic() - stable_since >= 3:
                            return transcript
                time.sleep(1)

            raise AssertionError(
                f"timed out waiting for {marker!r}:\n{transcript[-16000:]}"
            )

        def identities(machine):
            observed = {}
            var_device = machine.succeed("stat -c %d /var").strip()
            var_mount = machine.succeed("findmnt -n -o ID -T /var").strip()

            for path, (mode, type_name) in ROOTS.items():
                fields = machine.succeed(
                    f"stat -c '%u|%g|%a|%C|%d|%i' {path}"
                ).strip().split("|")
                assert fields[0:3] == ["0", "0", mode], (path, fields)
                assert fields[3].split(":", 3)[2] == type_name, (path, fields)
                assert fields[4] == var_device, (path, fields, var_device)
                assert machine.succeed(
                    f"findmnt -n -o ID -T {path}"
                ).strip() == var_mount
                observed[path] = (fields[4], fields[5])

            return observed

        protected.wait_for_unit("multi-user.target")
        protected.wait_for_unit("aos-sandbox-network-roots.service")
        protected.wait_for_unit("aos-netd.socket")
        initial = identities(protected)

        protected.succeed("systemctl restart aos-sandbox-network-roots.service")
        assert identities(protected) == initial

        protected.succeed("systemctl restart aos-netd.service")
        protected.succeed("systemctl restart aos-netd.service")
        assert identities(protected) == initial
        evidence = protected.succeed(
            "journalctl -b -u aos-sandbox-network-roots.service "
            "-u aos-netd.service --no-pager"
        )
        assert evidence.count("verified --prepare-sandbox-network-roots") >= 4
        protected.succeed(
            "! grep -q AOS_SHADOWED_RUNTIME_ROOTS "
            "/nix/store/${runtimeRootsBasename}/bin/aos-selinux-runtime-roots"
        )
        protected.succeed(
            "! grep -q AOS_SHADOWED_POLICY "
            "/etc/selinux/aos/policy/policy.33"
        )

        failure = await_serial(
            submount,
            "cannot open '/var/lib' without aliases or mount crossings",
        )
        assert "/var/lib submount installed" in failure
        assert "aos-netd.socket" in failure
        assert "Started AOS authenticated sandbox Network inventory broker" not in failure
      '';
  }
