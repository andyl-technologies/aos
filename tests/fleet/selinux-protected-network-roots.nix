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
  runtimeRoots = pkgs.aosSelinuxRuntimeRootsForKernel protectedConfig.system.build.kernel;
  runtimeRootsBasename = builtins.baseNameOf runtimeRoots;
  netdBasename = builtins.baseNameOf pkgs.aos-netd;
  libselinuxBasename = builtins.baseNameOf pkgs.libselinux;
  policyBasename = builtins.baseNameOf pkgs.aos-selinux-production-policy;
  inspectorLookalike = pkgs.mkDerivation {
    pname = "aos-netd";
    version = pkgs.aos-netd.version;
    src = ../sandbox/inspector-lookalike.c;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror "$src" \
            -o aos-sandbox-network-namespace-inspector
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp aos-sandbox-network-namespace-inspector "$out/bin/"
        '';
      }
    ];
  };
  inspectorLookalikeBasename = builtins.baseNameOf inspectorLookalike;
  inspectorSocketConnector = pkgs.mkDerivation {
    pname = "aos-inspector-socket-connect";
    version = "1";
    src = ../sandbox/inspector-socket-connect.c;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror "$src" \
            -o aos-inspector-socket-connect
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp aos-inspector-socket-connect "$out/bin/"
        '';
      }
    ];
  };
  qualificationModule = mode: {config, ...}: {
    aos.security.selinux = {
      enable = true;
      bootMode = "immutable-stage0";
      protectedSandboxNetworkRoots.enable = true;
      _qualificationAdmissionRelease = true;
    };
    aos.sandbox.networkBroker.enable = true;
    aos.sandbox.networkWorker.enable = true;
    aos.services.dbus.enable = true;
    aos.boot.initrd.stage0 = lib.mkForce (pkgs.aosSelinuxStage0With {
      admissionUnit = "";
      expectedPolicy = "${pkgs.aosSelinuxKernelPolicyReadbackForKernel config.system.build.kernel}/policy.33";
      expectedPolicyKernel = config.system.build.kernel;
      aos-selinux-runtime-roots = pkgs.aosSelinuxRuntimeRootsForKernel config.system.build.kernel;
    });
    aos.image.erofsCompressionLevel = 1;
    # These secure-boot test images retain the full Network runtime and test
    # artifacts. Keep their artifact headroom local to this fixture.
    aos.image.budgets.maxRootMiB = 768;
    aos.image.budgets.maxInitrdMiB = 224;
    aos.image.budgets.maxUkiMiB = 240;
    aos.image.budgets.maxEspMiB = 704;
    aos.image.budgets.maxRuntimeClosureMiB = 896;
    aos.image.budgets.maxDownloadMiB = 1024;
    aos.image.testArtifactRoots =
      [pkgs.attr]
      ++ lib.optionals (builtins.elem mode ["shadows" "unit-overrides"]) [inspectorSocketConnector];
    environment.systemPackages =
      [pkgs.attr pkgs.grep pkgs.util-linux]
      ++ lib.optionals (builtins.elem mode ["shadows" "unit-overrides"]) [inspectorLookalike inspectorSocketConnector];

    # This fixture needs no configuration-generation replacement. Keep its
    # control channel in one unit so enforcing init_t never needs the broad
    # manager reload permission used by the generic fleet bootstrap.
    systemd.services.aos-test-agent-bootstrap = lib.mkIf (builtins.elem mode ["shadows" "unit-overrides"]) {
      environment.PATH = "${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.attr}/bin:${pkgs.grep}/bin:${pkgs.util-linux}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
      serviceConfig.Type = lib.mkForce "simple";
      serviceConfig.Restart = "on-failure";
      serviceConfig.RestartSec = 1;
      script = lib.mkForce ''
        exec ${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent
      '';
    };

    systemd.services.aos-inspector-lookalike = lib.mkIf (mode == "shadows") {
      description = "Adversarial same-name Network inspector executable";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${inspectorLookalike}/bin/aos-sandbox-network-namespace-inspector";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    # This qualification-only socket launches the exact production ELF without
    # credentials. Reaching its credential guard proves the enforcing MAC
    # transition and guarded socket activation without admitting inspection.
    systemd.sockets.aos-sandbox-network-namespace-inspector = lib.mkIf (builtins.elem mode ["shadows" "unit-overrides"]) {
      description = "Qualification-only Network inspector activation socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-network-namespace-inspector/control.sock";
        Accept = true;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
      };
    };

    systemd.services."aos-sandbox-network-namespace-inspector@" = lib.mkIf (builtins.elem mode ["shadows" "unit-overrides"]) {
      description = "Qualification-only Network inspector MAC transition";
      unitConfig.CollectMode = "inactive-or-failed";
      serviceConfig = {
        Type = "exec";
        ExecStart = "${pkgs.aos-netd}/bin/aos-sandbox-network-namespace-inspector";
        BindReadOnlyPaths = ["/nix.lower/store:/nix/store"];
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal+console";
        RuntimeMaxSec = "5s";
        User = "root";
        Group = "root";
        CapabilityBoundingSet = [];
        AmbientCapabilities = [];
        NoNewPrivileges = true;
        PrivateNetwork = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        UnsetEnvironment = ["CREDENTIALS_DIRECTORY"];
      };
    };

    boot.initrd.systemd.services.aos-protected-root-adversary = lib.mkIf (mode == "shadows") {
      description = "Shadow logical protected-root executables before switch-root";
      wantedBy = ["initrd-fs.target"];
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
      before = ["initrd-fs.target"];
      unitConfig.DefaultDependencies = "no";
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
        ${pkgs.coreutils}/bin/chmod 0555 /run/shadow-runtime-roots /run/shadow-libselinux
        ${pkgs.coreutils}/bin/chmod 0444 /run/shadow-policy

        if ${pkgs.util-linux}/bin/mount --bind \
          /run/shadow-runtime-roots \
          /sysroot/nix/store/${runtimeRootsBasename}/bin/aos-selinux-runtime-roots; then
          echo "AOS protected-root adversary unexpectedly shadowed helper" >&2
          exit 1
        fi
        ${pkgs.util-linux}/bin/mount --bind \
          /run/shadow-libselinux \
          /sysroot/nix/store/${libselinuxBasename}/lib/libselinux.so.1
        ${pkgs.util-linux}/bin/mount --bind \
          /run/shadow-policy \
          /sysroot/nix/store/${policyBasename}/etc/selinux/aos/policy/policy.33
        ${pkgs.grep}/bin/grep -q AOS_SHADOWED_LIBSELINUX \
          /sysroot/nix/store/${libselinuxBasename}/lib/libselinux.so.1
        ${pkgs.grep}/bin/grep -q AOS_SHADOWED_POLICY \
          /sysroot/nix/store/${policyBasename}/etc/selinux/aos/policy/policy.33
        echo "AOS protected-root adversary: helper bind denied; DSO and policy shadowed"
      '';
    };

    # Place hostile drop-ins in the persistent /etc lower before stage-2 PID 1
    # loads any Network service. Their privileged prestart markers must not run.
    boot.initrd.systemd.services.aos-protected-unit-adversary = lib.mkIf (mode == "unit-overrides") {
      description = "Seed mutable Network unit drop-ins before switch-root";
      wantedBy = ["initrd-fs.target"];
      requires = ["aos-seed-profiles.service" "mount-var.service"];
      after = ["aos-seed-profiles.service" "mount-var.service"];
      before = ["etc-overlay-setup.service" "initrd-fs.target"];
      unitConfig.DefaultDependencies = "no";
      serviceConfig.Type = "oneshot";
      script = ''
        set -eu
        for unit in aos-netd.service \
          aos-sandbox-network-namespace-inspector@.service \
          aos-sandbox-network-lifecycle-worker@.service; do
          directory="/sysroot/var/etc/systemd/system/$unit.d"
          mkdir -p "$directory"
          printf '[Service]\nExecStartPre=+${pkgs.coreutils}/bin/touch /run/aos-forbidden-network-prestart\n' \
            > "$directory/override.conf"
        done

        # A dependency add-on must be rejected before it can queue a second
        # service, even when the protected fragment itself is image-pinned.
        dependency_unit=/sysroot/var/etc/systemd/system/aos-network-dependency-marker.service
        printf '[Service]\nType=oneshot\nExecStart=${pkgs.coreutils}/bin/touch /run/aos-forbidden-network-dependency\n' \
          > "$dependency_unit"
        mkdir -p /sysroot/var/etc/systemd/system/aos-netd.service.wants
        ln -s ../aos-network-dependency-marker.service \
          /sysroot/var/etc/systemd/system/aos-netd.service.wants/aos-network-dependency-marker.service
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
  overriddenSystem = systemFor "unit-overrides";
  protectedConfig = protectedSystem.config;
  protectedMeasuredConfig =
    (systems.server-verity.extendModules {
      modules = [(qualificationModule "shadows")];
    }).config;
  protectedMeasuredVarCrypt = protectedMeasuredConfig.boot.initrd.systemd.services."aos-var-crypt".script;
  brokerPackageOverride = protectedSystem.extendModules {
    modules = [{aos.sandbox.networkBroker.package = lib.mkForce inspectorLookalike;}];
  };
  workerPackageOverride = protectedSystem.extendModules {
    modules = [{aos.sandbox.networkWorker.package = lib.mkForce inspectorLookalike;}];
  };
  brokerStoreBindOverride = protectedSystem.extendModules {
    modules = [
      {
        systemd.services.aos-netd.serviceConfig.BindReadOnlyPaths = lib.mkForce ["/nix/store"];
      }
    ];
  };
  packageOverrideRejected = system:
    builtins.any
    (assertion:
      !assertion.assertion
      && assertion.message == "protected SELinux Network roots require the broker and worker from the exact policy-labeled aos-netd package")
    system.config.assertions;
in
  assert protectedConfig.aos.security.selinux.protectedSandboxNetworkRoots.enable;
  assert protectedConfig.aos.security.selinux.bootMode == "immutable-stage0";
  assert protectedConfig.aos.security.selinux.mode == "enforcing";
  assert protectedConfig.aos.security.selinux.policy == "aos";
  assert protectedConfig.aos.sandbox.networkBroker.enable;
  assert toString protectedConfig.aos.sandbox.networkBroker.package == toString pkgs.aos-netd;
  assert inspectorLookalike.version == pkgs.aos-netd.version;
  assert toString inspectorLookalike != toString pkgs.aos-netd;
  assert packageOverrideRejected brokerPackageOverride;
  assert packageOverrideRejected workerPackageOverride;
  assert protectedConfig.systemd.services.aos-netd.serviceConfig.BindReadOnlyPaths == ["/nix.lower/store:/nix/store"];
  assert protectedConfig.systemd.services."aos-sandbox-network-lifecycle-worker@".serviceConfig.BindReadOnlyPaths == ["/nix.lower/store:/nix/store"];
  assert builtins.any
  (assertion:
    !assertion.assertion
    && assertion.message == "aos-netd.service must execute against the exact immutable lower-store view")
  brokerStoreBindOverride.config.assertions;
  assert protectedConfig.aos.boot.secureBoot.enable;
  assert protectedConfig.aos.boot.secureBoot.lockdown.enable;
  assert protectedMeasuredConfig.aos.boot.secureBoot.measuredBoot.enable;
  assert lib.hasInfix ''"$mkfs" -q -L var -E root_selinux=system_u:object_r:var_t "$dev"'' protectedMeasuredVarCrypt;
  assert lib.hasInfix ''"$mkfs" -q -L var -E root_selinux=system_u:object_r:var_t /dev/mapper/var'' protectedMeasuredVarCrypt;
  assert lib.hasInfix ''plain /var root lacks its durable exact SELinux label'' protectedMeasuredVarCrypt;
  assert lib.hasInfix ''preserving existing plain ext4 /var'' protectedMeasuredVarCrypt;
  assert protectedConfig.aos.filesystems.rootFsType == "erofs";
  assert !protectedConfig.aos.filesystems.zfs.enable;
  assert protectedConfig.aos.boot.initrd.stage0.passthru.admissionUnit == "";
  assert protectedConfig.aos.boot.initrd.stage0.passthru.loadedPolicy == "${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  assert protectedConfig.aos.boot.initrd.stage0.passthru.expectedPolicy == "${pkgs.aosSelinuxKernelPolicyReadbackForKernel protectedConfig.system.build.kernel}/policy.33";
  assert runtimeRoots.passthru.expectedPolicyReadback == protectedConfig.aos.boot.initrd.stage0.passthru.expectedPolicy;
  assert protectedConfig.aos.boot.initrd.stage0.passthru.expectedPolicyKernel == protectedConfig.system.build.kernel;
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
      overridden = {
        system = overriddenSystem;
        bootMode = "image";
        firmwareVars = enrolledFirmwareVarsPath;
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
                    f"stat -c '%u|%g|%a|%d|%i' {path}"
                ).strip().split("|")
                assert fields[0:3] == ["0", "0", mode], (path, fields)
                raw_label = machine.succeed(
                    f"${pkgs.attr}/bin/getfattr -n security.selinux "
                    f"--only-values {path}"
                ).strip("\x00\n")
                assert raw_label.split(":", 3)[2] == type_name, (path, raw_label)
                assert fields[3] == var_device, (path, fields, var_device)
                assert machine.succeed(
                    f"findmnt -n -o ID -T {path}"
                ).strip() == var_mount
                observed[path] = (fields[3], fields[4])

            return observed

        def assert_private_lower_store(machine, pid, executable):
            mountinfo = machine.succeed(f"cat /proc/{pid}/mountinfo")
            store_mounts = [
                line.split(" - ", 1)
                for line in mountinfo.splitlines()
                if line.split()[4] == "/nix/store"
            ]
            assert len(store_mounts) == 1, store_mounts
            mount, filesystem = store_mounts[0]
            fields = mount.split()
            options = set(fields[5].split(","))
            assert fields[3] == "/nix.lower/store", fields
            assert filesystem.split()[0] == "erofs", filesystem
            assert {"ro", "nodev"} <= options, options
            assert "nosuid" not in options and "noexec" not in options, options

            private_executable = f"/proc/{pid}/root/nix/store/${netdBasename}/bin/{executable}"
            physical_executable = f"/nix.lower/store/${netdBasename}/bin/{executable}"
            identities = machine.succeed(
                f"stat -Lc '%d:%i' {private_executable} {physical_executable}"
            ).splitlines()
            assert len(identities) == 2 and identities[0] == identities[1], identities

            # An upper-layer shadow is visible in the host's logical store,
            # but cannot replace bytes resolved by this service's loader.
            shadowed = "/nix/store/${libselinuxBasename}/lib/libselinux.so.1"
            private_shadowed = f"/proc/{pid}/root{shadowed}"
            machine.succeed(f"grep -q AOS_SHADOWED_LIBSELINUX {shadowed}")
            machine.fail(f"grep -q AOS_SHADOWED_LIBSELINUX {private_shadowed}")
            private_dso = machine.succeed(
                f"stat -Lc '%d:%i' {private_shadowed} "
                "/nix.lower/store/${libselinuxBasename}/lib/libselinux.so.1"
            ).splitlines()
            assert len(private_dso) == 2 and private_dso[0] == private_dso[1], private_dso

        boot_log = await_serial(
            protected,
            "Finished Prepare protected AOS sandbox Network roots",
        )
        assert "helper bind denied; DSO and policy shadowed" in boot_log
        await_serial(protected, "Reached target Multi-User System")
        protected.wait_until_succeeds("test -S /run/aos/sandbox-network/control.sock")
        protected.wait_until_succeeds(
            "test -S /run/aos/sandbox-network-namespace-inspector/control.sock"
        )
        assert protected.succeed("cat /sys/fs/selinux/enforce").strip() == "1"
        root_mount = protected.succeed(
            "${pkgs.util-linux}/bin/findmnt -n -o ID -T /"
        ).strip()
        lower_store_mount = protected.succeed(
            "${pkgs.util-linux}/bin/findmnt -n -o ID -T /nix.lower/store"
        ).strip()
        assert root_mount == lower_store_mount, (root_mount, lower_store_mount)
        assert protected.succeed(
            "${pkgs.attr}/bin/getfattr -n security.selinux --only-values /var"
        ).strip("\x00\n") == "system_u:object_r:var_t"
        expected_label = protected.succeed(
            "${pkgs.attr}/bin/getfattr -n security.selinux --only-values "
            "/nix.lower/store/${netdBasename}/bin/"
            "aos-sandbox-network-namespace-inspector"
        ).strip("\x00\n")
        lookalike_label = protected.succeed(
            "${pkgs.attr}/bin/getfattr -n security.selinux --only-values "
            "/nix.lower/store/${inspectorLookalikeBasename}/bin/"
            "aos-sandbox-network-namespace-inspector"
        ).strip("\x00\n")
        assert expected_label.split(":", 3)[2] == "aos_sandbox_namespace_inspector_exec_t"
        assert lookalike_label.split(":", 3)[2] != "aos_sandbox_namespace_inspector_exec_t"
        lookalike_output = protected.succeed(
            "${inspectorLookalike}/bin/aos-sandbox-network-namespace-inspector"
        )
        assert "AOS_LOOKALIKE_CONTEXT=" in lookalike_output
        assert "aos_sandbox_namespace_inspector_t" not in lookalike_output

        protected.succeed("${inspectorSocketConnector}/bin/aos-inspector-socket-connect")
        await_serial(
            protected,
            "CREDENTIALS_DIRECTORY is absent",
        )
        protected.succeed(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect --lifecycle"
        )
        protected.wait_until_succeeds(
            "journalctl -b -o cat --no-pager | "
            "grep -F 'aos-sandbox-network-lifecycle-worker:'",
            timeout=30,
        )
        initial = identities(protected)

        # Socket activation must run the production broker's preflight, then
        # leave its actual labeled executable serving beyond the connection.
        broker_process = (
            "for process in /proc/[0-9]*; do "
            "test \"$(cat \"$process/comm\" 2>/dev/null)\" = aos-netd || continue; "
            "grep -q aos_sandbox_network_publisher_t \"$process/attr/current\" || continue; "
            "test \"$(readlink \"$process/exe\")\" = "
            "${pkgs.aos-netd}/bin/aos-netd && exit 0; "
            "done; exit 1"
        )
        protected.succeed(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect --broker"
        )
        # systemd reports Started only after the exact asserted ExecStartPre
        # has succeeded; the live domain/exe probe also rejects 203/EXEC.
        await_serial(
            protected,
            "Started AOS authenticated sandbox Network inventory broker",
        )
        protected.wait_until_succeeds(broker_process, timeout=30)
        broker_pid = protected.succeed("systemctl show -P MainPID aos-netd.service").strip()
        assert broker_pid.isdecimal() and broker_pid != "0", broker_pid
        assert_private_lower_store(protected, broker_pid, "aos-netd")
        time.sleep(2)
        protected.succeed(broker_process)

        root_handoff = (
            "/usr/lib/systemd/aos-selinux-root-handoff --launch-runtime-roots "
            "${runtimeRoots}/bin/aos-selinux-runtime-roots --root / "
            "--prepare-sandbox-network-roots"
        )
        protected.succeed(root_handoff)
        protected.succeed(root_handoff)
        assert identities(protected) == initial
        protected.succeed("sync")
        shutdown_status, _, _ = protected.agent.shutdown()
        assert shutdown_status == 0
        assert protected.qemu_proc.wait(timeout=120) == 0
        protected.relaunch_with_smbios_oem_strings([])
        assert identities(protected) == initial
        protected.succeed(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect --broker"
        )
        protected.wait_until_succeeds(broker_process, timeout=30)
        protected.succeed(
            "! grep -q AOS_SHADOWED_POLICY "
            "/etc/selinux/aos/policy/policy.33"
        )
        protected.succeed(
            "cmp -s /etc/selinux/aos/policy/policy.33 "
            "/nix.lower/store/${policyBasename}/etc/selinux/aos/policy/policy.33"
        )

        failure = await_serial(
            submount,
            "Failed to start Prepare protected AOS sandbox Network roots",
        )
        assert "/var/lib submount installed" in failure
        assert "aos-netd.socket" in failure
        assert "Started AOS authenticated sandbox Network inventory broker" not in failure

        overridden.wait_for_unit("multi-user.target", timeout=180)
        overridden.succeed("test -f /etc/systemd/system/aos-netd.service.d/override.conf")
        overridden.execute(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect --broker"
        )
        overridden.execute(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect"
        )
        overridden.execute(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect --lifecycle"
        )
        for unit, refusal in (
            ("aos-netd.service", "Refusing Network unit dependency drop-ins"),
            (
                "aos-sandbox-network-namespace-inspector@*.service",
                "Refusing Network unit configuration drop-ins",
            ),
            (
                "aos-sandbox-network-lifecycle-worker@*.service",
                "Refusing Network unit configuration drop-ins",
            ),
        ):
            overridden.wait_until_succeeds(
                "journalctl -b -u '{}' -o cat --no-pager | grep -Fq '{}'".format(
                    unit, refusal
                ),
                timeout=30,
            )
        overridden.fail("test -e /run/aos-forbidden-network-prestart")
        overridden.fail("test -e /run/aos-forbidden-network-dependency")
        fragment = overridden.succeed(
            "systemctl show -P FragmentPath aos-netd.service"
        ).strip()
        assert fragment.startswith("/nix/store/"), fragment
      '';
  }
