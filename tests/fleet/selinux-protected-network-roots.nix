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
    # artifacts. The largest enforcing variant exceeds 768 MiB; keep its
    # headroom local to this fixture and below the 1 GiB root partition.
    aos.image.budgets.maxRootMiB = 800;
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

    # This unprotected service proves that mutable manager environment reaches
    # ordinary units in the same enforcing VM.
    systemd.services.aos-network-manager-environment-control = lib.mkIf (mode == "shadows") {
      description = "Qualification control for mutable manager environment";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/printenv AOS_NETWORK_MANAGER_SENTINEL";
        StandardOutput = "journal";
        StandardError = "journal";
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
        # Keep loader failures visible when stage-2 journald is unavailable.
        StandardError = "kmsg+console";
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
        # /run survives switch-root; serial output can be lost if journald fails.
        printf 'helper bind denied; DSO and policy shadowed\n' \
          > /run/aos-protected-root-adversary.ok
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
  assert protectedConfig.systemd.services.systemd-journald.requires == ["aos-journald-runtime-prep.service"];
  assert protectedConfig.systemd.services.systemd-journald.after == ["aos-journald-runtime-prep.service"];
  assert !(protectedConfig.systemd.services.systemd-journald.serviceConfig ? RestrictSUIDSGID);
  assert protectedConfig.systemd.services.aos-journald-runtime-prep.serviceConfig.ExecStart
  == ''${pkgs.systemd}/bin/systemd-tmpfiles --create --inline "d /run/log/journal 2755 root systemd-journal -" "d /run/log/journal/%%m 2750 root systemd-journal -"'';
  assert protectedConfig.systemd.services."aos-sandbox-network-namespace-inspector@".serviceConfig.StandardInput == "socket";
  assert protectedConfig.systemd.services."aos-sandbox-network-namespace-inspector@".serviceConfig.StandardOutput == "socket";
  assert protectedConfig.systemd.services."aos-sandbox-network-namespace-inspector@".serviceConfig.StandardError == "kmsg+console";
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
        import json
        import re
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

        def journald_pids(machine):
            command = (
                "for process in /proc/[0-9]*; do "
                "case \"$(readlink \"$process/exe\" 2>/dev/null)\" in "
                "*/lib/systemd/systemd-journald) basename \"$process\";; "
                "esac; done"
            )
            return machine.succeed(command).splitlines()

        def wait_for_journald_restart(machine, old_pid):
            deadline = time.monotonic() + 30

            while time.monotonic() < deadline:
                pids = journald_pids(machine)
                if len(pids) == 1 and pids[0] != old_pid:
                    return pids[0]
                time.sleep(1)

            raise AssertionError(f"journald did not restart from PID {old_pid}")

        def assert_stage2_journal(machine):
            machine_id = machine.succeed("cat /etc/machine-id").strip()
            assert re.fullmatch(r"[0-9a-f]{32}", machine_id), machine_id

            # The flush to persistent storage removes the runtime child, so
            # inspect the current-ID journal that remains after full boot.
            current_directory = f"/var/log/journal/{machine_id}"
            assert machine.succeed(
                f"stat -c '%U|%G|%a' {current_directory}"
            ).strip() == "root|systemd-journal|2755"
            label = machine.succeed(
                f"${pkgs.attr}/bin/getfattr -n security.selinux "
                f"--only-values {current_directory}"
            ).strip("\x00\n")
            assert label.split(":", 3)[2] == "systemd_journal_t", label

            journal_ids = machine.succeed("ls -1 /var/log/journal").splitlines()
            assert journal_ids == [machine_id], journal_ids

            prep_unit = machine.succeed(
                "cat /etc/systemd/system/aos-journald-runtime-prep.service"
            )
            journald_dropin = machine.succeed(
                "cat /etc/systemd/system/systemd-journald.service.d/overrides.conf"
            )
            stock_journald = machine.succeed(
                "cat ${pkgs.systemd}/lib/systemd/system/systemd-journald.service"
            )
            assert "DefaultDependencies=no" in prep_unit, prep_unit
            assert "Before=systemd-journald.service" in prep_unit, prep_unit
            assert "--inline" in prep_unit and "/run/log/journal/%%m" in prep_unit
            assert "ReadWritePaths=/run" in prep_unit.splitlines(), prep_unit
            assert "Requires=aos-journald-runtime-prep.service" in journald_dropin
            assert "After=aos-journald-runtime-prep.service" in journald_dropin
            assert "RestrictSUIDSGID=yes" in stock_journald
            assert "RestrictSUIDSGID=no" not in journald_dropin

            pids = journald_pids(machine)
            assert len(pids) == 1, pids
            return pids[0]

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

        def assert_unit_refusal(machine, unit, refusal):
            machine.wait_until_succeeds(
                f"journalctl -b -u '{unit}' -o cat --no-pager | "
                f"grep -Fq '{refusal}'",
                timeout=30,
            )

        def activated_instance_since(machine, template, cursor):
            command = (
                f"journalctl -b --after-cursor='{cursor}' "
                f"-u '{template}@*.service' -o json --no-pager --quiet"
            )
            deadline = time.monotonic() + 30

            while time.monotonic() < deadline:
                entries = (
                    json.loads(line)
                    for line in machine.succeed(command).splitlines()
                )
                instances = {
                    name
                    for entry in entries
                    for name in (
                        entry.get("UNIT"),
                        entry.get("_SYSTEMD_UNIT"),
                        entry.get("OBJECT_SYSTEMD_UNIT"),
                    )
                    if name and name.startswith(f"{template}@")
                    and name.endswith(".service")
                    and name != f"{template}@.service"
                }
                if len(instances) == 1:
                    return instances.pop()
                assert not instances, (template, instances)
                time.sleep(1)

            raise AssertionError(f"no new activated instance for {template}")

        def assert_image_fragment(machine, unit, image_unit):
            expected = machine.succeed(
                "${pkgs.coreutils}/bin/readlink "
                f"/aos-toplevel/systemd-units/{image_unit}"
            ).strip()
            actual = machine.succeed(
                f"systemctl show -P FragmentPath '{unit}'"
            ).strip()
            assert expected.startswith("/nix/store/"), (image_unit, expected)
            assert actual == expected, (unit, actual, expected)

            if image_unit == "aos-sandbox-network-namespace-inspector@.service":
                # Inspect PID 1's loaded context after reexec, not merely the
                # text of the pinned fragment. No inherited/default stderr
                # setting may substitute for the image-pinned logging stream.
                stdio_command = (
                    "systemctl show -p StandardInput -p StandardOutput "
                    f"-p StandardError '{unit}'"
                )
                expected_stdio = {
                    "StandardInput=socket",
                    "StandardOutput=socket",
                    "StandardError=kmsg+console",
                }
                stdio = machine.succeed(stdio_command).splitlines()
                assert set(stdio) == expected_stdio, (unit, stdio)

                status, stdout, stderr = machine.execute(
                    f"systemctl set-property --runtime '{unit}' StandardError=null"
                )
                assert status != 0 and (
                    b"Protected Network units do not accept property overrides"
                    in stdout + stderr
                ), (unit, status, stdout, stderr)
                stdio = machine.succeed(stdio_command).splitlines()
                assert set(stdio) == expected_stdio, (unit, stdio)

        def assert_manager_environment_isolated(machine, value):
            assignment = f"AOS_NETWORK_MANAGER_SENTINEL={value}"
            assert assignment in machine.succeed(
                "systemctl show-environment"
            ).splitlines()

            # The control must inherit the new value. Otherwise a missing
            # protected value would not prove the protected-unit exception.
            machine.succeed(
                "systemctl restart aos-network-manager-environment-control.service"
            )
            machine.wait_until_succeeds(
                "journalctl -b -u aos-network-manager-environment-control.service "
                f"-o cat --no-pager | grep -Fxq '{value}'",
                timeout=30,
            )

            machine.succeed("systemctl restart aos-netd.service", timeout=90)
            machine.wait_until_succeeds(broker_process, timeout=30)
            pid = machine.succeed("systemctl show -P MainPID aos-netd.service").strip()
            assert pid.isdecimal() and pid != "0", pid
            machine.succeed(
                f"${pkgs.grep}/bin/grep -aFq 'PATH=' /proc/{pid}/environ"
            )
            machine.fail(
                f"${pkgs.grep}/bin/grep -aFq 'AOS_NETWORK_MANAGER_SENTINEL=' "
                f"/proc/{pid}/environ"
            )
            return pid

        def assert_live_mounts_rejected(machine):
            busctl = "${pkgs.systemd}/bin/busctl --system call org.freedesktop.systemd1"
            unit_reply = machine.succeed(
                f"{busctl} /org/freedesktop/systemd1 "
                "org.freedesktop.systemd1.Manager GetUnit s aos-netd.service"
            ).strip()
            assert unit_reply.startswith('o "') and unit_reply.endswith('"'), unit_reply
            unit_path = unit_reply[3:-1]
            assert unit_path.startswith("/org/freedesktop/systemd1/unit/"), unit_path

            requests = (
                (
                    unit_path,
                    "org.freedesktop.systemd1.Service",
                    "BindMount",
                    "ssbb",
                    "/run /run/aos-network-forbidden-live-bind true true",
                ),
                (
                    unit_path,
                    "org.freedesktop.systemd1.Service",
                    "MountImage",
                    "ssbba(ss)",
                    "/run/aos-nonexistent-image.raw /run/aos-network-forbidden-live-image true true 0",
                ),
                (
                    "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager",
                    "BindMountUnit",
                    "sssbb",
                    "aos-netd.service /run /run/aos-network-forbidden-manager-bind true true",
                ),
                (
                    "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager",
                    "MountImageUnit",
                    "sssbba(ss)",
                    "aos-netd.service /run/aos-nonexistent-image.raw "
                    "/run/aos-network-forbidden-manager-image true true 0",
                ),
            )
            for path, interface, method, signature, arguments in requests:
                command = (
                    f"{busctl} {path} {interface} {method} "
                    f"'{signature}' {arguments}"
                )
                status, stdout, stderr = machine.execute(command, timeout=30)
                assert status != 0 and (
                    b"Protected Network units do not accept live mounts"
                    in stdout + stderr
                ), (method, status, stdout, stderr)

        # Prep reports success before journald starts. After journald starts,
        # PID 1 may route later unit outcomes to the journal instead of serial.
        await_serial(protected, "Finished Prepare the current machine's runtime journal directory")
        protected.wait_until_succeeds(
            "test -f /run/aos-protected-root-adversary.ok"
        )
        # The fresh broker socket Requires/After the protected roots service.
        protected.wait_until_succeeds("test -S /run/aos/sandbox-network/control.sock")
        journald_pid = assert_stage2_journal(protected)
        protected.succeed(f"kill -TERM {journald_pid}")
        wait_for_journald_restart(protected, journald_pid)
        assert_stage2_journal(protected)
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

        assert_live_mounts_rejected(protected)

        # Manager.SetEnvironment requires the broad SELinux reload permission
        # this fixture does not add. A mutable runtime manager default reaches
        # the same effective-environment merge after daemon-reexec.
        protected.succeed("mkdir -p /run/systemd/system.conf.d")
        protected.succeed(
            "printf '%s\\n' '[Manager]' "
            "'DefaultEnvironment=AOS_NETWORK_MANAGER_SENTINEL=after-reexec' "
            "> /run/systemd/system.conf.d/90-aos-network-manager-environment.conf"
        )
        protected.succeed("systemctl daemon-reexec", timeout=90)
        protected.wait_for_unit("multi-user.target", timeout=180)
        assert "phase=reexec" in protected.succeed(
            "cat /run/aos/selinux-root-handoff"
        )
        broker_pid = assert_manager_environment_isolated(
            protected, "after-reexec"
        )
        assert_private_lower_store(protected, broker_pid, "aos-netd")
        assert_live_mounts_rejected(protected)

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

        # The image fragments must win even when mutable lookup paths contain
        # complete replacements and the canonical /etc links are whiteouted.
        replacement_units = (
            ("aos-netd.service", "broker"),
            ("aos-sandbox-network-namespace-inspector@.service", "inspector"),
            ("aos-sandbox-network-lifecycle-worker@.service", "lifecycle"),
        )
        protected.succeed("mkdir -p /run/systemd/system")
        for unit, role in replacement_units:
            protected.succeed(f"test -L /etc/systemd/system/{unit}")
            protected.succeed(
                "printf '%s\\n' '[Service]' 'Type=oneshot' "
                "'ExecStartPre=+${pkgs.coreutils}/bin/touch "
                f"/run/aos-forbidden-network-run-fragment-{role}' "
                "'ExecStart=${pkgs.coreutils}/bin/true' "
                f"> /run/systemd/system/{unit}"
            )
            protected.succeed(
                f"${pkgs.coreutils}/bin/unlink /etc/systemd/system/{unit}"
            )
            protected.fail(f"test -e /etc/systemd/system/{unit}")

        cursor_line = protected.succeed(
            "journalctl -b -n 1 --show-cursor -o cat --no-pager"
        ).splitlines()[-1]
        assert cursor_line.startswith("-- cursor: "), cursor_line
        activation_cursor = cursor_line[len("-- cursor: "):]

        protected.succeed("systemctl daemon-reexec", timeout=90)
        protected.wait_for_unit("multi-user.target", timeout=180)
        protected.succeed("systemctl restart aos-netd.service", timeout=90)
        protected.wait_until_succeeds(broker_process, timeout=30)
        assert_image_fragment(protected, "aos-netd.service", "aos-netd.service")

        for template, option, production_signal in (
            (
                "aos-sandbox-network-namespace-inspector",
                "",
                "CREDENTIALS_DIRECTORY is absent",
            ),
            (
                "aos-sandbox-network-lifecycle-worker",
                " --lifecycle",
                "aos-sandbox-network-lifecycle-worker:",
            ),
        ):
            protected.succeed(
                "${inspectorSocketConnector}/bin/aos-inspector-socket-connect"
                + option
            )
            instance = activated_instance_since(
                protected, template, activation_cursor
            )
            assert_image_fragment(protected, instance, f"{template}@.service")
            protected.wait_until_succeeds(
                f"journalctl -b --after-cursor='{activation_cursor}' "
                f"-u '{instance}' -o cat --no-pager --quiet | "
                f"grep -Fq '{production_signal}'",
                timeout=30,
            )

        for _, role in replacement_units:
            protected.fail(
                f"test -e /run/aos-forbidden-network-run-fragment-{role}"
            )

        # Runtime .conf drop-ins affect all three protected identities. A
        # reexec followed by fresh activation must refuse each one; this
        # enforcing fixture does not grant broad manager reload permission.
        for unit in (
            "aos-netd.service",
            "aos-sandbox-network-namespace-inspector@.service",
            "aos-sandbox-network-lifecycle-worker@.service",
        ):
            directory = f"/run/systemd/system/{unit}.d"
            protected.succeed(f"mkdir -p {directory}")
            protected.succeed(
                "printf '%s\\n' '[Service]' "
                "'ExecStartPre=+${pkgs.coreutils}/bin/touch "
                "/run/aos-forbidden-network-run-prestart' "
                f"> {directory}/override.conf"
            )
        protected.succeed("systemctl daemon-reexec", timeout=90)
        protected.wait_for_unit("multi-user.target", timeout=180)
        restart_status, restart_output, restart_error = protected.execute(
            "systemctl restart aos-netd.service", timeout=90
        )
        assert restart_status != 0, (restart_output, restart_error)
        protected.execute(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect"
        )
        protected.execute(
            "${inspectorSocketConnector}/bin/aos-inspector-socket-connect --lifecycle"
        )
        for unit in (
            "aos-netd.service",
            "aos-sandbox-network-namespace-inspector@*.service",
            "aos-sandbox-network-lifecycle-worker@*.service",
        ):
            assert_unit_refusal(
                protected, unit, "Refusing Network unit configuration drop-ins"
            )
        protected.fail("test -e /run/aos-forbidden-network-run-prestart")

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
            assert_unit_refusal(overridden, unit, refusal)
        overridden.fail("test -e /run/aos-forbidden-network-prestart")
        overridden.fail("test -e /run/aos-forbidden-network-dependency")
        fragment = overridden.succeed(
            "systemctl show -P FragmentPath aos-netd.service"
        ).strip()
        assert fragment.startswith("/nix/store/"), fragment
      '';
  }
