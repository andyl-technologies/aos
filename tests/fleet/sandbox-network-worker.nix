# Checks rendered worker policy and the standalone native Landlock boundary.
# Full operator-funded canonical P/O flow qualification remains separate.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  authorityDirectory = "/var/lib/aos/sandbox-network-worker-authority";
  stateRoot = "/var/lib/aos/sandbox-network/worker-qualification";
  authoritySentinel = "${authorityDirectory}/lifecycle-qualification-sentinel";
  stateSentinel = "${stateRoot}/lifecycle-qualification-sentinel";
  credentialSentinel = "/run/credentials/lifecycle-qualification-sentinel";
  sentinelPidFile = "/run/aos-network-lifecycle-sentinel.pid";
  lifecycleProbeSource = ../sandbox/network-lifecycle-landlock-probe.c;
  lifecycleSentinelSource = ../sandbox/network-lifecycle-sentinel-holder.c;

  lifecycleProbeLandlockPrefix = lib.concatStringsSep " " [
    "${pkgs.aos-landlock}/bin/aos-landlock"
    "--require-abi 4"
    "--fs-read /proc/self/cgroup"
    "--fs-read /proc/self/fd"
    "--fs-read /proc/self/task"
    "--fs-read /sys/fs/cgroup"
    "--fs-ro /nix/store"
    "--"
  ];

  lifecycleQualificationTools = pkgs.mkDerivation {
    pname = "aos-network-lifecycle-landlock-qualification";
    version = "1";
    src = null;
    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [
      lifecycleProbeSource
      lifecycleSentinelSource
    ];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            ${lifecycleProbeSource} -o network-lifecycle-landlock-probe
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            ${lifecycleSentinelSource} -o network-lifecycle-sentinel-holder
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp network-lifecycle-landlock-probe $out/bin/
          cp network-lifecycle-sentinel-holder $out/bin/
        '';
      }
    ];
    meta = {
      description = "Test-only Landlock and proc-alias probes for Network lifecycle admission";
      license = "Apache-2.0";
    };
  };

  lifecycleProbeWrapper = pkgs.writeShellScriptBin "aos-network-lifecycle-landlock-qualification" ''
    set -eu

    holder_pid="$(${pkgs.coreutils}/bin/cat ${sentinelPidFile})"
    case "$holder_pid" in
      *[!0-9]*) exit 1 ;;
      *) test -n "$holder_pid" ;;
    esac

    exec ${lifecycleProbeLandlockPrefix} \
      ${lifecycleQualificationTools}/bin/network-lifecycle-landlock-probe \
      ${authoritySentinel} \
      ${stateSentinel} \
      ${credentialSentinel} \
      "/proc/$holder_pid/root${authoritySentinel}" \
      "/proc/$holder_pid/fd/9"
  '';

  system = mkSystem [
    ../../systems/server-test.nix
    ({
      config,
      lib,
      ...
    }: {
      # Replay the fixture account through native host identity activation.
      aos.activation.stages.host.configuration = [
        (builtins.path {
          path = ./_sandbox-controller-identity.nix;
          name = "aos-sandbox-controller-identity.nix";
        })
      ];
      aos.firewall.enable = lib.mkForce false;
      aos.sandbox.networkBroker = {
        enable = true;
        maximumRetainedNamespaces = 1;
      };
      aos.sandbox.networkWorker = {
        enable = true;
        inherit authorityDirectory;
      };
      aos.image.budgets = {
        maxRootMiB = 736;
        maxDownloadMiB = 864;
      };

      environment.systemPackages = [
        pkgs.coreutils
        pkgs.iproute2
        pkgs.jq
        pkgs.nftables
        pkgs.socat
        pkgs.systemd
        pkgs.util-linux
      ];

      assertions = [
        {
          assertion =
            lib.hasPrefix
            "${pkgs.aos-netd}/bin/aos-sandbox-network-lifecycle-worker "
            config.systemd.services."aos-sandbox-network-lifecycle-worker@".serviceConfig.ExecStart;
          message = "lifecycle qualification no longer exercises the production lifecycle worker entrypoint";
        }
      ];

      # This test invokes only the native alias probe. It neither authenticates
      # a worker request nor supplies a financial Source to the production unit.
      systemd.services.aos-network-lifecycle-landlock-qualification = {
        description = "Test-only Network native Landlock alias probe";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${lifecycleProbeWrapper}/bin/aos-network-lifecycle-landlock-qualification";
          User = "root";
          Group = "root";
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          NoNewPrivileges = true;
        };
      };

      systemd.services.aos-network-lifecycle-sentinel-holder = {
        description = "Test-only dumpable Network lifecycle sentinel holder";
        serviceConfig = {
          Type = "simple";
          ExecStart = ''
            ${lifecycleQualificationTools}/bin/network-lifecycle-sentinel-holder \
              ${authoritySentinel} \
              ${sentinelPidFile}
          '';
          User = "root";
          Group = "root";
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          NoNewPrivileges = true;
          Restart = "no";
        };
      };
    })
  ];
in {
  name = "sandbox-network-worker";
  timeout = 420;
  bootTimeout = 180;

  machines.vm = {
    inherit system;
    # Native host configuration evaluates the complete installed package set.
    # Match the other Sandbox worker VMs while retaining the service limits.
    memoryMiB = 2048;
  };

  testScript = ''
    AUTHORITY = "${authorityDirectory}"
    AUTHORITY_SENTINEL = "${authoritySentinel}"
    STATE_ROOT = "${stateRoot}"
    STATE_SENTINEL = "${stateSentinel}"
    CREDENTIAL_SENTINEL = "${credentialSentinel}"
    SENTINEL_PID_FILE = "${sentinelPidFile}"
    SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"

    try:
        vm.wait_for_unit("multi-user.target", timeout=120)
    except Exception:
        for command in (
            "systemctl status aos-activate.service --no-pager -l",
            "journalctl -b -u aos-activate.service --no-pager -n 100",
            "cat /proc/meminfo /proc/pressure/memory",
        ):
            status, stdout, stderr = vm.execute(command)
            print(f"host configuration diagnostic ({status}): {command}")
            print(stdout.decode("utf-8", errors="replace"))
            print(stderr.decode("utf-8", errors="replace"))
        raise
    vm.wait_for_unit("aos-sandbox-network-worker-ready.service", timeout=30)

    guarded_units = (
        "aos-netd.service",
        "aos-sandbox-network-worker@.service",
        "aos-sandbox-network-lifecycle-worker@.service",
        "aos-sandbox-network-observation-worker@.service",
        "aos-sandbox-network-pin-worker@.service",
    )
    for unit_name in guarded_units:
        unit_text = vm.succeed(f"systemctl cat '{unit_name}'")
        assert "RestrictSUIDSGID=true" in unit_text, unit_name
        for syscall in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
            assert f"SystemCallFilter=~{syscall}" in unit_text, (unit_name, syscall)

    # P removes the signed Destroy target's exact pin; O stays read-only.
    # Manager properties require a concrete instance, even before it starts.
    preparation_policy = vm.succeed(
        "systemctl show 'aos-sandbox-network-worker@profile-check.service' "
        "--property=SystemCallFilter --value"
    ).split()
    assert "umount2" in preparation_policy, preparation_policy
    assert "~umount2" not in preparation_policy, preparation_policy
    observation_policy = vm.succeed(
        "systemctl cat 'aos-sandbox-network-observation-worker@.service'"
    )
    assert "SystemCallFilter=~umount2" in observation_policy, observation_policy

    # These files are denial sentinels, not broker credentials or authority.
    vm.succeed(f"mkdir -p {AUTHORITY} {STATE_ROOT}")
    sentinel = "aos-network-lifecycle-sentinel-v1"
    vm.succeed(
        f"printf %s {sentinel} > {AUTHORITY_SENTINEL} && "
        f"printf %s {sentinel} > {STATE_SENTINEL} && "
        "mkdir -p /run/credentials && "
        f"printf %s {sentinel} > {CREDENTIAL_SENTINEL} && "
        f"chmod 0600 {AUTHORITY_SENTINEL} {STATE_SENTINEL} {CREDENTIAL_SENTINEL}"
    )
    previous_yama = vm.succeed(
        "cat /proc/sys/kernel/yama/ptrace_scope"
    ).strip()
    assert previous_yama.isdigit(), previous_yama
    vm.succeed("printf 0 > /proc/sys/kernel/yama/ptrace_scope")
    try:
        vm.succeed(f"rm -f {SENTINEL_PID_FILE}")
        vm.succeed("systemctl start aos-network-lifecycle-sentinel-holder.service")
        vm.wait_until_succeeds(f"test -s {SENTINEL_PID_FILE}", timeout=10)
        holder_pid = int(vm.succeed(f"cat {SENTINEL_PID_FILE}").strip())
        holder_main_pid = int(vm.succeed(
            "systemctl show aos-network-lifecycle-sentinel-holder.service "
            "--property=MainPID --value"
        ).strip())
        assert holder_pid > 1 and holder_pid == holder_main_pid, (
            holder_pid,
            holder_main_pid,
        )

        proc_root_alias = f"/proc/{holder_pid}/root{AUTHORITY_SENTINEL}"
        proc_fd_alias = f"/proc/{holder_pid}/fd/9"
        for sequence, alias in enumerate([proc_root_alias, proc_fd_alias], 1):
            observed = vm.succeed(
                f"{SYSTEMD_RUN} --quiet --wait --pipe --collect "
                f"--unit=aos-lifecycle-unconfined-{sequence} "
                "--property=CapabilityBoundingSet= "
                "--property=AmbientCapabilities= "
                "--property=NoNewPrivileges=yes "
                "--property=ProtectProc=invisible "
                "--property=ProcSubset=pid "
                f"${pkgs.coreutils}/bin/cat {alias}"
            )
            assert observed == sentinel, (alias, observed)

        vm.succeed(
            "systemctl start aos-network-lifecycle-landlock-qualification.service"
        )
        vm.succeed(
            "journalctl --no-pager -u "
            "aos-network-lifecycle-landlock-qualification.service | "
            "grep -F LIFECYCLE_LANDLOCK_OK"
        )
    finally:
        vm.succeed(
            f"printf %s {previous_yama} > /proc/sys/kernel/yama/ptrace_scope"
        )
        vm.succeed(
            "systemctl stop aos-network-lifecycle-sentinel-holder.service || true"
        )

  '';
}
