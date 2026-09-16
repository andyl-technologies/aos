# End-to-end qualification for the production systemd one-shot Network worker.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  gate = pkgs.aos-sandbox-network-lease-gate;
  gateFixtureSource = ../sandbox/network-lease-gate-fixture.c;
  authorityDirectory = "/var/lib/aos/sandbox-network-worker-authority";
  stateRoot = "/var/lib/aos/sandbox-network/worker-qualification";
  resultPath = "/var/lib/aos/sandbox-network/worker-qualification.result";
  preparedPath = "/var/lib/aos/sandbox-network/worker-qualification.prepared";
  observePath = "/var/lib/aos/sandbox-network/worker-qualification.observe";
  workerSocket = "/run/aos/sandbox-network-worker/control.sock";
  lifecycleWorkerSocket = "/run/aos/sandbox-network-lifecycle-worker/control.sock";
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

  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-network-worker-fixture";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos-netd.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoFlags = "-p aos-sandbox-network-systemd-custody-fixture --bin aos-netd-custody-fixture";
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv = pkgs.aos-netd.passthru.cargoEnv;
  };

  gateFixture = pkgs.mkDerivation {
    pname = "aos-network-worker-gate-fixture";
    version = "1";
    src = null;
    buildDeps = [
      pkgs.linux-headers
      pkgs.pkg-config
    ];
    runtimeDeps = [
      gate
      pkgs.libbpf
    ];
    propagatedDeps = [];
    disallowedReferences = [gateFixtureSource];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -I${gate}/include \
            -I${pkgs.linux-headers}/include \
            -DAOS_NETWORK_LEASE_GATE_OBJECT='"${gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o"' \
            -DAOS_NETWORK_LEASE_GATE_DENY_OBJECT='"${gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o"' \
            ${gateFixtureSource} \
            -o network-lease-gate-fixture \
            $(pkg-config --cflags --libs libbpf)
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp network-lease-gate-fixture $out/bin/
        '';
      }
    ];
    meta = {
      description = "Test-only state and packet probe for the production Network worker";
      license = "Apache-2.0";
    };
  };

  system = mkSystem [
    ../../systems/server-test.nix
    ({
      config,
      lib,
      ...
    }: {
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
        fixture
        gateFixture
        pkgs.coreutils
        pkgs.iproute2
        pkgs.jq
        pkgs.nftables
        pkgs.socat
        pkgs.systemd
        pkgs.util-linux
      ];

      # The fixture replaces only the broker executable and runs in the host
      # Network namespace so the real executor can transfer that exact
      # namespace. The production one-shot worker unit remains unchanged.
      systemd.services.aos-netd.serviceConfig = {
        ExecStart = lib.mkForce ''
          ${fixture}/bin/aos-netd-custody-fixture \
            worker-serve \
            ${stateRoot} \
            ${resultPath} \
            ${pkgs.aos-netd}/bin/aos-sandbox-network-worker \
            ${gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o \
            ${workerSocket} \
            ${lifecycleWorkerSocket} \
            ${pkgs.iproute2}/sbin/ip \
            ${pkgs.nftables}/sbin/nft \
            ${pkgs.aos-sandbox-network-observer}/bin/aos-sandbox-network-observer
        '';
        PrivateNetwork = lib.mkForce false;
        Restart = lib.mkForce "no";
      };

      assertions = [
        {
          assertion =
            lib.hasPrefix
            "${pkgs.aos-netd}/bin/aos-sandbox-network-lifecycle-worker "
            config.systemd.services."aos-sandbox-network-lifecycle-worker@".serviceConfig.ExecStart;
          message = "lifecycle qualification no longer exercises the production lifecycle worker entrypoint";
        }
      ];

      # This independently requires the platform's alias-resistant Landlock
      # behavior before the production effect worker is exercised. The effect
      # worker itself needs authenticated authority and mutable journal access,
      # so the admission-only wrapper is deliberately not inherited by it.
      systemd.services."aos-sandbox-network-lifecycle-worker@".serviceConfig.ExecStartPre = "${lifecycleProbeWrapper}/bin/aos-network-lifecycle-landlock-qualification";

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
    memoryMiB = 1280;
  };

  testScript = ''
    import json

    FIXTURE = "${fixture}/bin/aos-netd-custody-fixture"
    GATE_FIXTURE = "${gateFixture}/bin/network-lease-gate-fixture"
    AUTHORITY = "${authorityDirectory}"
    AUTHORITY_SENTINEL = "${authoritySentinel}"
    STATE_ROOT = "${stateRoot}"
    STATE_SENTINEL = "${stateSentinel}"
    CREDENTIAL_SENTINEL = "${credentialSentinel}"
    SENTINEL_PID_FILE = "${sentinelPidFile}"
    RESULT = "${resultPath}"
    PREPARED = "${preparedPath}"
    OBSERVE = "${observePath}"
    OPERATION_JOURNAL = f"{STATE_ROOT}/operations/network-state.journal"
    NAMESPACE_JOURNAL = f"{STATE_ROOT}/namespaces/network-namespaces.journal"
    PIN_ROOT = "/run/aos/sandbox-pins/netns"
    IP = "${pkgs.iproute2}/sbin/ip"
    NFT = "${pkgs.nftables}/sbin/nft"
    NSENTER = "${pkgs.util-linux}/bin/nsenter"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
    SOCAT = "${pkgs.socat}/bin/socat"
    LEASE = "55" * 32
    probe_sequence = 0

    def in_sandbox(pid, namespace_fd, command):
        return (
            f"{NSENTER} --net=/proc/{pid}/fd/{namespace_fd} "
            f"{command}"
        )

    def probe(direction, expected):
        global probe_sequence
        probe_sequence += 1
        port = 43000 + probe_sequence
        result = f"/run/aos-worker-probe-{probe_sequence}"
        ready = f"{result}.ready"
        unit = f"aos-worker-receiver-{probe_sequence}"
        token = f"worker-{direction}-{probe_sequence}"

        if direction == "ingress":
            receiver = in_sandbox(
                driver_pid,
                namespace_fd,
                f"{GATE_FIXTURE} receive ipv6 {port} {result} {ready}",
            )
            sender = (
                f"printf '%s' '{token}' | {SOCAT} -u - "
                f"UDP6-DATAGRAM:[{sandbox_address}]:{port}"
            )
        else:
            assert direction == "egress", direction
            receiver = (
                f"{GATE_FIXTURE} receive ipv6 {port} {result} {ready}"
            )
            sender = in_sandbox(
                driver_pid,
                namespace_fd,
                f"{SOCAT} -u - UDP6-DATAGRAM:[{host_address}]:{port}",
            )
            sender = f"printf '%s' '{token}' | {sender}"

        vm.succeed(f"rm -f {result} {result}.tmp {ready}")
        vm.succeed(
            f"systemd-run --unit={unit} --collect --service-type=simple "
            f"{receiver}"
        )
        vm.wait_until_succeeds(f"test -s {ready}", timeout=10)
        vm.succeed(f"rm -f {ready} && {sender}")
        vm.wait_until_fails(
            f"systemctl is-active --quiet {unit}.service", timeout=10
        )
        if expected:
            observed = vm.succeed(
                f"if test -e {result}; then cat {result}; "
                "else printf __missing__; fi"
            )
            assert observed == token, (direction, observed, token)
        else:
            vm.fail(f"test -e {result}")

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.wait_for_unit("aos-sandbox-network-worker-ready.service", timeout=30)
    vm.succeed("systemctl stop aos-netd.service || true")
    vm.succeed(f"test ! -e {AUTHORITY}")
    vm.succeed(f"{FIXTURE} worker-provision {AUTHORITY}")
    vm.succeed(f"test $(stat -c %a {AUTHORITY}) = 700")
    vm.succeed("systemctl reset-failed aos-netd.service")
    vm.succeed("systemctl start aos-netd.service")
    try:
        vm.wait_until_succeeds(f"test -s {PREPARED}", timeout=60)
    except Exception:
        print(vm.execute("systemctl status --no-pager --full aos-netd.service"))
        print(vm.execute("journalctl --no-pager -n 200 -u aos-netd.service -u 'aos-sandbox-network-worker@*'"))
        print(vm.execute(f"ls -la {AUTHORITY} {STATE_ROOT} /run/aos/sandbox-network-worker || true"))
        print(vm.execute("systemctl status --no-pager --full aos-netd.socket aos-sandbox-network-worker.socket"))
        raise

    driver_pid = int(vm.succeed(
        "systemctl show aos-netd.service -p MainPID --value"
    ).strip())
    assert driver_pid > 1, driver_pid
    lines = vm.succeed(f"cat {PREPARED}").splitlines()
    fields = lines[0].split()
    assert len(fields) == 10 and fields[0] == "PREPARED", fields
    (
        _,
        host_interface,
        sandbox_interface,
        host_address,
        sandbox_address,
        prefix_length,
        assignment_epoch,
        assignment_digest,
        network_handle,
        allocation_generation,
    ) = fields
    namespace_fd = int(lines[1])
    assert prefix_length == "127", fields
    assert len(assignment_digest) == 64, assignment_digest
    assert len(network_handle) == 64, network_handle
    assert namespace_fd >= 3, namespace_fd
    vm.succeed(f"test -e /proc/{driver_pid}/fd/{namespace_fd}")
    vm.succeed(f"test ! -e {RESULT}")
    vm.succeed(f"test -s {OPERATION_JOURNAL}")
    vm.fail(
        "systemctl --quiet is-active "
        "'aos-sandbox-network-worker@*.service'"
    )
    namespace_pin = f"{PIN_ROOT}/{network_handle}"
    vm.succeed(f"touch {namespace_pin}")
    vm.succeed(
        f"{MOUNT} --bind /proc/{driver_pid}/fd/{namespace_fd} "
        f"{namespace_pin}"
    )
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

        vm.succeed(f"touch {OBSERVE}")
        try:
            vm.wait_until_succeeds(f"test -s {RESULT}", timeout=60)
        except Exception:
            print(vm.execute("systemctl status --no-pager --full aos-netd.service"))
            print(vm.execute("systemctl status --no-pager --full 'aos-sandbox-network-lifecycle-worker@*'"))
            print(vm.execute("journalctl --no-pager -n 300 -u aos-netd.service -u 'aos-sandbox-network-worker@*' -u 'aos-sandbox-network-lifecycle-worker@*'"))
            print(vm.execute(f"find {STATE_ROOT} -maxdepth 3 -ls || true"))
            raise
        vm.succeed(
            "journalctl --no-pager -u "
            "'aos-sandbox-network-lifecycle-worker@*' | "
            "grep -F LIFECYCLE_LANDLOCK_OK"
        )
    finally:
        vm.succeed(
            f"printf %s {previous_yama} > /proc/sys/kernel/yama/ptrace_scope"
        )
        vm.succeed(
            "systemctl stop aos-network-lifecycle-sentinel-holder.service || true"
        )

    committed = vm.succeed(f"cat {RESULT}").splitlines()
    assert committed[0] == f"WORKER_OK {' '.join(fields[1:])}", committed
    assert int(committed[1]) == namespace_fd, committed
    assert len(committed[2]) == 64, committed
    lifecycle = committed[3].split()
    assert len(lifecycle) == 5 and lifecycle[0] == "LIFECYCLE_ADMITTED", lifecycle
    assert len(lifecycle[1]) == 64 and len(lifecycle[2]) == 64, lifecycle
    target_identity = vm.succeed(
        f"stat -c %d:%i /proc/{driver_pid}/fd/{namespace_fd}"
    ).strip()
    host_identity = vm.succeed(
        f"stat -c %d:%i /proc/{driver_pid}/ns/net"
    ).strip()
    assert lifecycle[4] == target_identity, (lifecycle, target_identity)
    assert lifecycle[3] not in [host_identity, target_identity], (
        lifecycle,
        host_identity,
        target_identity,
    )
    # Reaching RESULT requires an exact replay of the committed publication,
    # followed by durable-journal reopen and catalog-authorized re-observation.
    vm.succeed(f"test -s {OPERATION_JOURNAL}")
    vm.succeed(f"test -s {NAMESPACE_JOURNAL}")
    vm.fail(
        "systemctl --quiet is-active "
        "'aos-sandbox-network-worker@*.service'"
    )

    host_link = json.loads(
        vm.succeed(f"{IP} -j link show dev {host_interface}")
    )[0]
    sandbox_link = json.loads(vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} -j link show dev {sandbox_interface}",
    )))[0]
    assert "UP" not in host_link["flags"], host_link
    assert "UP" not in sandbox_link["flags"], sandbox_link

    host_addresses = json.loads(
        vm.succeed(f"{IP} -j -6 address show dev {host_interface}")
    )[0]["addr_info"]
    sandbox_addresses = json.loads(vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} -j -6 address show dev {sandbox_interface}",
    )))[0]["addr_info"]
    assert any(
        address["local"] == host_address
        and address["prefixlen"] == int(prefix_length)
        and address.get("nodad") is True
        and not address.get("tentative", False)
        and not address.get("dadfailed", False)
        for address in host_addresses
    ), host_addresses
    assert any(
        address["local"] == sandbox_address
        and address["prefixlen"] == int(prefix_length)
        and address.get("nodad") is True
        and not address.get("tentative", False)
        and not address.get("dadfailed", False)
        for address in sandbox_addresses
    ), sandbox_addresses

    host_neighbors = json.loads(
        vm.succeed(f"{IP} -j -6 neighbor show dev {host_interface}")
    )
    sandbox_neighbors = json.loads(vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} -j -6 neighbor show dev {sandbox_interface}",
    )))
    assert any(
        neighbor["dst"] == sandbox_address
        and neighbor["lladdr"] == sandbox_link["address"]
        and neighbor["state"] == ["PERMANENT"]
        for neighbor in host_neighbors
    ), host_neighbors
    assert any(
        neighbor["dst"] == host_address
        and neighbor["lladdr"] == host_link["address"]
        and neighbor["state"] == ["PERMANENT"]
        for neighbor in sandbox_neighbors
    ), sandbox_neighbors

    gate_status = json.loads(vm.succeed(
        f"{GATE_FIXTURE} status-observer {network_handle}"
    ))
    assert gate_status["assignment_epoch"] == int(assignment_epoch), gate_status
    assert gate_status["allocation_generation"] == int(allocation_generation), gate_status
    assert gate_status["assignment_digest"] == assignment_digest, gate_status
    assert gate_status["ingress"]["armed"] == 0, gate_status
    assert gate_status["egress"]["armed"] == 0, gate_status
    vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{NFT} --json list table inet aos_sandbox",
    ))

    # WORKER_OK proves only authenticated preparation and worker quiescence.
    # Independently exercise the realized namespace and fail-closed gate.
    vm.succeed(f"{IP} link set dev {host_interface} up")
    vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} link set dev {sandbox_interface} up",
    ))
    probe("ingress", False)
    probe("egress", False)

    clocks = json.loads(vm.succeed(f"{GATE_FIXTURE} clocks"))
    deadline = clocks["boottime_nanoseconds"] + 60_000_000_000
    vm.succeed(
        f"{GATE_FIXTURE} update-observer {network_handle} arm "
        f"{assignment_epoch} 1 {deadline} {LEASE}"
    )
    probe("ingress", True)
    probe("egress", True)

    vm.succeed(f"{GATE_FIXTURE} update-observer {network_handle} disarm")
    probe("ingress", False)
    probe("egress", False)
  '';
}
