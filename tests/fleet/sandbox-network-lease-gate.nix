# Executable production-artifact proof for the fixed tc-BPF ownership lease gate.
{
  mkSystem,
  pkgs,
  ...
}: let
  gate = pkgs.aos-sandbox-network-lease-gate;
  denySource = ../sandbox/network-lease-gate-deny.bpf.c;
  fixtureSource = ../sandbox/network-lease-gate-fixture.c;
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch = targetArchBySystem.${pkgs.stdenv.system};

  denyObject = pkgs.mkDerivation {
    pname = "aos-network-lease-gate-test-deny";
    version = "1";
    src = null;
    buildDeps = [
      pkgs.linux-headers
      pkgs.llvm
      pkgs.libbpf
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [denySource];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/lib/bpf
          cp ${denySource} deny.bpf.c
          ${pkgs.buildPackages.llvm}/bin/clang -target bpf -O2 -g \
            -D__TARGET_ARCH_${targetArch} \
            -I${pkgs.linux-headers}/include \
            -I${pkgs.libbpf}/include \
            -Wall -Wextra -Werror \
            -c deny.bpf.c -o $out/lib/bpf/deny.bpf.o

          ${pkgs.buildPackages.llvm}/bin/llvm-strip -g \
            $out/lib/bpf/deny.bpf.o
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };

  fixture = pkgs.mkDerivation {
    pname = "aos-network-lease-gate-test-fixture";
    version = "1";
    src = null;
    buildDeps = [
      pkgs.linux-headers
      pkgs.pkg-config
    ];
    runtimeDeps = [
      denyObject
      gate
      pkgs.libbpf
    ];
    propagatedDeps = [];
    disallowedReferences = [fixtureSource];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -I${gate}/include \
            -I${pkgs.linux-headers}/include \
            -DAOS_NETWORK_LEASE_GATE_OBJECT='"${gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o"' \
            -DAOS_NETWORK_LEASE_GATE_DENY_OBJECT='"${denyObject}/lib/bpf/deny.bpf.o"' \
            ${fixtureSource} \
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
      description = "Test-only loader and fault injector for the sandbox lease gate";
      license = "Apache-2.0";
    };
  };

  system = mkSystem [
    ../../systems/server-test.nix
    {
      aos.firewall.trustedInterfaces = [
        "lo"
        "aoh000000000001"
      ];

      environment.systemPackages = [
        fixture
        gate
        pkgs.coreutils
        pkgs.iproute2
        pkgs.socat
        pkgs.systemd
        pkgs.util-linux
      ];
    }
  ];
in {
  name = "sandbox-network-lease-gate";
  timeout = 420;
  bootTimeout = 180;

  machines.vm = {inherit system;};

  testScript = ''
    import json

    FIXTURE = "${fixture}/bin/network-lease-gate-fixture"
    IP = "${pkgs.iproute2}/sbin/ip"
    RTCWAKE = "${pkgs.util-linux}/sbin/rtcwake"
    SOCAT = "${pkgs.socat}/bin/socat"
    HANDLE = "11" * 32
    ASSIGNMENT = "22" * 32
    LEASE_ONE = "33" * 32
    LEASE_TWO = "44" * 32
    HOST_IF = "aoh000000000001"
    PEER_IF = "aog000000000001"
    PEER_NS = "aos-gate-peer"
    PEER_NS_PATH = f"/run/netns/{PEER_NS}"
    HOST_ADDRESS = "192.0.2.0"
    PEER_ADDRESS = "192.0.2.1"
    ASSIGNMENT_EPOCH = 41
    ALLOCATION_GENERATION = 1
    probe_sequence = 0

    def clocks():
        return json.loads(vm.succeed(f"{FIXTURE} clocks"))

    def kill_held_fixture(unit, arguments, ready_path):
        vm.succeed(f"rm -f {ready_path}")
        vm.succeed(
            f"systemd-run --unit={unit} --collect --service-type=simple "
            f"{FIXTURE} {arguments}"
        )
        vm.wait_until_succeeds(f"test -s {ready_path}", timeout=20)
        pid = int(vm.succeed(
            f"systemctl show {unit}.service -p MainPID --value"
        ).strip())
        assert pid > 1, pid
        vm.succeed(
            f"systemctl kill --kill-whom=main --signal=KILL {unit}.service"
        )
        vm.wait_until_fails(
            f"systemctl is-active --quiet {unit}.service", timeout=20
        )
        vm.fail(f"test -e /proc/{pid}")
        return pid

    def probe(direction, expected, observe=False):
        global probe_sequence
        probe_sequence += 1
        port = 42000 + probe_sequence
        result = f"/run/aos-gate-probe-{probe_sequence}"
        ready = f"{result}.ready"
        unit = f"aos-gate-receiver-{probe_sequence}"
        token = f"lease-gate-{direction}-{probe_sequence}"

        if direction == "egress":
            receiver_command = (
                f"{IP} netns exec {PEER_NS} {FIXTURE} receive "
                f"{port} {result} {ready}"
            )
            sender_command = (
                f"printf '%s' '{token}' | {SOCAT} -u - "
                f"UDP4-DATAGRAM:{PEER_ADDRESS}:{port}"
            )
        else:
            receiver_command = f"{FIXTURE} receive {port} {result} {ready}"
            sender_command = (
                f"printf '%s' '{token}' | {IP} netns exec {PEER_NS} "
                f"{SOCAT} -u - UDP4-DATAGRAM:{HOST_ADDRESS}:{port}"
            )

        vm.succeed(f"rm -f {result} {result}.tmp {ready}")
        vm.succeed(
            f"systemd-run --unit={unit} --collect --service-type=simple "
            f"{receiver_command}"
        )
        # The fixture publishes readiness after bind(2), then starts its
        # bounded receive wait only after this command removes the marker.
        vm.wait_until_succeeds(f"test -s {ready}", timeout=10)
        vm.succeed(f"rm -f {ready} && {sender_command}")
        vm.wait_until_fails(
            f"systemctl is-active --quiet {unit}.service", timeout=10
        )

        if expected:
            observed = vm.succeed(
                f"if test -e {result}; then cat {result}; "
                "else printf __missing__; fi"
            )
            if observe:
                gate_status = json.loads(vm.succeed(f"{FIXTURE} status"))
                context = json.loads(
                    vm.succeed(f"{FIXTURE} observer-status")
                )[direction]
                current_clocks = clocks()
                assert observed == token, (
                    direction,
                    observed,
                    token,
                    gate_status,
                    context,
                    current_clocks,
                )
                assert context["ifindex"] == gate_status["host_ifindex"], (
                    direction,
                    gate_status,
                    context,
                )
                assert (
                    context["boottime_nanoseconds"]
                    < gate_status[direction]["deadline_boottime_nanoseconds"]
                ), (direction, gate_status, context)
            else:
                assert observed == token, (direction, observed, token)
        else:
            vm.fail(f"test -e {result}")

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.succeed("test -e /dev/rtc0")
    vm.succeed("grep -qw mem /sys/power/state")
    vm.succeed("mkdir -p /sys/fs/bpf")
    vm.succeed(
        "mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf"
    )
    vm.succeed("mkdir -p /sys/fs/bpf/aos")
    vm.succeed(f"{IP} netns add {PEER_NS}")
    vm.succeed(
        f"{IP} link add {HOST_IF} type veth peer name {PEER_IF}"
    )
    vm.succeed(f"{IP} link set {PEER_IF} netns {PEER_NS}")
    vm.succeed(f"{IP} address add {HOST_ADDRESS}/31 dev {HOST_IF}")
    vm.succeed(
        f"{IP} netns exec {PEER_NS} {IP} address add "
        f"{PEER_ADDRESS}/31 dev {PEER_IF}"
    )
    host_mac = json.loads(
        vm.succeed(f"{IP} -j link show dev {HOST_IF}")
    )[0]["address"]
    peer_mac = json.loads(
        vm.succeed(
            f"{IP} netns exec {PEER_NS} {IP} -j link show dev {PEER_IF}"
        )
    )[0]["address"]
    vm.succeed(f"{IP} link set {HOST_IF} up")
    vm.succeed(f"{IP} netns exec {PEER_NS} {IP} link set {PEER_IF} up")
    vm.succeed(
        f"{IP} neigh replace {PEER_ADDRESS} lladdr {peer_mac} "
        f"nud permanent dev {HOST_IF}"
    )
    vm.succeed(
        f"{IP} netns exec {PEER_NS} {IP} neigh replace {HOST_ADDRESS} "
        f"lladdr {host_mac} nud permanent dev {PEER_IF}"
    )
    probe("ingress", True)
    probe("egress", True)
    vm.succeed(f"{IP} link set {HOST_IF} down")
    vm.succeed(f"{IP} netns exec {PEER_NS} {IP} link set {PEER_IF} down")

    # Malformed frozen binding values remain default-drop even with an armed,
    # otherwise-current state. The fixture bypass is test-only.
    for fault in ("zero-assignment-digest", "reserved-binding", "old-format"):
        deadline = clocks()["boottime_nanoseconds"] + 60_000_000_000
        kill_held_fixture(
            f"aos-gate-invalid-{fault}",
            f"install-invalid-hold {HOST_IF} {PEER_IF} {PEER_NS_PATH} "
            f"{ASSIGNMENT_EPOCH} {ALLOCATION_GENERATION} {HANDLE} "
            f"{ASSIGNMENT} {fault} {deadline} {LEASE_ONE}",
            "/run/aos-network-lease-gate-install.ready",
        )
        vm.succeed(f"{IP} link set {HOST_IF} up")
        vm.succeed(f"{IP} netns exec {PEER_NS} {IP} link set {PEER_IF} up")
        probe("ingress", False)
        probe("egress", False)
        vm.succeed(f"{IP} link set {HOST_IF} down")
        vm.succeed(f"{IP} netns exec {PEER_NS} {IP} link set {PEER_IF} down")
        vm.succeed(f"{FIXTURE} force-teardown")

    installer_pid = kill_held_fixture(
        "aos-gate-installer",
        f"install-hold {HOST_IF} {PEER_IF} {PEER_NS_PATH} "
        f"{ASSIGNMENT_EPOCH} {ALLOCATION_GENERATION} {HANDLE} {ASSIGNMENT}",
        "/run/aos-network-lease-gate-install.ready",
    )
    vm.succeed(f"{IP} link set {HOST_IF} up")
    vm.succeed(f"{IP} netns exec {PEER_NS} {IP} link set {PEER_IF} up")

    # The pinned ingress and egress links survive actual loader death. With
    # the initialized unarmed state, each direction independently drops.
    probe("ingress", False)
    probe("egress", False)
    status = json.loads(vm.succeed(f"{FIXTURE} status"))
    assert status["assignment_epoch"] == ASSIGNMENT_EPOCH, status
    assert status["allocation_generation"] == ALLOCATION_GENERATION, status
    assert status["ingress"]["armed"] == 0, status
    assert status["egress"]["armed"] == 0, status
    vm.succeed(f"{FIXTURE} attach-observers")

    first_deadline = clocks()["boottime_nanoseconds"] + 120_000_000_000
    updater_pid = kill_held_fixture(
        "aos-gate-updater",
        f"update-hold arm {ASSIGNMENT_EPOCH} 1 {first_deadline} {LEASE_ONE}",
        "/run/aos-network-lease-gate-update.ready",
    )
    assert updater_pid != installer_pid
    probe("ingress", True, observe=True)
    probe("egress", True, observe=True)

    # Stale state on one direction does not hide enforcement by the other.
    vm.succeed(f"{FIXTURE} inject ingress stale-epoch")
    vm.fail(
        f"{FIXTURE} update renew {ASSIGNMENT_EPOCH} 2 "
        f"{first_deadline + 1_000_000_000} {LEASE_TWO}"
    )
    probe("ingress", False)
    probe("egress", True)
    vm.succeed(f"{FIXTURE} inject ingress restore-peer")

    vm.succeed(f"{FIXTURE} inject egress stale-digest")
    probe("ingress", True)
    probe("egress", False)
    vm.succeed(f"{FIXTURE} inject egress restore-peer")

    # A valid lease returns TCX_NEXT, so a later mandatory deny program still
    # executes instead of being bypassed by TCX_PASS.
    vm.succeed(f"{FIXTURE} attach-deny ingress")
    probe("ingress", False)
    probe("egress", True)
    vm.succeed(f"{FIXTURE} detach-deny ingress")
    probe("ingress", True)

    vm.succeed(f"{FIXTURE} attach-deny egress")
    probe("ingress", True)
    probe("egress", False)
    vm.succeed(f"{FIXTURE} detach-deny egress")
    probe("egress", True)

    # Disarm retains the generation high-water mark. A restarted updater may
    # neither replay that generation nor change the assignment epoch.
    vm.succeed(f"{FIXTURE} update disarm")
    disarmed = json.loads(vm.succeed(f"{FIXTURE} status"))
    assert disarmed["ingress"]["generation"] == 1, disarmed
    assert disarmed["egress"]["generation"] == 1, disarmed
    vm.fail(
        f"{FIXTURE} update arm {ASSIGNMENT_EPOCH} 1 "
        f"{first_deadline + 2_000_000_000} {LEASE_ONE}"
    )
    vm.fail(
        f"{FIXTURE} update arm {ASSIGNMENT_EPOCH + 1} 2 "
        f"{first_deadline + 2_000_000_000} {LEASE_TWO}"
    )
    probe("ingress", False)
    probe("egress", False)

    second_deadline = clocks()["boottime_nanoseconds"] + 120_000_000_000
    vm.succeed(
        f"{FIXTURE} update arm {ASSIGNMENT_EPOCH} 2 "
        f"{second_deadline} {LEASE_TWO}"
    )
    probe("ingress", True)
    probe("egress", True)

    # The guest really enters Linux S3 and wakes by emulated RTC. CLOCK_BOOTTIME
    # consumes the sleep while CLOCK_MONOTONIC excludes it; the packet gate uses
    # that same BOOTTIME source and is expired immediately after resume.
    vm.succeed(f"{FIXTURE} update disarm")
    suspend_deadline = clocks()["boottime_nanoseconds"] + 10_000_000_000
    kill_held_fixture(
        "aos-gate-renewer",
        f"update-hold arm {ASSIGNMENT_EPOCH} 3 "
        f"{suspend_deadline} {LEASE_TWO}",
        "/run/aos-network-lease-gate-update.ready",
    )
    vm.succeed(f"{FIXTURE} attach-allow ingress")
    vm.succeed(f"{FIXTURE} attach-allow egress")
    probe("ingress", True, observe=True)
    probe("egress", True, observe=True)
    before_suspend = clocks()
    assert before_suspend["boottime_nanoseconds"] < suspend_deadline
    assert (
        suspend_deadline - before_suspend["boottime_nanoseconds"]
        >= 5_000_000_000
    ), (before_suspend, suspend_deadline)
    vm.succeed(f"{RTCWAKE} -m mem -s 12", timeout=40)
    after_suspend = clocks()
    boottime_delta = (
        after_suspend["boottime_nanoseconds"]
        - before_suspend["boottime_nanoseconds"]
    )
    monotonic_delta = (
        after_suspend["monotonic_nanoseconds"]
        - before_suspend["monotonic_nanoseconds"]
    )
    assert boottime_delta >= 11_000_000_000, (
        before_suspend, after_suspend, boottime_delta, monotonic_delta
    )
    assert boottime_delta - monotonic_delta >= 10_000_000_000, (
        before_suspend, after_suspend, boottime_delta, monotonic_delta
    )
    assert (
        before_suspend["boottime_nanoseconds"] + monotonic_delta
        < suspend_deadline
    ), (before_suspend, after_suspend, suspend_deadline)
    assert after_suspend["boottime_nanoseconds"] >= suspend_deadline, (
        after_suspend, suspend_deadline
    )
    probe("ingress", False)
    probe("egress", False)
    vm.succeed(f"{FIXTURE} detach-allow ingress")
    vm.succeed(f"{FIXTURE} detach-allow egress")
    vm.succeed(f"{FIXTURE} detach-observers")

    # Unknown pin sets are never torn down by guesswork. Removing the update
    # pin or the state entry cannot detach/bypass the packet programs; no future
    # typed update is possible and both hooks remain default-drop.
    vm.succeed(f"{FIXTURE} update disarm")
    vm.succeed(f"{IP} link set {HOST_IF} down")
    vm.succeed("mkdir /sys/fs/bpf/aos/network-lease-gate-proof/unknown")
    vm.fail(f"{FIXTURE} teardown {HOST_IF}")
    vm.succeed("rmdir /sys/fs/bpf/aos/network-lease-gate-proof/unknown")
    vm.succeed(f"{IP} link set {HOST_IF} up")
    vm.succeed(f"{FIXTURE} delete-state")
    vm.fail(f"{FIXTURE} status")
    vm.succeed("rm /sys/fs/bpf/aos/network-lease-gate-proof/lease_state")
    vm.fail(
        f"{FIXTURE} update arm {ASSIGNMENT_EPOCH} 4 "
        f"{second_deadline + 10_000_000_000} {LEASE_TWO}"
    )
    probe("ingress", False)
    probe("egress", False)
  '';
}
