# Real-systemd qualification for restart-retained Network namespace custody.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  gate = pkgs.aos-sandbox-network-lease-gate;
  gateFixtureSource = ../sandbox/network-lease-gate-fixture.c;
  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-network-systemd-custody-fixture";
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
    pname = "aos-network-observer-gate-fixture";
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
      description = "Test-only loader for production Network observer pins";
      license = "Apache-2.0";
    };
  };

  fakeBusConfig = pkgs.writeTextFile {
    name = "aos-custody-fake-system-bus.conf";
    destination = "/share/aos-custody-fake-system-bus.conf";
    text = ''
      <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
       "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
      <busconfig>
        <type>system</type>
        <listen>unix:path=/run/aos-custody-fake-bus/system_bus_socket</listen>
        <auth>EXTERNAL</auth>
        <policy context="default">
          <allow user="*"/>
          <allow own="*"/>
          <allow send_destination="*"/>
          <allow receive_sender="*"/>
        </policy>
      </busconfig>
    '';
  };

  makeSystem = {
    capacity,
    faultMode ? null,
  }:
    mkSystem [
      ../../systems/server-test.nix
      ({lib, ...}: {
        aos.sandbox.networkBroker = {
          enable = true;
          maximumRetainedNamespaces = capacity;
        };
        aos.image.budgets = {
          maxRootMiB = 704;
          maxDownloadMiB = 832;
        };
        environment.systemPackages = [
          fixture
          gate
          gateFixture
          pkgs.aos-sandbox-network-observer
          pkgs.coreutils
          pkgs.iproute2
          pkgs.jq
          pkgs.nftables
          pkgs.systemd
          pkgs.util-linux
        ];

        # Replace only the executable under test. Every production capability,
        # namespace, address-family, descriptor-store, and hardening setting is
        # inherited unchanged from modules/sandbox/network-broker.nix.
        systemd.services =
          {
            aos-netd = {
              requires = lib.optionals (faultMode != null) ["aos-custody-fake-manager.service"];
              after = lib.optionals (faultMode != null) ["aos-custody-fake-manager.service"];
              serviceConfig =
                {
                  ExecStart = lib.mkForce "${fixture}/bin/aos-netd-custody-fixture serve ${toString capacity}";
                }
                // lib.optionalAttrs (faultMode != null) {
                  # The production inspector still opens its fixed system-bus
                  # path. Only this fixture service's mount namespace sees the
                  # fault bus substituted at that path.
                  BindReadOnlyPaths = "/run/aos-custody-fake-bus/system_bus_socket:/run/dbus/system_bus_socket";
                };
            };
          }
          // lib.optionalAttrs (faultMode != null) {
            aos-custody-fake-bus = {
              description = "Private D-Bus daemon for custody fault qualification";
              wantedBy = ["multi-user.target"];
              serviceConfig = {
                Type = "simple";
                RuntimeDirectory = "aos-custody-fake-bus";
                RuntimeDirectoryMode = "0755";
                ExecStart = "${pkgs.dbus}/bin/dbus-daemon --nofork --nopidfile --config-file=${fakeBusConfig}/share/aos-custody-fake-system-bus.conf";
                Restart = "on-failure";
              };
            };

            aos-custody-fake-manager = {
              description = "Faulting systemd manager facade for custody qualification";
              wantedBy = ["multi-user.target"];
              requires = ["aos-custody-fake-bus.service"];
              after = ["aos-custody-fake-bus.service"];
              serviceConfig = {
                Type = "simple";
                ExecStart = "${fixture}/bin/aos-netd-custody-fixture fake-manager unix:path=/run/aos-custody-fake-bus/system_bus_socket ${faultMode} /run/aos-custody-fake-bus/manager-ready";
                Restart = "on-failure";
                RestartSec = "1s";
              };
            };
          };
      })
    ];
in {
  name = "sandbox-network-namespace-custody";
  timeout = 360;
  bootTimeout = 180;

  machines = {
    lifecycle = {
      system = makeSystem {capacity = 2;};
      memoryMiB = 1024;
    };
    capacity = {
      system = makeSystem {capacity = 1;};
      memoryMiB = 1024;
    };
    denied = {
      system = makeSystem {
        capacity = 2;
        faultMode = "denied";
      };
      memoryMiB = 1024;
    };
    malformed = {
      system = makeSystem {
        capacity = 2;
        faultMode = "malformed";
      };
      memoryMiB = 1024;
    };
    oversized = {
      system = makeSystem {
        capacity = 2;
        faultMode = "oversized";
      };
      memoryMiB = 1024;
    };
  };

  testScript = ''
    import base64
    import json
    import shlex

    FIXTURE = "${fixture}/bin/aos-netd-custody-fixture"
    GATE_FIXTURE = "${gateFixture}/bin/network-lease-gate-fixture"
    GATE_INSTALL_READY = "/run/aos-network-lease-gate-install.ready"
    OBSERVER = "${pkgs.aos-sandbox-network-observer}/bin/aos-sandbox-network-observer"
    GATE_OBJECT = "${gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o"
    BASH = "${pkgs.bash}/bin/bash"
    IP = "${pkgs.iproute2}/sbin/ip"
    JQ = "${pkgs.jq}/bin/jq"
    NFT = "${pkgs.nftables}/sbin/nft"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    UMOUNT = "${pkgs.util-linux}/bin/umount"
    SETPRIV = "${pkgs.util-linux}/bin/setpriv"
    NSENTER = "${pkgs.util-linux}/bin/nsenter"
    BUSCTL = "${pkgs.systemd}/bin/busctl"
    INSTALL = "${pkgs.coreutils}/bin/install"
    SHA256SUM = "${pkgs.coreutils}/bin/sha256sum"
    STAT = "${pkgs.coreutils}/bin/stat"
    STATE_ROOT = "/var/lib/aos/sandbox-network"
    RUNTIME_ROOT = "/run/aos/sandbox-pins/netns"
    CONTROL = f"{STATE_ROOT}/custody-fixture.sock"
    NAME = "aos-network-netns-v1-" + "01" * 32
    HOST_NAME = "aos-network-netns-v1-" + "02" * 32
    SECOND_NAME = "aos-network-netns-v1-" + "03" * 32
    PIN = f"{RUNTIME_ROOT}/{NAME}"

    def fixture(machine, command, *descriptors):
        arguments = " ".join(
            [shlex.quote(FIXTURE), "send", shlex.quote(command)]
            + [shlex.quote(path) for path in descriptors]
        )
        return machine.succeed(arguments).strip()

    def stored_count(machine):
        return int(machine.succeed(
            "systemctl show aos-netd.service "
            "--property=NFileDescriptorStore --value"
        ).strip())

    def dump_store(machine):
        return machine.succeed(
            f"{BUSCTL} call org.freedesktop.systemd1 "
            "/org/freedesktop/systemd1 "
            "org.freedesktop.systemd1.Manager "
            "DumpUnitFileDescriptorStore s aos-netd.service"
        )

    def netnsid_record(output):
        fields = output.split()
        assert len(fields) == 8, output
        assert fields[0] == "NETNSID", output
        assert fields[2] == "CURRENT", output
        assert fields[5] == "PEER", output
        return {
            "namespace_id": int(fields[1]),
            "current_identity": (int(fields[3]), int(fields[4])),
            "peer_identity": (int(fields[6]), int(fields[7])),
        }

    def prepare(machine, namespaces):
        machine.wait_for_unit("multi-user.target", timeout=120)
        machine.succeed("systemctl is-active --quiet aos-netd.socket")
        machine.succeed("systemctl is-active --quiet dbus.socket")
        machine.fail("systemctl is-active --quiet aos-netd.service")
        machine.succeed(f"mkdir -p {STATE_ROOT} {RUNTIME_ROOT}")
        machine.succeed(
            f"${pkgs.coreutils}/bin/stat -Lc '%d %i' /proc/1/ns/net "
            f"> {STATE_ROOT}/trusted-host-netns"
        )
        for namespace, store_name in namespaces:
            pin = f"{RUNTIME_ROOT}/{store_name}"
            machine.succeed(f"{IP} netns add {shlex.quote(namespace)}")
            machine.succeed(f"touch {shlex.quote(pin)}")
            machine.succeed(
                f"{MOUNT} --bind /run/netns/{shlex.quote(namespace)} "
                f"{shlex.quote(pin)}"
            )

        machine.succeed("systemctl start aos-netd.service")
        machine.wait_until_succeeds(
            f'test "$({FIXTURE} send PING)" = PONG',
            timeout=20,
        )
        properties = machine.succeed(
            "systemctl show aos-netd.service "
            "--property=CapabilityBoundingSet "
            "--property=AmbientCapabilities "
            "--property=NoNewPrivileges "
            "--property=PrivateNetwork "
            "--property=RestrictNamespaces "
            "--property=RestrictAddressFamilies"
        )
        values = dict(line.split("=", 1) for line in properties.splitlines())
        assert values["CapabilityBoundingSet"] == "", properties
        assert values["AmbientCapabilities"] == "", properties
        assert values["NoNewPrivileges"] == "yes", properties
        assert values["PrivateNetwork"] == "yes", properties
        assert values["RestrictNamespaces"] == "yes", properties
        assert values["RestrictAddressFamilies"] == "AF_UNIX", properties

    lifecycle.wait_for_unit("multi-user.target", timeout=120)
    assert lifecycle.succeed(
        f"{FIXTURE} artifact-custody {OBSERVER} {GATE_OBJECT}"
    ).strip() == "ARTIFACT_CUSTODY_OK"

    # Qualify descriptor-only RTM_GETNSID in both directions, then construct a
    # same-ifindex false peer split across two other namespaces. The numeric
    # link indices remain reciprocal, and every local namespace ID is assigned,
    # but retained H->A and A->H descriptors reject H->B plus A->C.
    proof_setup = f"""
      set -eu
      {IP} netns add aos-proof-a
      {IP} netns add aos-proof-b
      {IP} netns add aos-proof-c
      {IP} link add name aosproofh address 02:aa:bb:cc:00:02 \
        type veth peer name aosproofs address 02:aa:bb:cc:00:03
      {IP} link set aosproofs netns aos-proof-a
    """
    lifecycle.succeed(f"{BASH} -c {shlex.quote(proof_setup)}")
    initial_host = json.loads(lifecycle.succeed(
        f"{IP} -j -details link show dev aosproofh"
    ))[0]
    initial_sandbox = json.loads(lifecycle.succeed(
        f"{IP} -n aos-proof-a -j -details link show dev aosproofs"
    ))[0]
    initial_host_to_a = netnsid_record(lifecycle.succeed(
        f"{FIXTURE} netnsid /run/netns/aos-proof-a"
    ))
    initial_a_to_host = netnsid_record(lifecycle.succeed(
        f"{NSENTER} --net=/run/netns/aos-proof-a "
        f"{FIXTURE} netnsid /proc/1/ns/net"
    ))
    assert initial_host_to_a["namespace_id"] == initial_host["link_netnsid"], initial_host
    assert initial_a_to_host["namespace_id"] == initial_sandbox["link_netnsid"], initial_sandbox

    host_ifindex = initial_host["ifindex"]
    sandbox_ifindex = initial_host["link_index"]
    adversarial_setup = f"""
      set -eu
      {IP} -n aos-proof-a link set aosproofs netns aos-proof-b
      {IP} -n aos-proof-a link add name aosproofs index {sandbox_ifindex} \
        address 02:aa:bb:cc:00:03 type veth peer name aosproofc \
        index {host_ifindex} address 02:aa:bb:cc:00:02
      {IP} -n aos-proof-a link set aosproofc netns aos-proof-c
    """
    lifecycle.succeed(f"{BASH} -c {shlex.quote(adversarial_setup)}")
    false_host = json.loads(lifecycle.succeed(
        f"{IP} -j -details link show dev aosproofh"
    ))[0]
    false_sandbox = json.loads(lifecycle.succeed(
        f"{IP} -n aos-proof-a -j -details link show dev aosproofs"
    ))[0]
    attack_host_to_a = netnsid_record(lifecycle.succeed(
        f"{FIXTURE} netnsid /run/netns/aos-proof-a"
    ))
    attack_a_to_host = netnsid_record(lifecycle.succeed(
        f"{NSENTER} --net=/run/netns/aos-proof-a "
        f"{FIXTURE} netnsid /proc/1/ns/net"
    ))
    assert false_host["ifindex"] == false_sandbox["link_index"], (false_host, false_sandbox)
    assert false_host["link_index"] == false_sandbox["ifindex"], (false_host, false_sandbox)
    assert false_host["link_netnsid"] >= 0, false_host
    assert false_sandbox["link_netnsid"] >= 0, false_sandbox
    assert attack_host_to_a["current_identity"] == initial_host_to_a["current_identity"]
    assert attack_host_to_a["peer_identity"] == initial_host_to_a["peer_identity"]
    assert attack_a_to_host["current_identity"] == initial_a_to_host["current_identity"]
    assert attack_a_to_host["peer_identity"] == initial_a_to_host["peer_identity"]
    assert attack_host_to_a["namespace_id"] != false_host["link_netnsid"], false_host
    assert attack_a_to_host["namespace_id"] != false_sandbox["link_netnsid"], false_sandbox

    proof_cleanup = f"""
      set -eu
      {IP} link delete aosproofh
      {IP} -n aos-proof-a link delete aosproofs
      {IP} netns delete aos-proof-a
      {IP} netns delete aos-proof-b
      {IP} netns delete aos-proof-c
    """
    lifecycle.succeed(f"{BASH} -c {shlex.quote(proof_cleanup)}")

    # Drive the exported worker through real signed admission, protected
    # preparation/operation/catalog state, an nsfs pin, and retained activation
    # custody. Planning is separate so the controller can construct the exact
    # handle-derived pin and managed veth names before observation.
    qualification_root = f"{STATE_ROOT}/observer-qualification"

    # The observer runs before aos-netd starts, so systemd has not created the
    # service's fixed RuntimeDirectory yet. Reproduce that root-owned protected
    # directory contract explicitly; earlier fixture cleanup may have removed
    # the complete parent path.
    lifecycle.succeed(
        f"{INSTALL} -d -o 0 -g 0 -m 0700 {RUNTIME_ROOT}; "
        f"test \"$({STAT} -c '%u:%g:%a' {RUNTIME_ROOT})\" = 0:0:700"
    )

    def prepare_observer_state(mode):
        state_root = f"{qualification_root}/{mode}"
        lifecycle.succeed(
            f"mkdir -p {state_root}/preparation {state_root}/operations "
            f"{state_root}/namespaces; chmod 0700 {state_root} "
            f"{state_root}/preparation {state_root}/operations "
            f"{state_root}/namespaces"
        )
        fields = lifecycle.succeed(
            f"{FIXTURE} observer-plan {mode} {state_root} {GATE_OBJECT}"
        ).split()
        assert len(fields) == 17 and fields[0] == "OBSERVER_PLAN", fields
        store_name = fields[1]
        prefix = "aos-network-netns-v1-"
        assert store_name.startswith(prefix), store_name
        return state_root, fields, f"{RUNTIME_ROOT}/{store_name[len(prefix):]}"

    fixture_digest = lifecycle.succeed(f"{SHA256SUM} {FIXTURE}").split()[0]
    gate_digest = lifecycle.succeed(f"{SHA256SUM} {GATE_OBJECT}").split()[0]

    def namespace_nft(namespace, statement):
        lifecycle.succeed(
            f"{IP} netns exec {namespace} {NFT} {shlex.quote(statement)}"
        )

    def install_default_drop_table(namespace, enforcement_digest, policy_digest):
        encoded_enforcement = base64.urlsafe_b64encode(
            bytes.fromhex(enforcement_digest)
        ).decode("ascii").rstrip("=")
        encoded_policy = base64.urlsafe_b64encode(
            bytes.fromhex(policy_digest)
        ).decode("ascii").rstrip("=")
        provenance = f"aos.net.v1:a={encoded_enforcement}:p={encoded_policy}"
        assert len(encoded_enforcement) == 43
        assert len(encoded_policy) == 43
        assert len(provenance) == 102
        namespace_nft(
            namespace,
            f'add table inet aos_sandbox {{ comment "{provenance}"; }}',
        )
        namespace_nft(
            namespace,
            "add chain inet aos_sandbox ingress "
            "{ type filter hook input priority 0; policy drop; }",
        )
        namespace_nft(
            namespace,
            "add chain inet aos_sandbox egress "
            "{ type filter hook output priority 0; policy drop; }",
        )

    isolated_root, isolated_plan, isolated_pin = prepare_observer_state("isolated")
    isolated_enforcement_digest = isolated_plan[12]
    isolated_policy_digest = isolated_plan[13]
    assert fixture_digest == isolated_enforcement_digest
    isolated_setup = f"""
      set -eu
      {IP} netns add aos-observe-isolated
      {IP} -n aos-observe-isolated link set lo up
      touch {isolated_pin}
      {MOUNT} --bind /run/netns/aos-observe-isolated {isolated_pin}
    """
    lifecycle.succeed(f"{BASH} -c {shlex.quote(isolated_setup)}")
    assert lifecycle.succeed(
        f"{FIXTURE} observer-run isolated {isolated_root} "
        f"{isolated_pin} {IP} {GATE_OBJECT}"
    ).strip() == "OBSERVER_OK isolated"
    install_default_drop_table(
        "aos-observe-isolated",
        isolated_enforcement_digest,
        isolated_policy_digest,
    )
    assert lifecycle.succeed(
        f"{FIXTURE} observer-kernel-run isolated {isolated_root} "
        f"{isolated_pin} {IP} {NFT} {FIXTURE} {OBSERVER} {GATE_OBJECT}"
    ).strip() == "KERNEL_OBSERVER_OK isolated"

    managed_root, managed_plan, managed_pin = prepare_observer_state("managed")
    (
        _,
        _,
        managed_host,
        managed_sandbox,
        managed_host_mac,
        managed_sandbox_mac,
        managed_host_address_1,
        managed_sandbox_address_1,
        managed_prefix_1,
        managed_host_address_2,
        managed_sandbox_address_2,
        managed_prefix_2,
        managed_enforcement_digest,
        managed_policy_digest,
        managed_assignment_epoch,
        managed_assignment_digest,
        managed_allocation_generation,
    ) = managed_plan
    managed_handle = managed_plan[1].removeprefix("aos-network-netns-v1-")
    assert len(managed_handle) == 64
    assert fixture_digest == managed_enforcement_digest
    managed_setup = f"""
      set -eu
      {IP} netns add aos-observe-managed
      {IP} netns add aos-observe-wrong-host-peer
      {IP} netns add aos-observe-wrong-sandbox-peer
      {IP} -n aos-observe-managed link set lo up
      {IP} link add name {managed_host} address {managed_host_mac} \
        type veth peer name {managed_sandbox} address {managed_sandbox_mac}
      {IP} link set {managed_sandbox} netns aos-observe-managed
      {IP} link set dev {managed_host} addrgenmode none
      {IP} -n aos-observe-managed link set dev {managed_sandbox} addrgenmode none
      {IP} address add {managed_host_address_1}/{managed_prefix_1} dev {managed_host}
      {IP} address add {managed_host_address_2}/{managed_prefix_2} dev {managed_host}
      {IP} -n aos-observe-managed address add \
        {managed_sandbox_address_1}/{managed_prefix_1} dev {managed_sandbox}
      {IP} -n aos-observe-managed address add \
        {managed_sandbox_address_2}/{managed_prefix_2} dev {managed_sandbox}
      touch {managed_pin}
      {MOUNT} --bind /run/netns/aos-observe-managed {managed_pin}
    """
    lifecycle.succeed(f"{BASH} -c {shlex.quote(managed_setup)}")
    lifecycle.succeed(
        f"{INSTALL} -d -o 0 -g 0 -m 0755 /sys/fs/bpf/aos/sandbox-network"
    )
    lifecycle.succeed(f"rm -f {GATE_INSTALL_READY}")
    lifecycle.succeed(
        f"systemd-run --unit=aos-observer-gate-loader --collect "
        f"--service-type=simple {GATE_FIXTURE} install-observer-hold "
        f"{managed_host} {managed_sandbox} {managed_pin} "
        f"{managed_assignment_epoch} {managed_allocation_generation} "
        f"{managed_handle} {managed_assignment_digest} {gate_digest}"
    )
    lifecycle.wait_until_succeeds(f"test -s {GATE_INSTALL_READY}", timeout=20)
    lifecycle.succeed(f"{IP} link set {managed_host} up")
    lifecycle.succeed(
        f"{IP} -n aos-observe-managed link set {managed_sandbox} up"
    )
    addresses_are_settled = "all(.[].addr_info[]; ((.tentative // false) == false))"
    lifecycle.wait_until_succeeds(
        f"{IP} -j address show dev {managed_host} | "
        f"{JQ} -e {shlex.quote(addresses_are_settled)} >/dev/null",
        timeout=10,
    )
    lifecycle.wait_until_succeeds(
        f"{IP} -n aos-observe-managed -j address show dev {managed_sandbox} | "
        f"{JQ} -e {shlex.quote(addresses_are_settled)} >/dev/null",
        timeout=10,
    )
    assert lifecycle.succeed(
        f"{FIXTURE} observer-run managed {managed_root} {managed_pin} {IP} "
        f"{GATE_OBJECT}"
    ).strip() == "OBSERVER_OK managed"

    # Install the exact plan-selected default-drop table in the same retained
    # namespace, inspect actual AOS nft JSON, and decode two complete snapshots
    # through retained immutable nft and loader descriptors.
    managed_sandbox_ifindex = json.loads(lifecycle.succeed(
        f"{IP} -n aos-observe-managed -j link show dev {managed_sandbox}"
    ))[0]["ifindex"]
    endpoint_id = "51" * 16

    def managed_nft(statement):
        namespace_nft("aos-observe-managed", statement)

    install_default_drop_table(
        "aos-observe-managed",
        managed_enforcement_digest,
        managed_policy_digest,
    )
    managed_ipv4_addresses = f"{{ {managed_sandbox_address_1} }}"
    managed_ipv6_addresses = f"{{ {managed_sandbox_address_2} }}"
    managed_nft(
        f"add rule inet aos_sandbox ingress meta iif {managed_sandbox_ifindex} "
        f"ip daddr != {managed_ipv4_addresses} drop "
        'comment "aos.sandbox.network.rule.v1 anti-spoof"'
    )
    managed_nft(
        f"add rule inet aos_sandbox egress meta oif {managed_sandbox_ifindex} "
        f"ip saddr != {managed_ipv4_addresses} drop "
        'comment "aos.sandbox.network.rule.v1 anti-spoof"'
    )
    managed_nft(
        f"add rule inet aos_sandbox ingress meta iif {managed_sandbox_ifindex} "
        f"ip6 daddr != {managed_ipv6_addresses} drop "
        'comment "aos.sandbox.network.rule.v1 anti-spoof"'
    )
    managed_nft(
        f"add rule inet aos_sandbox egress meta oif {managed_sandbox_ifindex} "
        f"ip6 saddr != {managed_ipv6_addresses} drop "
        'comment "aos.sandbox.network.rule.v1 anti-spoof"'
    )
    managed_nft(
        "add rule inet aos_sandbox ingress ip6 saddr 2001:db8::1 "
        "tcp dport 8443 accept "
        f'comment "aos.sandbox.network.rule.v1 flow={endpoint_id}"'
    )
    managed_nft(
        "add rule inet aos_sandbox ingress ip saddr 198.51.100.7 "
        "udp dport 53-54 accept "
        f'comment "aos.sandbox.network.rule.v1 flow={endpoint_id}"'
    )
    managed_nft(
        "add rule inet aos_sandbox ingress ip6 saddr 2001:db8:1::/64 "
        "meta l4proto 58 accept "
        f'comment "aos.sandbox.network.rule.v1 flow={endpoint_id}"'
    )
    managed_nft(
        "add rule inet aos_sandbox egress ip daddr 10.80.0.0/16 "
        "tcp dport 443 accept "
        f'comment "aos.sandbox.network.rule.v1 flow={endpoint_id}"'
    )
    managed_nft(
        "add rule inet aos_sandbox egress ip6 daddr 2001:db8:2::/64 "
        "udp dport 1000-1005 accept "
        f'comment "aos.sandbox.network.rule.v1 flow={endpoint_id}"'
    )
    managed_nft(
        "add rule inet aos_sandbox egress ip daddr 203.0.113.0/24 "
        "meta l4proto 1 accept "
        f'comment "aos.sandbox.network.rule.v1 flow={endpoint_id}"'
    )
    actual_nft_json = lifecycle.succeed(
        f"{IP} netns exec aos-observe-managed {NFT} --json --handle "
        "--numeric --numeric-priority list table inet aos_sandbox"
    )
    print(actual_nft_json)
    assert lifecycle.succeed(
        f"{NSENTER} --net={managed_pin} {FIXTURE} nft-observe {IP} {NFT} {FIXTURE} "
        f"{GATE_OBJECT} "
        f"{managed_sandbox_ifindex} {managed_sandbox_address_1} "
        f"{managed_sandbox_address_2}"
    ).strip() == "NFT_OBSERVER_OK"
    assert lifecycle.succeed(
        f"{FIXTURE} observer-kernel-run managed {managed_root} {managed_pin} "
        f"{IP} {NFT} {FIXTURE} {OBSERVER} {GATE_OBJECT}"
    ).strip() == "KERNEL_OBSERVER_OK managed"

    # Observer-scoped cleanup must not touch the fixed-root pins used by the
    # independent lease-gate proof fixture.
    default_gate_root = "/sys/fs/bpf/aos/network-lease-gate-proof"
    default_scope_sentinel = f"{default_gate_root}/deny_ingress_link"
    lifecycle.succeed(f"mkdir -p {default_scope_sentinel}")
    lifecycle.succeed(
        "systemctl kill --kill-whom=main --signal=KILL "
        "aos-observer-gate-loader.service"
    )
    lifecycle.succeed(
        f"{GATE_FIXTURE} force-observer-teardown {managed_handle}"
    )
    lifecycle.succeed(f"test -d {default_scope_sentinel}")
    lifecycle.succeed(f"rmdir {default_scope_sentinel} {default_gate_root}")

    managed_host_link = json.loads(lifecycle.succeed(
        f"{IP} -j -details link show dev {managed_host}"
    ))[0]
    managed_sandbox_link = json.loads(lifecycle.succeed(
        f"{IP} -n aos-observe-managed -j -details link show dev {managed_sandbox}"
    ))[0]
    managed_host_ifindex = managed_host_link["ifindex"]
    managed_sandbox_ifindex = managed_sandbox_link["ifindex"]
    managed_host_mtu = managed_host_link["mtu"]
    managed_sandbox_mtu = managed_sandbox_link["mtu"]
    managed_attack = f"""
      set -eu
      {IP} -n aos-observe-managed link set {managed_sandbox} \
        netns aos-observe-wrong-host-peer
      {IP} -n aos-observe-wrong-host-peer link set {managed_sandbox} up
      {IP} -n aos-observe-managed link add name {managed_sandbox} \
        index {managed_sandbox_ifindex} address {managed_sandbox_mac} \
        type veth peer name aosobwrong index {managed_host_ifindex} \
        address {managed_host_mac}
      {IP} -n aos-observe-managed link set {managed_sandbox} \
        mtu {managed_sandbox_mtu} addrgenmode none up
      {IP} -n aos-observe-managed link set aosobwrong \
        mtu {managed_host_mtu} addrgenmode none up
      {IP} -n aos-observe-managed link set aosobwrong \
        netns aos-observe-wrong-sandbox-peer
      {IP} -n aos-observe-wrong-sandbox-peer link set aosobwrong up
    """
    lifecycle.succeed(f"{BASH} -c {shlex.quote(managed_attack)}")
    false_managed_host = json.loads(lifecycle.succeed(
        f"{IP} -j -details link show dev {managed_host}"
    ))[0]
    false_managed_sandbox = json.loads(lifecycle.succeed(
        f"{IP} -n aos-observe-managed -j -details link show dev {managed_sandbox}"
    ))[0]
    expected_veth_flags = {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}
    assert false_managed_host["ifindex"] == managed_host_ifindex, false_managed_host
    assert false_managed_host["link_index"] == managed_sandbox_ifindex, false_managed_host
    assert false_managed_host["ifname"] == managed_host, false_managed_host
    assert false_managed_host["address"] == managed_host_mac, false_managed_host
    assert false_managed_host["mtu"] == managed_host_mtu, false_managed_host
    assert false_managed_host["linkinfo"]["info_kind"] == "veth", false_managed_host
    assert set(false_managed_host["flags"]) == expected_veth_flags, false_managed_host

    assert false_managed_sandbox["ifindex"] == managed_sandbox_ifindex, false_managed_sandbox
    assert false_managed_sandbox["link_index"] == managed_host_ifindex, false_managed_sandbox
    assert false_managed_sandbox["ifname"] == managed_sandbox, false_managed_sandbox
    assert false_managed_sandbox["address"] == managed_sandbox_mac, false_managed_sandbox
    assert false_managed_sandbox["mtu"] == managed_sandbox_mtu, false_managed_sandbox
    assert false_managed_sandbox["linkinfo"]["info_kind"] == "veth", false_managed_sandbox
    assert set(false_managed_sandbox["flags"]) == expected_veth_flags, false_managed_sandbox

    rejected_status, rejected_stdout, rejected_stderr = lifecycle.execute(
        f"{FIXTURE} observer-run managed {managed_root} {managed_pin} {IP} "
        f"{GATE_OBJECT}"
    )
    rejected_output = rejected_stdout + rejected_stderr
    assert rejected_status != 0, rejected_output
    assert b"observer rejected after restoring initial host namespace" in rejected_output, rejected_output
    assert b"veth peer identity does not match reciprocal retained-descriptor proof" in rejected_output, rejected_output

    # Root-owned immutable store outputs are admitted, but neither a writable
    # artifact nor a symlink at the leaf or store-entry boundary is custody.
    bad_hash = "0" * 32
    bad_root = f"/nix/store/{bad_hash}-network-observer-negative"
    lifecycle.succeed(
        f"mkdir -p {bad_root}/bin; "
        f"cp {OBSERVER} {bad_root}/bin/writable-helper; "
        f"ln -s {OBSERVER} {bad_root}/bin/symlink-helper; "
        f"chmod 0555 {bad_root} {bad_root}/bin; "
        f"chmod 0755 {bad_root}/bin/writable-helper"
    )
    lifecycle.fail(
        f"{FIXTURE} artifact-custody "
        f"{bad_root}/bin/writable-helper {GATE_OBJECT}"
    )
    lifecycle.fail(
        f"{FIXTURE} artifact-custody "
        f"{bad_root}/bin/symlink-helper {GATE_OBJECT}"
    )
    replaced_hash = "1" * 32
    replaced_root = f"/nix/store/{replaced_hash}-network-observer-replaced"
    lifecycle.succeed(f"ln -s {bad_root} {replaced_root}")
    lifecycle.fail(
        f"{FIXTURE} artifact-custody "
        f"{replaced_root}/bin/writable-helper {GATE_OBJECT}"
    )

    prepare(lifecycle, [("custody-one", NAME)])

    # The trusted controller, not the capability-free fixture, creates and
    # pins the namespace. Its PID 1 identity is separately supplied so the
    # fixture can reject the actual host namespace despite PrivateNetwork=yes.
    assert fixture(lifecycle, "PING") == "PONG"

    # Filesystem permissions are relaxed only long enough to demonstrate that
    # the listener authenticates each packet's kernel credentials itself.
    lifecycle.succeed(f"chmod 0711 {STATE_ROOT}; chmod 0666 {CONTROL}")
    untrusted = lifecycle.succeed(
        f"{SETPRIV} --reuid 65534 --regid 65534 --clear-groups "
        f"{FIXTURE} send PING"
    ).strip()
    lifecycle.succeed(f"chmod 0600 {CONTROL}; chmod 0700 {STATE_ROOT}")
    assert untrusted.startswith("ERROR control command is not from root:root"), untrusted
    assert fixture(lifecycle, "PING") == "PONG"

    # Exact control framing rejects extra descriptors and truncation without
    # killing the serving process or mutating the real manager store.
    descriptor_mismatch = fixture(lifecycle, "PING", "/proc/self/ns/net")
    assert descriptor_mismatch.startswith("ERROR control command descriptor count"), descriptor_mismatch
    truncated_command = fixture(lifecycle, "X" * 300)
    assert truncated_command.startswith("ERROR truncated control command"), truncated_command
    assert fixture(lifecycle, "PING") == "PONG"
    assert stored_count(lifecycle) == 0

    host_rejection = fixture(lifecycle, f"STORE {HOST_NAME}", "/proc/1/ns/net")
    assert host_rejection.startswith("ERROR Network namespace descriptor replay conflicts"), host_rejection
    assert stored_count(lifecycle) == 0

    initial_store = fixture(lifecycle, f"STORE {NAME}", "/run/netns/custody-one")
    assert initial_store == "STORED", initial_store
    assert stored_count(lifecycle) == 1
    initial_dump = dump_store(lifecycle)
    assert NAME in initial_dump, initial_dump
    assert fixture(lifecycle, f"STORE {NAME}", "/run/netns/custody-one") == "REPLAY"
    assert stored_count(lifecycle) == 1

    # Remove the source pin: both the canonical pin and systemd's retained FD
    # independently keep the namespace object alive.
    lifecycle.succeed(f"{IP} netns delete custody-one")
    lifecycle.succeed(f"test -e {PIN}")

    original_pid = lifecycle.succeed(
        "systemctl show aos-netd.service --property=MainPID --value"
    ).strip()
    lifecycle.succeed(
        "systemctl kill --kill-whom=main --signal=SIGKILL aos-netd.service"
    )
    lifecycle.wait_until_succeeds(
        "new=$(systemctl show aos-netd.service --property=MainPID --value); "
        f"test \"$new\" != 0 -a \"$new\" != {shlex.quote(original_pid)}",
        timeout=20,
    )
    lifecycle.wait_until_succeeds(
        f'test "$({FIXTURE} send PING)" = PONG',
        timeout=20,
    )
    assert stored_count(lifecycle) == 1
    assert NAME in dump_store(lifecycle)

    before_restart = lifecycle.succeed(
        "systemctl show aos-netd.service --property=MainPID --value"
    ).strip()
    lifecycle.succeed("systemctl restart aos-netd.service")
    lifecycle.wait_until_succeeds(
        "new=$(systemctl show aos-netd.service --property=MainPID --value); "
        f"test \"$new\" != 0 -a \"$new\" != {shlex.quote(before_restart)}",
        timeout=20,
    )
    lifecycle.wait_until_succeeds(
        f'test "$({FIXTURE} send PING)" = PONG',
        timeout=20,
    )
    assert stored_count(lifecycle) == 1

    # A deliberate stop preserves systemd custody but removes the runtime pin
    # once the controller unmounts it. The subsequent start must fail closed
    # against the still-protected requirement instead of serving without a pin.
    lifecycle.succeed(f"{UMOUNT} {PIN}")
    lifecycle.succeed(f"touch {RUNTIME_ROOT}/explicit-stop-marker")
    lifecycle.succeed("systemctl stop aos-netd.service")
    assert stored_count(lifecycle) == 1
    lifecycle.fail(f"test -e {RUNTIME_ROOT}/explicit-stop-marker")
    lifecycle.fail(f"test -e {PIN}")
    lifecycle.succeed("systemctl start aos-netd.service || true", timeout=30)
    lifecycle.wait_until_succeeds(
        "state=$(systemctl show aos-netd.service --property=ActiveState --value); "
        'test "$state" = failed -o "$state" = inactive',
        timeout=30,
    )
    lifecycle.fail(f"{FIXTURE} send PING")
    assert stored_count(lifecycle) == 1
    lifecycle.succeed(
        "journalctl -u aos-netd.service --no-pager "
        "| grep -F 'open canonical namespace pin'"
    )

    # A separate one-slot unit makes the main process send both notifications
    # before a single barrier. PID 1 accepts the first and silently rejects the
    # second; this is distinct from the adapter's local capacity precheck.
    prepare(capacity, [("capacity-one", NAME), ("capacity-two", SECOND_NAME)])
    response = fixture(
        capacity,
        f"CAPACITY {NAME} {SECOND_NAME}",
        "/run/netns/capacity-one",
        "/run/netns/capacity-two",
    )
    assert response == "CAPACITY_PROBED", response
    assert stored_count(capacity) == 1
    capacity_dump = dump_store(capacity)
    assert NAME in capacity_dump, capacity_dump
    assert SECOND_NAME not in capacity_dump, capacity_dump

    def qualify_fault(machine, namespace, expected_fragment):
        machine.wait_for_unit("multi-user.target", timeout=120)
        machine.wait_until_succeeds(
            "test -f /run/aos-custody-fake-bus/manager-ready",
            timeout=30,
        )
        prepare(machine, [(namespace, NAME)])

        bind = machine.succeed(
            "systemctl show aos-netd.service "
            "--property=BindReadOnlyPaths --value"
        ).strip()
        assert "/run/aos-custody-fake-bus/system_bus_socket" in bind, bind
        assert "/run/dbus/system_bus_socket" in bind, bind

        ambiguous = fixture(machine, f"STORE {NAME}", f"/run/netns/{namespace}")
        assert "outcome is ambiguous" in ambiguous.lower(), ambiguous

        # The notification and barrier went to real PID 1. Host busctl remains
        # outside the fixture mount namespace and proves that retention before
        # the substituted observer made the result ambiguous.
        assert stored_count(machine) == 1
        actual_dump = dump_store(machine)
        assert NAME in actual_dump, actual_dump

        poisoned = fixture(machine, f"STORE {NAME}", f"/run/netns/{namespace}")
        assert "poisoned until process restart" in poisoned.lower(), poisoned
        assert expected_fragment in ambiguous.lower(), ambiguous
        assert stored_count(machine) == 1

    qualify_fault(denied, "fault-denied", "fixture denies the post-mutation dump")
    qualify_fault(malformed, "fault-malformed", "manager returned a noncanonical name")
    qualify_fault(oversized, "fault-oversized", "manager capacity, count, and row set disagree")
  '';
}
