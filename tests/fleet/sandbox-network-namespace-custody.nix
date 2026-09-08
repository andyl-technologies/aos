# Real-systemd qualification for restart-retained Network namespace custody.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
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
          pkgs.aos-sandbox-network-lease-gate
          pkgs.aos-sandbox-network-observer
          pkgs.coreutils
          pkgs.iproute2
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
    import shlex

    FIXTURE = "${fixture}/bin/aos-netd-custody-fixture"
    OBSERVER = "${pkgs.aos-sandbox-network-observer}/bin/aos-sandbox-network-observer"
    GATE_OBJECT = "${pkgs.aos-sandbox-network-lease-gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o"
    IP = "${pkgs.iproute2}/sbin/ip"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    UMOUNT = "${pkgs.util-linux}/bin/umount"
    SETPRIV = "${pkgs.util-linux}/bin/setpriv"
    BUSCTL = "${pkgs.systemd}/bin/busctl"
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

    assert fixture(lifecycle, f"STORE {NAME}", "/run/netns/custody-one") == "STORED"
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
