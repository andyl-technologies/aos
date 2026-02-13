# lib/testing/fleet.nix — Multi-VM test orchestrator
#
# Boots multiple QEMU VMs connected via multicast socket networking.
# Each machine has its own virtio-serial agent for independent control.
# The test script can run commands on any machine by name and assert
# on the results.
#
# Architecture:
#   - Each machine gets a separate QEMU process with its own agent socket
#   - Machines are connected via QEMU multicast socket networking (L2 segment)
#   - Static IPs assigned via systemd-networkd (192.168.50.0/24 subnet)
#   - The test script uses run_on/assert_on/assert_output_on helpers
#   - Direct kernel boot (-kernel flag) for each machine
#   - All machines are shut down after the test completes

{
  pkgs,
  lib,
  testTools ? { },
}:

let
  vmLib = import ./vm.nix { inherit pkgs lib testTools; };
  assertions = import ./assertions.nix;

  qemu = testTools.qemu;
  hostSocat = pkgs.socat;
  hostJq = pkgs.jq;

  mkFleetTest =
    {
      name,
      machines,
      testScript,
      timeout ? 300,
    }:
    let
      machineNames = builtins.attrNames machines;

      # Assign sequential IPs: 192.168.50.10, .11, .12, ...
      machinesWithIndex = lib.imap0 (i: mname: {
        name = mname;
        machine = machines.${mname};
        ip = "192.168.50.${builtins.toString (i + 10)}";
        mac = machines.${mname}.mac or "52:54:00:00:00:${builtins.toString (i + 1)}";
      }) machineNames;

      # Build /etc/hosts entries for all machines
      hostsEntries = lib.concatStringsSep "\n" (builtins.map (m: "${m.ip} ${m.name}") machinesWithIndex);

      # Build network config for a specific machine
      mkNetworkConfig =
        m:
        lib.concatStringsSep "\n" [
          "[Match]"
          "Name=eth0"
          ""
          "[Network]"
          "Address=${m.ip}/24"
        ];

    in
    pkgs.mkDerivation {
      pname = "aos-fleet-test-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        hostSocat
        hostJq
        qemu
      ];

      phases = [
        {
          name = "test";
          script = ''
            set -euo pipefail

            FLEET_DIR="$TMPDIR/fleet"
            mkdir -p "$FLEET_DIR"

            # Clear LD_LIBRARY_PATH — AOS build libs can conflict with QEMU
            unset LD_LIBRARY_PATH

            PIDS=""

            # Cleanup handler: kill all QEMU processes
            cleanup() {
              for pid in $PIDS; do
                kill "$pid" 2>/dev/null || true
              done
              wait 2>/dev/null || true
            }
            trap cleanup EXIT

            # ----------------------------------------------------------
            # Launch each machine
            # ----------------------------------------------------------
            ${lib.concatStringsSep "\n" (
              builtins.map (
                m:
                let
                  image = vmLib.mkTestRootfs {
                    system = m.machine.system;
                    name = m.name;
                    hostname = m.name;
                    networkConfig = mkNetworkConfig m;
                    hostsEntries = hostsEntries;
                  };
                  kernel = m.machine.system.config.system.build.kernel;
                in
                ''
                  echo "Starting machine: ${m.name} (role: ${m.machine.role or "worker"}, ip: ${m.ip})"

                  AGENT_SOCK_${m.name}="$FLEET_DIR/${m.name}-agent.sock"
                  SERIAL_LOG_${m.name}="$FLEET_DIR/${m.name}-serial.log"

                  # Copy rootfs to writable location
                  cp "${image}" "$FLEET_DIR/${m.name}-rootfs.img"
                  chmod u+w "$FLEET_DIR/${m.name}-rootfs.img"

                  # Find kernel image
                  VMLINUZ_${m.name}=$(ls ${kernel}/boot/vmlinuz-* | head -1)

                  qemu-system-x86_64 \
                    -machine q35,accel=kvm \
                    -cpu host \
                    -m 2048 \
                    -smp 2 \
                    -nographic \
                    -kernel "''${VMLINUZ_${m.name}}" \
                    -append "root=/dev/vda rw console=ttyS0 init=/sbin/init panic=1 net.ifnames=0" \
                    -drive file="$FLEET_DIR/${m.name}-rootfs.img",format=raw,if=virtio \
                    -device virtio-serial \
                    -device virtserialport,chardev=agent,name=aos.test.agent \
                    -chardev socket,id=agent,path="$AGENT_SOCK_${m.name}",server=on,wait=off \
                    -serial file:"$SERIAL_LOG_${m.name}" \
                    -netdev socket,id=net0,mcast=230.0.0.1:1234 \
                    -device virtio-net-pci,netdev=net0,mac=${m.mac} \
                    -no-reboot > "$FLEET_DIR/${m.name}-qemu.log" 2>&1 &
                  PIDS="$PIDS $!"
                ''
              ) machinesWithIndex
            )}

            sleep 2

            # ----------------------------------------------------------
            # Wait for all agents to become ready (PING/PONG)
            # ----------------------------------------------------------
            DEADLINE=$((SECONDS + ${builtins.toString timeout}))
            ${lib.concatStringsSep "\n" (
              builtins.map (m: ''
                echo "Waiting for ${m.name}..."
                while [ "$SECONDS" -lt "$DEADLINE" ]; do
                  if [ -S "''${AGENT_SOCK_${m.name}}" ]; then
                    RESPONSE=$( (printf 'PING\n'; sleep 5) | socat - UNIX-CONNECT:"''${AGENT_SOCK_${m.name}}" 2>/dev/null | head -1 || true)
                    if echo "$RESPONSE" | grep -q '"ready"'; then
                      echo "${m.name} ready."
                      break
                    fi
                  fi
                  sleep 1
                done
              '') machinesWithIndex
            )}

            if [ "$SECONDS" -ge "$DEADLINE" ]; then
              echo "TIMEOUT: Not all machines became ready within ${builtins.toString timeout}s"
              ${lib.concatStringsSep "\n" (
                builtins.map (m: ''
                  echo "--- ${m.name} serial log ---"
                  cat "$SERIAL_LOG_${m.name}" 2>/dev/null || true
                  echo "--- ${m.name} qemu log ---"
                  cat "$FLEET_DIR/${m.name}-qemu.log" 2>/dev/null || true
                '') machinesWithIndex
              )}
              exit 1
            fi

            # Import shared fleet test helpers (run_on, assert_on, assert_output_on)
            ${assertions.mkFleetHelpers "${hostSocat}/bin/socat"}

            # ----------------------------------------------------------
            # Run fleet test script
            # ----------------------------------------------------------
            echo ""
            echo "==> Running fleet test: ${name}"
            echo ""

            ${testScript}

            # ----------------------------------------------------------
            # Shutdown all machines
            # ----------------------------------------------------------
            echo ""
            echo "Shutting down fleet..."
            ${lib.concatStringsSep "\n" (
              builtins.map (m: ''
                (printf 'SHUTDOWN\n'; sleep 2) | socat - UNIX-CONNECT:"''${AGENT_SOCK_${m.name}}" 2>/dev/null || true
              '') machinesWithIndex
            )}
            sleep 2
            wait 2>/dev/null || true
            trap - EXIT

            echo ""
            echo "==> Fleet test passed: ${name}"
            mkdir -p $out
            echo "PASS" > $out/result
            ${lib.concatStringsSep "\n" (
              builtins.map (m: ''
                cp "$SERIAL_LOG_${m.name}" "$out/${m.name}-serial.log" 2>/dev/null || true
              '') machinesWithIndex
            )}
          '';
        }
      ];

      requiredSystemFeatures = [ "kvm" ];
    };

in
{
  inherit mkFleetTest;
}
