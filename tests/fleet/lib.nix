# tests/fleet/lib.nix — Multi-VM test orchestrator
#
# Boots multiple QEMU VMs connected via socket networking. Each machine
# has its own virtio-serial agent for independent control. The test script
# can run commands on any machine by name and assert on the results.
#
# Architecture:
#   - Each machine gets a separate QEMU process with its own agent socket
#   - Machines are connected via QEMU socket networking (listen/connect)
#   - The test script uses run_on/assert_on helpers with machine names
#   - All machines are shut down after the test completes
#
# Network layout:
#   Each machine is assigned a unique MAC address and port for socket
#   networking. The first machine listens, subsequent machines connect.

{ pkgs, lib }:

let
  vmLib = import ../vm/lib.nix { inherit pkgs lib; };

  mkFleetTest = { name, machines, testScript, timeout ? 300 }:
    let
      machineNames = builtins.attrNames machines;
      machineCount = builtins.length machineNames;
    in
    pkgs.mkDerivation {
      pname = "aos-fleet-test-${name}";
      version = "0";
      src = null;

      buildDeps = [ pkgs.socat ];

      phases = [
        {
          name = "test";
          script = ''
            set -euo pipefail

            FLEET_DIR="$TMPDIR/fleet"
            mkdir -p "$FLEET_DIR"

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
            ${lib.concatStringsSep "\n" (builtins.map (machineName:
              let
                machine = machines.${machineName};
                image = vmLib.mkTestImage {
                  system = machine.system;
                  name = machineName;
                };
                netPort = builtins.toString (machine.netPort or 10000);
                mac = machine.mac or "52:54:00:00:00:01";
              in ''
                echo "Starting machine: ${machineName} (role: ${machine.role or "worker"})"

                AGENT_SOCK_${machineName}="$FLEET_DIR/${machineName}-agent.sock"
                MONITOR_SOCK_${machineName}="$FLEET_DIR/${machineName}-monitor.sock"
                SERIAL_LOG_${machineName}="$FLEET_DIR/${machineName}-serial.log"

                qemu-system-x86_64 \
                  -machine q35,accel=kvm \
                  -cpu host \
                  -m 2048 \
                  -smp 2 \
                  -nographic \
                  -drive file="${image}",format=raw,if=virtio,readonly=on \
                  -device virtio-serial \
                  -device virtserialport,chardev=agent,name=aos.test.agent \
                  -chardev socket,id=agent,path="$AGENT_SOCK_${machineName}",server=on,wait=off \
                  -monitor unix:"$MONITOR_SOCK_${machineName}",server,nowait \
                  -serial file:"$SERIAL_LOG_${machineName}" \
                  -netdev socket,id=net0,listen=:${netPort} \
                  -device virtio-net-pci,netdev=net0,mac=${mac} \
                  -no-reboot &
                PIDS="$PIDS $!"
              ''
            ) machineNames)}

            # ----------------------------------------------------------
            # Wait for all agents to become ready
            # ----------------------------------------------------------
            DEADLINE=$((SECONDS + ${builtins.toString timeout}))
            for machine in ${lib.concatStringsSep " " machineNames}; do
              echo "Waiting for $machine..."
              SOCK_VAR="AGENT_SOCK_$machine"
              while [ "$SECONDS" -lt "$DEADLINE" ]; do
                if [ -S "''${!SOCK_VAR}" ]; then
                  RESPONSE=$(timeout 5 ${pkgs.socat}/bin/socat - UNIX-CONNECT:"''${!SOCK_VAR}" 2>/dev/null || true)
                  if echo "$RESPONSE" | grep -q '"ready"'; then
                    echo "$machine ready."
                    break
                  fi
                fi
                sleep 1
              done
            done

            if [ "$SECONDS" -ge "$DEADLINE" ]; then
              echo "TIMEOUT: Not all machines became ready within ${builtins.toString timeout}s"
              exit 1
            fi

            # ----------------------------------------------------------
            # Fleet test helper functions
            # ----------------------------------------------------------

            # Run a command on a specific machine
            run_on() {
              local machine="$1"
              local cmd="$2"
              local sock_var="AGENT_SOCK_$machine"
              echo "$cmd" | ${pkgs.socat}/bin/socat - UNIX-CONNECT:"''${!sock_var}"
            }

            # Assert a command succeeds on a specific machine
            assert_on() {
              local machine="$1"
              local cmd="$2"
              local desc="''${3:-[$machine] $cmd}"
              RESULT=$(run_on "$machine" "$cmd")
              EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
              if [ "$EXIT_CODE" != "0" ]; then
                echo "FAIL: $desc"
                echo "  stdout: $(echo "$RESULT" | jq -r '.stdout')"
                echo "  stderr: $(echo "$RESULT" | jq -r '.stderr')"
                return 1
              fi
              echo "PASS: $desc"
            }

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
            for machine in ${lib.concatStringsSep " " machineNames}; do
              run_on "$machine" "SHUTDOWN" || true
            done
            wait 2>/dev/null || true
            trap - EXIT

            echo ""
            echo "==> Fleet test passed: ${name}"
            mkdir -p $out
            echo "PASS" > $out/result
            ${lib.concatStringsSep "\n" (builtins.map (m: ''
              cp "$FLEET_DIR/${m}-serial.log" "$out/${m}-serial.log" 2>/dev/null || true
            '') machineNames)}
          '';
        }
      ];

      requiredSystemFeatures = [ "kvm" ];
    };

in {
  inherit mkFleetTest;
}
