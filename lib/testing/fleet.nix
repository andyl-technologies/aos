# lib/testing/fleet.nix — Multi-VM test orchestrator
#
# Boots multiple VMs connected via a shared virtual network.
# Each machine has its own agent for independent command execution.
# The test script can run commands on any machine by name and assert
# on the results.
#
# Drivers:
#   - "firecracker" (default): Lightweight VMM, vsock agent communication,
#     host-side bridge + tap devices for inter-VM networking.
#   - "qemu": Full-featured VMM, virtio-serial agent communication,
#     QEMU multicast socket networking.
#
# Architecture:
#   - Each machine gets a separate VM process with its own agent channel
#   - Machines are connected via a shared L2 network segment
#   - Static IPs assigned via systemd-networkd (192.168.50.0/24 subnet)
#   - The test script uses run_on/assert_on/assert_output_on helpers
#   - Direct kernel boot for each machine
#   - All machines are shut down after the test completes
{
  pkgs,
  lib,
  testTools ? {},
}: let
  vmLib = import ./vm.nix {inherit pkgs lib testTools;};
  assertions = import ./assertions.nix;

  qemu = testTools.qemu;
  hostSocat = pkgs.socat;
  hostJq = pkgs.jq;
  firecracker = pkgs.firecracker;

  mkFleetTest = {
    name,
    machines,
    testScript,
    timeout ? 300,
    driver ? "firecracker",
  }: let
    machineNames = builtins.attrNames machines;

    # Assign sequential IPs: 192.168.50.10, .11, .12, ...
    # For Firecracker, also assign unique CIDs: 3, 4, 5, ...
    machinesWithIndex =
      lib.imap (i: mname: {
        name = mname;
        machine = machines.${mname};
        ip = "192.168.50.${builtins.toString (i + 10)}";
        mac = machines.${mname}.mac or "52:54:00:00:00:${builtins.toString (i + 1)}";
        index = i;
        cid = i + 3;
        tapName = "tap-${builtins.toString i}";
      })
      machineNames;

    # Build /etc/hosts entries for all machines
    hostsEntries = lib.concatStringsSep "\n" (builtins.map (m: "${m.ip} ${m.name}") machinesWithIndex);

    # Build network config for a specific machine
    mkNetworkConfig = m:
      lib.concatStringsSep "\n" [
        "[Match]"
        "Name=eth0"
        ""
        "[Network]"
        "Address=${m.ip}/24"
      ];

    # Build per-machine rootfs images (shared by both drivers)
    machineImages =
      builtins.map (m: {
        inherit m;
        image = vmLib.mkTestRootfs {
          system = m.machine.system;
          name = m.name;
          hostname = m.name;
          networkConfig = mkNetworkConfig m;
          hostsEntries = hostsEntries;
        };
        kernel = m.machine.system.config.system.build.kernel;
      })
      machinesWithIndex;

    # -------------------------------------------------------------------
    # Driver-specific build dependencies
    # -------------------------------------------------------------------
    driverBuildDeps =
      if driver == "firecracker"
      then [
        pkgs.coreutils
        hostSocat
        hostJq
        firecracker
        pkgs.iproute2
      ]
      else if driver == "qemu"
      then [
        pkgs.coreutils
        hostSocat
        hostJq
        qemu
      ]
      else throw "mkFleetTest '${name}': unknown driver '${driver}' (expected 'firecracker' or 'qemu')";

    # -------------------------------------------------------------------
    # Firecracker driver script
    # -------------------------------------------------------------------
    # Uses host-side bridge + tap devices for inter-VM L2 networking.
    # Uses vsock for per-machine agent communication (unique CID per VM).
    # Requires CAP_NET_ADMIN (available on the builder).
    firecrackerScript = ''
      set -euo pipefail

      FLEET_DIR="$TMPDIR/fleet"
      mkdir -p "$FLEET_DIR"

      # Clear LD_LIBRARY_PATH — AOS build libs can conflict
      unset LD_LIBRARY_PATH

      PIDS=""
      BRIDGE="aos-br-$$"

      # Cleanup handler: kill all Firecracker processes and tear down networking
      cleanup() {
        for pid in $PIDS; do
          kill "$pid" 2>/dev/null || true
        done
        wait 2>/dev/null || true
        # Tear down tap devices and bridge
        ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          ip link set ${mi.m.tapName} down 2>/dev/null || true
          ip link del ${mi.m.tapName} 2>/dev/null || true
        '')
        machineImages
      )}
        ip link set "$BRIDGE" down 2>/dev/null || true
        ip link del "$BRIDGE" 2>/dev/null || true
      }
      trap cleanup EXIT

      # ----------------------------------------------------------
      # Set up bridge and tap devices for inter-VM networking
      # ----------------------------------------------------------
      echo "Setting up network bridge: $BRIDGE"
      ip link add "$BRIDGE" type bridge
      ip link set "$BRIDGE" up

      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "Creating tap device: ${mi.m.tapName}"
          ip tuntap add ${mi.m.tapName} mode tap
          ip link set ${mi.m.tapName} up
          ip link set ${mi.m.tapName} master "$BRIDGE"
        '')
        machineImages
      )}

      # ----------------------------------------------------------
      # Launch each machine
      # ----------------------------------------------------------
      ${lib.concatStringsSep "\n" (
        builtins.map (
          mi: let
            m = mi.m;
          in ''
            echo "Starting machine: ${m.name} (role: ${m.machine.role or "worker"}, ip: ${m.ip}, cid: ${builtins.toString m.cid})"

            VSOCK_UDS_${m.name}="$FLEET_DIR/${m.name}.vsock"
            SERIAL_LOG_${m.name}="$FLEET_DIR/${m.name}-serial.log"
            FC_LOG_${m.name}="$FLEET_DIR/${m.name}-fc.log"

            # Copy rootfs to writable location
            cp "${mi.image}" "$FLEET_DIR/${m.name}-rootfs.img"
            chmod u+w "$FLEET_DIR/${m.name}-rootfs.img"

            # Find the uncompressed kernel image (Firecracker requires vmlinux, not vmlinuz)
            VMLINUX_${m.name}=$(ls ${mi.kernel}/boot/vmlinux-* | head -1)

            # Write Firecracker JSON config
            cat > "$FLEET_DIR/${m.name}-fc.json" << FCCFGEOF
            {
              "boot-source": {
                "kernel_image_path": "''${VMLINUX_${m.name}}",
                "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/sbin/init systemd.journald.forward_to_console=1 enforcing=0 net.ifnames=0"
              },
              "drives": [
                {
                  "drive_id": "rootfs",
                  "path_on_host": "$FLEET_DIR/${m.name}-rootfs.img",
                  "is_root_device": true,
                  "is_read_only": false,
                  "cache_type": "Unsafe",
                  "io_engine": "Sync"
                }
              ],
              "machine-config": {
                "vcpu_count": 2,
                "mem_size_mib": 2048,
                "smt": false,
                "track_dirty_pages": false,
                "huge_pages": "None"
              },
              "vsock": {
                "guest_cid": ${builtins.toString m.cid},
                "uds_path": "''${VSOCK_UDS_${m.name}}"
              },
              "network-interfaces": [
                {
                  "iface_id": "eth0",
                  "host_dev_name": "${m.tapName}",
                  "guest_mac": "${m.mac}"
                }
              ]
            }
            FCCFGEOF

            firecracker --no-api --config-file "$FLEET_DIR/${m.name}-fc.json" \
              > "''${SERIAL_LOG_${m.name}}" 2>"''${FC_LOG_${m.name}}" &
            PIDS="$PIDS $!"
          ''
        )
        machineImages
      )}

      sleep 1

      # Verify all Firecracker processes are still running
      for pid in $PIDS; do
        if ! kill -0 "$pid" 2>/dev/null; then
          echo "ERROR: A Firecracker process exited immediately (PID $pid)"
          ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "--- ${mi.m.name} serial log ---"
          cat "$SERIAL_LOG_${mi.m.name}" 2>/dev/null || true
          echo "--- ${mi.m.name} firecracker log ---"
          cat "$FC_LOG_${mi.m.name}" 2>/dev/null || true
        '')
        machineImages
      )}
          exit 1
        fi
      done

      # ----------------------------------------------------------
      # Wait for all agents to become ready (PING/PONG via vsock)
      # ----------------------------------------------------------
      # Helper to send a command via vsock CONNECT protocol
      vsock_cmd() {
        local uds="$1"
        local cmd="$2"
        {
          printf 'CONNECT 52\n'
          sleep 0.1
          printf '%s\n' "$cmd"
          sleep 5
        } | socat - UNIX-CONNECT:"$uds" 2>/dev/null | tail -n +2 | head -1
      }

      START_TIME=$(date +%s)
      DEADLINE=$((START_TIME + ${builtins.toString timeout}))
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "Waiting for ${mi.m.name}..."
          while [ "$(date +%s)" -lt "$DEADLINE" ]; do
            if [ -S "''${VSOCK_UDS_${mi.m.name}}" ]; then
              RESPONSE=$(vsock_cmd "''${VSOCK_UDS_${mi.m.name}}" "PING" || true)
              if echo "$RESPONSE" | grep -q '"ready"'; then
                echo "${mi.m.name} ready."
                break
              fi
            fi
            sleep 0.5
          done
        '')
        machineImages
      )}

      if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "TIMEOUT: Not all machines became ready within ${builtins.toString timeout}s"
        ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "--- ${mi.m.name} serial log ---"
          cat "$SERIAL_LOG_${mi.m.name}" 2>/dev/null || true
          echo "--- ${mi.m.name} firecracker log ---"
          cat "$FC_LOG_${mi.m.name}" 2>/dev/null || true
        '')
        machineImages
      )}
        exit 1
      fi

      # Import shared fleet test helpers (run_on, assert_on, assert_output_on)
      ${assertions.mkFleetVsockHelpers "${hostSocat}/bin/socat"}

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
        builtins.map (mi: ''
          vsock_cmd "''${VSOCK_UDS_${mi.m.name}}" "SHUTDOWN" || true
        '')
        machineImages
      )}
      sleep 2
      wait 2>/dev/null || true
      trap - EXIT

      # Tear down networking
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          ip link set ${mi.m.tapName} down 2>/dev/null || true
          ip link del ${mi.m.tapName} 2>/dev/null || true
        '')
        machineImages
      )}
      ip link set "$BRIDGE" down 2>/dev/null || true
      ip link del "$BRIDGE" 2>/dev/null || true

      echo ""
      echo "==> Fleet test passed: ${name}"
      mkdir -p $out
      echo "PASS" > $out/result
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          cp "$SERIAL_LOG_${mi.m.name}" "$out/${mi.m.name}-serial.log" 2>/dev/null || true
        '')
        machineImages
      )}
    '';

    # -------------------------------------------------------------------
    # QEMU driver script (existing implementation, preserved as-is)
    # -------------------------------------------------------------------
    qemuScript = ''
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
          mi: let
            m = mi.m;
          in ''
            echo "Starting machine: ${m.name} (role: ${m.machine.role or "worker"}, ip: ${m.ip})"

            AGENT_SOCK_${m.name}="$FLEET_DIR/${m.name}-agent.sock"
            SERIAL_LOG_${m.name}="$FLEET_DIR/${m.name}-serial.log"

            # Copy rootfs to writable location
            cp "${mi.image}" "$FLEET_DIR/${m.name}-rootfs.img"
            chmod u+w "$FLEET_DIR/${m.name}-rootfs.img"

            # Find kernel image
            VMLINUZ_${m.name}=$(ls ${mi.kernel}/boot/vmlinuz-* | head -1)

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
        )
        machineImages
      )}

      sleep 2

      # ----------------------------------------------------------
      # Wait for all agents to become ready (PING/PONG)
      # ----------------------------------------------------------
      DEADLINE=$((SECONDS + ${builtins.toString timeout}))
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "Waiting for ${mi.m.name}..."
          while [ "$SECONDS" -lt "$DEADLINE" ]; do
            if [ -S "''${AGENT_SOCK_${mi.m.name}}" ]; then
              RESPONSE=$( (printf 'PING\n'; sleep 5) | socat - UNIX-CONNECT:"''${AGENT_SOCK_${mi.m.name}}" 2>/dev/null | head -1 || true)
              if echo "$RESPONSE" | grep -q '"ready"'; then
                echo "${mi.m.name} ready."
                break
              fi
            fi
            sleep 1
          done
        '')
        machineImages
      )}

      if [ "$SECONDS" -ge "$DEADLINE" ]; then
        echo "TIMEOUT: Not all machines became ready within ${builtins.toString timeout}s"
        ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "--- ${mi.m.name} serial log ---"
          cat "$SERIAL_LOG_${mi.m.name}" 2>/dev/null || true
          echo "--- ${mi.m.name} qemu log ---"
          cat "$FLEET_DIR/${mi.m.name}-qemu.log" 2>/dev/null || true
        '')
        machineImages
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
        builtins.map (mi: ''
          (printf 'SHUTDOWN\n'; sleep 2) | socat - UNIX-CONNECT:"''${AGENT_SOCK_${mi.m.name}}" 2>/dev/null || true
        '')
        machineImages
      )}
      sleep 2
      wait 2>/dev/null || true
      trap - EXIT

      echo ""
      echo "==> Fleet test passed: ${name}"
      mkdir -p $out
      echo "PASS" > $out/result
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          cp "$SERIAL_LOG_${mi.m.name}" "$out/${mi.m.name}-serial.log" 2>/dev/null || true
        '')
        machineImages
      )}
    '';

    testPhaseScript =
      if driver == "firecracker"
      then firecrackerScript
      else qemuScript;
  in
    pkgs.mkDerivation {
      pname = "aos-fleet-test-${name}";
      version = "0";
      src = null;

      buildDeps = driverBuildDeps;

      phases = [
        {
          name = "test";
          script = testPhaseScript;
        }
      ];

      requiredSystemFeatures = ["kvm"];
    };
in {
  inherit mkFleetTest;
}
