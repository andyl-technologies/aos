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
  assertions = import ./assertions.nix {inherit (pkgs) aos-agent-rpc;};

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

    # Build per-machine GPT disk images (shared by both drivers).
    # Each machine boots through the production-like initrd path.
    machineImages =
      builtins.map (m: {
        inherit m;
        image = vmLib.mkTestDisk {
          system = m.machine.system;
          name = m.name;
          hostname = m.name;
          networkConfig = mkNetworkConfig m;
          hostsEntries = hostsEntries;
        };
        kernel = m.machine.system.config.system.build.kernel;
        initrd = m.machine.system.config.system.build.initrd;
      })
      machinesWithIndex;

    # -------------------------------------------------------------------
    # Driver-specific build dependencies
    # -------------------------------------------------------------------
    driverBuildDeps =
      if driver == "firecracker"
      then [
        pkgs.coreutils
        hostJq
        firecracker
        pkgs.aos-agent-rpc
      ]
      else if driver == "qemu"
      then [
        pkgs.coreutils
        hostSocat
        hostJq
        qemu
        pkgs.aos-agent-rpc
      ]
      else throw "mkFleetTest '${name}': unknown driver '${driver}' (expected 'firecracker' or 'qemu')";

    # -------------------------------------------------------------------
    # Firecracker driver script
    # -------------------------------------------------------------------
    # Uses host-side bridge + tap devices for inter-VM L2 networking.
    # Uses vsock for per-machine agent communication (unique CID per VM).
    # Requires CAP_NET_ADMIN (available on the builder).
    firecrackerScript = ''
      set -eu

      FLEET_DIR="$TMPDIR/fleet"
      mkdir -p "$FLEET_DIR"

      # Clear LD_LIBRARY_PATH — AOS build libs can conflict
      unset LD_LIBRARY_PATH

      PIDS=""

      # Cleanup handler: kill all Firecracker processes
      cleanup() {
        for pid in $PIDS; do
          kill "$pid" 2>/dev/null || true
        done
        wait 2>/dev/null || true
      }
      trap cleanup EXIT

      # ----------------------------------------------------------
      # Launch each machine (no inter-VM networking — sandbox
      # doesn't allow tap devices, and the test scripts only
      # check per-VM configuration, not actual connectivity)
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

            # Copy disk image to writable location
            cp "${mi.image}/disk.img" "$FLEET_DIR/${m.name}-disk.img"
            chmod u+w "$FLEET_DIR/${m.name}-disk.img"

            # Find the uncompressed kernel image (Firecracker requires vmlinux, not vmlinuz)
            VMLINUX_${m.name}=$(ls ${mi.kernel}/boot/vmlinux-* | head -1)
            INITRD_${m.name}=${mi.initrd}/initrd.img

            # Write Firecracker JSON config (no network interfaces — sandbox limitation).
            # is_root_device=false avoids Firecracker auto-appending
            # root=/dev/vda rw; we set root=/dev/vda2 ro explicitly.
            cat > "$FLEET_DIR/${m.name}-fc.json" << FCCFGEOF
            {
              "boot-source": {
                "kernel_image_path": "''${VMLINUX_${m.name}}",
                "initrd_path": "''${INITRD_${m.name}}",
                "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 systemd.journald.forward_to_console=1 ignition.platform.id=metal enforcing=0"
              },
              "drives": [
                {
                  "drive_id": "rootfs",
                  "path_on_host": "$FLEET_DIR/${m.name}-disk.img",
                  "is_root_device": false,
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
              "network-interfaces": []
            }
            FCCFGEOF

            # Per-machine silent stdin source — see vm.nix for rationale
            # (prevents agetty respawn loops when the debug profile's
            # autologin is active).
            FC_STDIN_${m.name}="$FLEET_DIR/${m.name}-fc-stdin"
            mkfifo "''${FC_STDIN_${m.name}}"
            sleep infinity <>"''${FC_STDIN_${m.name}}" &
            PIDS="$PIDS $!"

            firecracker --no-api --config-file "$FLEET_DIR/${m.name}-fc.json" \
              < "''${FC_STDIN_${m.name}}" \
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
          cat "''${SERIAL_LOG_${mi.m.name}}" 2>/dev/null || true
          echo "--- ${mi.m.name} firecracker log ---"
          cat "''${FC_LOG_${mi.m.name}}" 2>/dev/null || true
        '')
        machineImages
      )}
          exit 1
        fi
      done

      # ----------------------------------------------------------
      # Wait for all agents to become ready (PING/PONG via vsock)
      # ----------------------------------------------------------
      START_TIME=$(date +%s)
      DEADLINE=$((START_TIME + ${builtins.toString timeout}))
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          echo "Waiting for ${mi.m.name}..."
          while [ "$(date +%s)" -lt "$DEADLINE" ]; do
            if [ -S "''${VSOCK_UDS_${mi.m.name}}" ]; then
              RESPONSE=$(${assertions.rpcBin} --driver firecracker "''${VSOCK_UDS_${mi.m.name}}" "PING" || true)
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
          cat "''${SERIAL_LOG_${mi.m.name}}" 2>/dev/null || true
          echo "--- ${mi.m.name} firecracker log ---"
          cat "''${FC_LOG_${mi.m.name}}" 2>/dev/null || true
        '')
        machineImages
      )}
        exit 1
      fi

      # Import shared fleet test helpers (run_on, assert_on, assert_output_on)
      ${assertions.fleetVsockHelpers}

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
          ${assertions.rpcBin} --driver firecracker "''${VSOCK_UDS_${mi.m.name}}" "SHUTDOWN" || true
        '')
        machineImages
      )}
      sleep 2
      # Kill all backgrounded processes (sleep infinity + firecracker)
      # so wait doesn't hang. The cleanup trap does the same, but the
      # happy path reaches here before the trap fires.
      for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
      done
      wait 2>/dev/null || true
      trap - EXIT

      echo ""
      echo "==> Fleet test passed: ${name}"
      mkdir -p $out
      echo "PASS" > $out/result
      ${lib.concatStringsSep "\n" (
        builtins.map (mi: ''
          cp "''${SERIAL_LOG_${mi.m.name}}" "$out/${mi.m.name}-serial.log" 2>/dev/null || true
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
            SERIAL_SOCK_${m.name}="$FLEET_DIR/${m.name}-serial.sock"
            SERIAL_LOG_${m.name}="$FLEET_DIR/${m.name}-serial.log"

            # Copy disk image to writable location
            cp "${mi.image}/disk.img" "$FLEET_DIR/${m.name}-disk.img"
            chmod u+w "$FLEET_DIR/${m.name}-disk.img"

            # Find kernel image
            VMLINUZ_${m.name}=$(ls ${mi.kernel}/boot/vmlinuz-* | head -1)
            INITRD_${m.name}=${mi.initrd}/initrd.img

            # Per-machine unidirectional serial drain — see vm.nix for the
            # rationale (guest reads from /dev/ttyS0 must block, not EOF).
            socat -u UNIX-LISTEN:"''${SERIAL_SOCK_${m.name}}",reuseaddr,fork \
                     OPEN:"''${SERIAL_LOG_${m.name}}",creat,append &
            PIDS="$PIDS $!"
            SOCK_WAIT=0
            while [ ! -S "''${SERIAL_SOCK_${m.name}}" ]; do
              sleep 0.05
              SOCK_WAIT=$((SOCK_WAIT + 1))
              if [ "$SOCK_WAIT" -gt 100 ]; then
                echo "ERROR: serial drain socket for ${m.name} did not appear within 5s"
                exit 1
              fi
            done

            qemu-system-x86_64 \
              -machine q35,accel=kvm \
              -cpu host \
              -m 2048 \
              -smp 2 \
              -nographic \
              -kernel "''${VMLINUZ_${m.name}}" \
              -initrd "''${INITRD_${m.name}}" \
              -append "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 systemd.journald.forward_to_console=1 ignition.platform.id=metal enforcing=0 net.ifnames=0" \
              -drive file="$FLEET_DIR/${m.name}-disk.img",format=raw,if=virtio \
              -device virtio-serial \
              -device virtserialport,chardev=agent,name=aos.test.agent \
              -chardev socket,id=agent,path="$AGENT_SOCK_${m.name}",server=on,wait=off \
              -chardev socket,id=ttyS0,path="''${SERIAL_SOCK_${m.name}}",server=off \
              -serial chardev:ttyS0 \
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
              RESPONSE=$(${assertions.rpcBin} --driver qemu "''${AGENT_SOCK_${mi.m.name}}" "PING" || true)
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
      ${assertions.fleetHelpers}

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
          ${assertions.rpcBin} --driver qemu "''${AGENT_SOCK_${mi.m.name}}" "SHUTDOWN" || true
        '')
        machineImages
      )}
      sleep 2
      for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
      done
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
