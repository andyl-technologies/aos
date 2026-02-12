# tests/vm/lib.nix — QEMU test harness with virtio-serial guest agent
#
# Architecture:
#   1. Build a rootfs ext4 image from the system's Nix store closure
#      (uses mkfs.ext4 -d — no losetup/mount, sandbox-compatible)
#   2. Boot QEMU with direct kernel boot (-kernel flag, no bootloader)
#   3. Guest agent communicates over virtio-serial
#   4. Host sends commands, asserts on results
#
# Requirements:
#   - Kernel with built-in: VIRTIO, VIRTIO_PCI, VIRTIO_BLK, EXT4_FS,
#     VIRTIO_CONSOLE, DEVTMPFS, DEVTMPFS_MOUNT
#   - requiredSystemFeatures = [ "kvm" ] on the builder

{ pkgs, lib, testTools }:

let
  # Test infrastructure from nixpkgs — runs on the HOST, not in the AOS image.
  qemu = testTools.qemu;
  hostSocat = testTools.socat;
  hostJq = testTools.jq;

  # ---------------------------------------------------------------------------
  # Build a rootfs ext4 image for VM testing
  # ---------------------------------------------------------------------------
  # Uses exportReferencesGraph to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  mkTestRootfs = { system, name }:
    let
      toplevel = system.config.system.build.toplevel;
      systemdPkg = pkgs.systemd;
      coreutilsPkg = pkgs.coreutils;
      bashPkg = pkgs.bash;
    in
    pkgs.mkDerivation {
      pname = "vm-rootfs-${name}";
      version = "0";
      src = null;

      buildDeps = [ pkgs.e2fsprogs pkgs.coreutils ];

      # Nix writes the transitive closure graphs before running the builder
      exportReferencesGraph = [
        "closure-toplevel" toplevel
        "closure-systemd" systemdPkg
        "closure-coreutils" coreutilsPkg
        "closure-bash" bashPkg
      ];

      TOPLEVEL = builtins.toString toplevel;
      SYSTEMD = builtins.toString systemdPkg;
      COREUTILS = builtins.toString coreutilsPkg;
      BASH = builtins.toString bashPkg;

      phases = [
        {
          name = "build-rootfs";
          script = ''
            mkdir -p rootfs/nix/store
            mkdir -p rootfs/sbin rootfs/bin rootfs/etc rootfs/dev
            mkdir -p rootfs/proc rootfs/sys rootfs/tmp rootfs/run
            mkdir -p rootfs/var/log rootfs/var/lib rootfs/var/tmp
            mkdir -p rootfs/opt/aos-test/bin

            # Collect all unique store paths from the closure graphs
            cat closure-toplevel closure-systemd closure-coreutils closure-bash \
              | grep '^/nix/store/' | sort -u > all-paths

            echo "==> Copying $(wc -l < all-paths) store paths to rootfs"

            count=0
            total=$(wc -l < all-paths)
            while IFS= read -r p; do
              count=$((count + 1))
              if [ -e "$p" ]; then
                cp -a "$p" rootfs/nix/store/
              fi
              if [ $((count % 10)) -eq 0 ]; then
                printf '\r    [%d/%d]' "$count" "$total"
              fi
            done < all-paths
            echo ""

            # /sbin/init -> systemd
            ln -sfn $SYSTEMD/lib/systemd/systemd rootfs/sbin/init

            # systemd was built with --prefix=/ so it looks for helpers,
            # unit files, and udev rules at /lib/systemd/, /lib/udev/, etc.
            # Symlink all of systemd's lib subdirectories to /lib/
            mkdir -p rootfs/lib
            for d in $SYSTEMD/lib/*; do
              ln -sfn "$d" "rootfs/lib/$(basename $d)"
            done

            # Populate /usr/bin, /usr/sbin, /bin, /sbin with essential binaries
            # systemd's default PATH for services is /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
            mkdir -p rootfs/usr/bin rootfs/usr/sbin
            # /bin/sh -> bash
            ln -sfn $BASH/bin/bash rootfs/bin/sh
            # coreutils (sleep, cat, echo, tr, sed, etc.)
            for bin in $COREUTILS/bin/*; do
              name=$(basename "$bin")
              ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
            done
            # systemd binaries (systemctl, journalctl, loginctl, etc.)
            for bin in $SYSTEMD/bin/*; do
              name=$(basename "$bin")
              ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
            done
            for bin in $SYSTEMD/sbin/*; do
              name=$(basename "$bin")
              ln -sfn "$bin" "rootfs/usr/sbin/$name" 2>/dev/null || true
            done
            # Also populate /bin and /sbin for convenience
            for bin in $COREUTILS/bin/*; do
              name=$(basename "$bin")
              if [ ! -e "rootfs/bin/$name" ]; then
                ln -sfn "$bin" "rootfs/bin/$name" 2>/dev/null || true
              fi
            done

            # /run/current-system -> toplevel
            ln -sfn $TOPLEVEL rootfs/run/current-system

            # Basic /etc for systemd
            echo "aos-test" > rootfs/etc/hostname
            touch rootfs/etc/machine-id

            cat > rootfs/etc/os-release << 'OSREL'
ID=aos
NAME="ANDYL OS"
PRETTY_NAME="ANDYL OS (test)"
VERSION_ID=0.1
OSREL

            cat > rootfs/etc/passwd << 'PASSWD'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:Nobody:/:/sbin/nologin
systemd-journal:x:101:101:systemd Journal:/:/sbin/nologin
systemd-network:x:102:102:systemd Network:/:/sbin/nologin
PASSWD

            cat > rootfs/etc/group << 'GROUP'
root:x:0:
nobody:x:65534:
utmp:x:22:
systemd-journal:x:101:
systemd-network:x:102:
GROUP

            cat > rootfs/etc/shadow << 'SHADOW'
root:!:1::::::
nobody:!:1::::::
SHADOW
            chmod 640 rootfs/etc/shadow

            # Minimal nsswitch.conf for systemd
            cat > rootfs/etc/nsswitch.conf << 'NSS'
passwd: files
group:  files
shadow: files
hosts:  files dns
NSS

            # Guest agent script
            cat > rootfs/opt/aos-test/bin/aos-test-agent << 'AGENT'
#!/bin/sh
set -u
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Try udev symlink first, fall back to raw virtio device
AGENT_PORT=""
echo "aos-test-agent: waiting for virtio port..." >&2
TRIES=0
while [ -z "$AGENT_PORT" ]; do
  if [ -e "/dev/virtio-ports/aos.test.agent" ]; then
    AGENT_PORT="/dev/virtio-ports/aos.test.agent"
  elif [ -e "/dev/vport0p1" ]; then
    AGENT_PORT="/dev/vport0p1"
  else
    TRIES=$((TRIES + 1))
    if [ $((TRIES % 50)) -eq 0 ]; then
      echo "aos-test-agent: still waiting ($TRIES attempts)..." >&2
      ls /dev/vport* 2>&1 >&2 || true
      ls /dev/virtio-ports/ 2>&1 >&2 || true
    fi
    sleep 0.1
  fi
done
echo "aos-test-agent: using port $AGENT_PORT" >&2

# Process commands — each command is a fresh open/close of the port.
# The host sends a command, agent reads it, processes it, writes response.
while true; do
  # Read one command (opens port, reads one line, closes)
  cmd=$(head -1 "$AGENT_PORT" 2>/dev/null) || true
  if [ -z "$cmd" ]; then
    sleep 0.1
    continue
  fi
  echo "aos-test-agent: received: $cmd" >&2
  if [ "$cmd" = "PING" ]; then
    printf '{"status":"ready"}\n' > "$AGENT_PORT"
    continue
  fi
  if [ "$cmd" = "SHUTDOWN" ]; then
    printf '{"status":"shutdown"}\n' > "$AGENT_PORT"
    poweroff -f
    exit 0
  fi
  eval "$cmd" > /tmp/agent-stdout 2>/tmp/agent-stderr
  exit_code=$?
  stdout=$(cat /tmp/agent-stdout 2>/dev/null || true)
  stderr=$(cat /tmp/agent-stderr 2>/dev/null || true)
  # JSON-escape using bash builtins only (sed is not in the guest)
  NL='
'
  escape_json() {
    local s="$1"
    s="''${s//\\/\\\\}"
    s="''${s//\"/\\\"}"
    s="''${s//$NL/\\n}"
    printf '%s' "$s"
  }
  stdout_escaped=$(escape_json "$stdout")
  stderr_escaped=$(escape_json "$stderr")
  printf '{"exit_code":%d,"stdout":"%s","stderr":"%s"}\n' \
    "$exit_code" "$stdout_escaped" "$stderr_escaped" > "$AGENT_PORT"
done
AGENT
            chmod +x rootfs/opt/aos-test/bin/aos-test-agent

            # Mask serial-getty@ttyS0 — we use -serial file: in QEMU so there's
            # no real tty, and waiting for the device wastes 90 seconds.
            mkdir -p rootfs/etc/systemd/system/multi-user.target.wants
            ln -sfn /dev/null rootfs/etc/systemd/system/serial-getty@ttyS0.service

            # Guest agent systemd service
            cat > rootfs/etc/systemd/system/aos-test-agent.service << 'UNIT'
[Unit]
Description=AOS VM Test Guest Agent
After=systemd-udevd.service
Wants=systemd-udevd.service

[Service]
Type=simple
ExecStart=/opt/aos-test/bin/aos-test-agent
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT
            ln -sfn ../aos-test-agent.service \
              rootfs/etc/systemd/system/multi-user.target.wants/aos-test-agent.service

            # Calculate image size with overhead
            # Use du -sk (kilobytes) for portability, then convert to MB
            SIZE_KB=$(du -sk rootfs | cut -f1)
            SIZE_MB=$(( SIZE_KB / 1024 ))
            # Triple the size for ext4 metadata, journal, inode tables
            IMAGE_MB=$(( SIZE_MB * 3 + 512 ))

            echo "==> Rootfs data: ''${SIZE_MB}MB, image: ''${IMAGE_MB}MB"
            mkfs.ext4 -d rootfs -L rootfs -m 1 -q $out ''${IMAGE_MB}M
          '';
        }
      ];
    };

  # ---------------------------------------------------------------------------
  # Create a VM test derivation
  # ---------------------------------------------------------------------------
  mkVMTest = { name, system, testScript, timeout ? 120 }:
    let
      rootfs = mkTestRootfs { inherit system name; };
      kernel = system.config.system.build.kernel;
    in
    pkgs.mkDerivation {
      pname = "aos-vm-test-${name}";
      version = "0";
      src = null;

      buildDeps = [ pkgs.coreutils hostSocat hostJq qemu ];

      ROOTFS = builtins.toString rootfs;
      KERNEL = builtins.toString kernel;

      phases = [
        {
          name = "test";
          script = ''
            set -eu

            AGENT_SOCK="$TMPDIR/agent.sock"
            SERIAL_LOG="$TMPDIR/serial.log"

            # Copy rootfs image to writable location
            cp $ROOTFS rootfs.img
            chmod u+w rootfs.img

            # Find the kernel image
            VMLINUZ=$(ls $KERNEL/boot/vmlinuz-* | head -1)

            # Pre-flight checks
            QEMU_LOG="$TMPDIR/qemu.log"
            echo "Kernel: $VMLINUZ"
            echo "Rootfs: rootfs.img ($(ls -lh rootfs.img | awk '{print $5}'))"
            ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

            # Clear LD_LIBRARY_PATH — AOS build libs can conflict with nixpkgs binaries
            # (QEMU, socat, jq are from nixpkgs and have their own RPATH)
            unset LD_LIBRARY_PATH

            qemu-system-x86_64 --version || echo "QEMU version check failed"

            # Launch QEMU with direct kernel boot
            qemu-system-x86_64 \
              -machine q35,accel=kvm \
              -cpu host \
              -m 2048 \
              -smp 2 \
              -nographic \
              -kernel "$VMLINUZ" \
              -append "root=/dev/vda rw console=ttyS0 init=/sbin/init panic=1 systemd.journald.forward_to_console=1" \
              -drive file=rootfs.img,format=raw,if=virtio \
              -device virtio-serial \
              -device virtserialport,chardev=agent,name=aos.test.agent \
              -chardev socket,id=agent,path="$AGENT_SOCK",server=on,wait=off \
              -serial file:"$SERIAL_LOG" \
              -no-reboot > "$QEMU_LOG" 2>&1 &
            QEMU_PID=$!
            echo "QEMU PID: $QEMU_PID"
            sleep 2
            if ! kill -0 "$QEMU_PID" 2>/dev/null; then
              echo "ERROR: QEMU exited immediately!"
              echo "--- QEMU log ---"
              cat "$QEMU_LOG" 2>/dev/null || true
              exit 1
            fi

            cleanup() {
              kill "$QEMU_PID" 2>/dev/null || true
              wait "$QEMU_PID" 2>/dev/null || true
            }
            trap cleanup EXIT

            # Test helper: send command to guest, read one response line.
            # Keep stdin open with sleep so socat doesn't close the connection
            # before the agent responds. head -1 reads exactly one response line,
            # then exits, triggering SIGPIPE cascade that kills sleep+socat.
            run_in_guest() {
              local cmd="$1"
              (printf '%s\n' "$cmd"; sleep 300) | socat - UNIX-CONNECT:"$AGENT_SOCK" 2>/dev/null | head -1
            }

            # Wait for guest agent using PING/PONG
            echo "Waiting for guest agent..."
            START_TIME=$(date +%s)
            DEADLINE=$((START_TIME + ${builtins.toString timeout}))
            AGENT_READY=0
            while [ "$(date +%s)" -lt "$DEADLINE" ]; do
              if [ -S "$AGENT_SOCK" ]; then
                RESPONSE=$(run_in_guest "PING" 2>/dev/null || true)
                if echo "$RESPONSE" | grep -q '"ready"'; then
                  echo "Guest agent ready."
                  AGENT_READY=1
                  break
                fi
              fi
              sleep 2
            done

            if [ "$AGENT_READY" -ne 1 ]; then
              echo "TIMEOUT: Guest agent did not become ready within ${builtins.toString timeout}s"
              echo "--- QEMU log ---"
              cat "$QEMU_LOG" 2>/dev/null || true
              echo "--- Serial log ---"
              cat "$SERIAL_LOG" 2>/dev/null || true
              exit 1
            fi

            assert_success() {
              local cmd="$1"
              local desc="''${2:-$cmd}"
              RESULT=$(run_in_guest "$cmd")
              EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
              if [ "$EXIT_CODE" != "0" ]; then
                echo "FAIL: $desc"
                echo "  command: $cmd"
                echo "  exit_code: $EXIT_CODE"
                echo "  stdout: $(echo "$RESULT" | jq -r '.stdout')"
                echo "  stderr: $(echo "$RESULT" | jq -r '.stderr')"
                return 1
              fi
              echo "PASS: $desc"
            }

            assert_output_contains() {
              local cmd="$1"
              local expected="$2"
              local desc="''${3:-$cmd contains $expected}"
              RESULT=$(run_in_guest "$cmd")
              STDOUT=$(echo "$RESULT" | jq -r '.stdout')
              if ! echo "$STDOUT" | grep -q "$expected"; then
                echo "FAIL: $desc"
                echo "  expected to contain: $expected"
                echo "  actual output: $STDOUT"
                return 1
              fi
              echo "PASS: $desc"
            }

            echo ""
            echo "==> Running test: ${name}"
            echo ""

            ${testScript}

            echo ""
            echo "Shutting down guest..."
            run_in_guest "SHUTDOWN" || true
            sleep 2
            wait "$QEMU_PID" 2>/dev/null || true
            trap - EXIT

            echo ""
            echo "==> All tests passed for: ${name}"
            mkdir -p $out
            cp "$SERIAL_LOG" $out/serial.log 2>/dev/null || true
            echo "PASS" > $out/result
          '';
        }
      ];

      requiredSystemFeatures = [ "kvm" ];
    };

in {
  inherit mkVMTest mkTestRootfs;
}
