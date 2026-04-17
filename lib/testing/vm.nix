# lib/testing/vm.nix — Multi-driver VM test harness (Firecracker + QEMU)
#
# Architecture:
#   1. Build a rootfs ext4 image from the system's Nix store closure
#      (uses mkfs.ext4 -d — no losetup/mount, sandbox-compatible)
#   2. Boot a VM using either Firecracker (default) or QEMU
#   3. Guest agent communicates over vsock (Firecracker) or virtio-serial (QEMU)
#   4. Host sends commands, asserts on results
#
# Drivers:
#   - "firecracker": Lightweight VMM, vsock communication, vmlinux kernel,
#     JSON config file, ~125ms boot. Guest agent uses socat VSOCK-LISTEN.
#   - "qemu": Full-featured VMM, virtio-serial communication, vmlinuz kernel,
#     CLI flags. Guest agent reads /dev/virtio-ports/*.
#
# Requirements:
#   - Kernel with built-in: VIRTIO, VIRTIO_PCI, VIRTIO_BLK, EXT4_FS,
#     VIRTIO_CONSOLE, DEVTMPFS, DEVTMPFS_MOUNT, VIRTIO_VSOCKETS (Firecracker),
#     VIRTIO_MMIO (Firecracker)
#   - requiredSystemFeatures = [ "kvm" ] on the builder
{
  pkgs,
  lib,
  testTools ? { },
}:
let
  # QEMU is the sole host-tool exception (CLAUDE.md) — too complex to bootstrap.
  # socat, jq, and firecracker are AOS packages built from source.
  qemu = testTools.qemu;
  hostSocat = pkgs.socat;
  hostJq = pkgs.jq;
  firecracker = pkgs.firecracker;

  # Headless rootfs builder (for integration tests without systemd/agent)
  fcLib = import ./firecracker.nix { inherit pkgs lib; };
  kernel = pkgs.linux;

  # Shared shell assertion helpers
  assertions = import ./assertions.nix;

  # ---------------------------------------------------------------------------
  # Build a rootfs ext4 image for VM testing
  # ---------------------------------------------------------------------------
  # Uses exportReferencesGraph to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  mkTestRootfs =
    {
      system,
      name ? "aos-test",
      hostname ? "aos-test",
      networkConfig ? null,
      hostsEntries ? null,
      userdata ? null,
    }:
    let
      toplevel = system.config.system.build.toplevel;
      systemdPkg = pkgs.systemd;
      coreutilsPkg = pkgs.coreutils;
      bashPkg = pkgs.bash;
      socatPkg = pkgs.socat;
      systemPackages = system.config.environment.systemPackages;
    in
    pkgs.mkDerivation {
      pname = "vm-rootfs-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.e2fsprogs
        pkgs.coreutils
      ];

      # Nix writes the transitive closure graphs before running the builder
      exportReferencesGraph = [
        "closure-toplevel"
        toplevel
        "closure-systemd"
        systemdPkg
        "closure-coreutils"
        coreutilsPkg
        "closure-bash"
        bashPkg
        "closure-socat"
        socatPkg
      ];

      TOPLEVEL = builtins.toString toplevel;
      SYSTEMD = builtins.toString systemdPkg;
      COREUTILS = builtins.toString coreutilsPkg;
      AOS_BASH = builtins.toString bashPkg;
      SOCAT = builtins.toString socatPkg;
      SYSTEM_PACKAGES = builtins.concatStringsSep " " (builtins.map builtins.toString systemPackages);

      phases = [
        {
          name = "build-rootfs";
          script = ''
                        mkdir -p rootfs/nix/store
                        mkdir -p rootfs/sbin rootfs/bin rootfs/etc rootfs/dev
                        mkdir -p rootfs/proc rootfs/sys rootfs/tmp rootfs/run
                        mkdir -p rootfs/var/log rootfs/var/lib rootfs/var/tmp
                        mkdir -p rootfs/opt/aos-test/bin
                        mkdir -p rootfs/lib64

                        # Collect all unique store paths from the closure graphs
                        cat closure-toplevel closure-systemd closure-coreutils closure-bash closure-socat \
                          | grep '^/nix/store/' | sort -u > all-paths

                        echo "==> Copying $(wc -l < all-paths) store paths to rootfs"

                        count=0
                        failed=0
                        total=$(wc -l < all-paths)
                        while IFS= read -r p; do
                          count=$((count + 1))
                          if [ -e "$p" ]; then
                            if ! cp -a "$p" rootfs/nix/store/ 2>/tmp/cp-err; then
                              echo "    WARN: failed to copy $p: $(cat /tmp/cp-err)"
                              failed=$((failed + 1))
                            fi
                          else
                            echo "    WARN: path does not exist: $p"
                            failed=$((failed + 1))
                          fi
                          if [ $((count % 10)) -eq 0 ]; then
                            printf '\r    [%d/%d]' "$count" "$total"
                          fi
                        done < all-paths
                        echo ""
                        if [ "$failed" -gt 0 ]; then
                          echo "    WARNING: $failed paths failed to copy"
                        fi

                        # /lib64/ld-linux-x86-64.so.2 — needed for PIE binaries
                        # (e.g. containerd built with CGO) that reference the
                        # system dynamic linker. Find the glibc ld-linux from
                        # the copied store paths.
                        LD_LINUX=$(find rootfs/nix/store -name 'ld-linux-x86-64.so.2' -path '*glibc-*/lib/*' 2>/dev/null | sort -V | tail -1)
                        if [ -n "$LD_LINUX" ]; then
                          # Convert rootfs-relative path to absolute guest path
                          GUEST_LD="''${LD_LINUX#rootfs}"
                          ln -sfn "$GUEST_LD" rootfs/lib64/ld-linux-x86-64.so.2
                          echo "    /lib64/ld-linux-x86-64.so.2 -> $GUEST_LD"
                        else
                          echo "    WARNING: ld-linux-x86-64.so.2 not found in rootfs glibc"
                        fi

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
                        ln -sfn $AOS_BASH/bin/bash rootfs/bin/sh
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

                        # socat — needed by the guest agent for vsock communication
                        # (Firecracker driver). Always included so rootfs works with both drivers.
                        if [ -d "$SOCAT/bin" ]; then
                          for bin in "$SOCAT/bin/"*; do
                            name=$(basename "$bin")
                            ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
                          done
                        fi

                        # Symlink binaries from all environment.systemPackages
                        # so services can find them at /usr/bin and /usr/sbin
                        for pkg in $SYSTEM_PACKAGES; do
                          if [ -d "$pkg/bin" ]; then
                            for bin in "$pkg/bin/"*; do
                              name=$(basename "$bin")
                              if [ ! -e "rootfs/usr/bin/$name" ]; then
                                ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
                              fi
                            done
                          fi
                          if [ -d "$pkg/sbin" ]; then
                            for bin in "$pkg/sbin/"*; do
                              name=$(basename "$bin")
                              if [ ! -e "rootfs/usr/sbin/$name" ]; then
                                ln -sfn "$bin" "rootfs/usr/sbin/$name" 2>/dev/null || true
                              fi
                            done
                          fi
                          if [ -d "$pkg/libexec" ]; then
                            mkdir -p rootfs/usr/libexec
                            for bin in "$pkg/libexec/"*; do
                              name=$(basename "$bin")
                              if [ ! -e "rootfs/usr/libexec/$name" ]; then
                                ln -sfn "$bin" "rootfs/usr/libexec/$name" 2>/dev/null || true
                              fi
                            done
                          fi
                        done

                        # /run/current-system -> toplevel
                        ln -sfn $TOPLEVEL rootfs/run/current-system

                        # Merge toplevel's /etc into rootfs (service units, configs, etc.)
                        # This copies unit files, .wants symlinks, and module-generated configs.
                        # Files created below (hostname, passwd, etc.) will overwrite as needed.
                        if [ -d "$TOPLEVEL/etc" ]; then
                          echo "==> Merging toplevel /etc into rootfs"
                          # Use tar pipe to copy without preserving store permissions.
                          # tar extract applies umask, making files writable.
                          (cd "$TOPLEVEL/etc" && tar cf - .) | (cd rootfs/etc && tar xf -)
                          # Make real dirs writable so the symlink-resolution pass
                          # below can rm/replace entries inside them.
                          chmod -R u+w rootfs/etc
                          # Toplevel /etc can contain symlinks pointing into the read-only
                          # /nix/store (e.g. /etc/systemd/system → a system-units derivation).
                          # tar preserves those as symlinks, so subsequent writes underneath
                          # would hit the store and fail with EACCES. Replace each such link
                          # with a copy of its target — cp -a keeps internal relative symlinks
                          # (.wants/*.service) intact, so systemd semantics are preserved.
                          find rootfs/etc -type l | while IFS= read -r link; do
                            target=$(readlink "$link")
                            case "$target" in
                              /nix/store/*)
                                rm "$link"
                                cp -a "$target" "$link"
                                ;;
                            esac
                          done
                          # Newly-copied trees may carry store read-only perms; re-apply.
                          chmod -R u+w rootfs/etc
                          echo "    toplevel /etc merged"
                          # Override SELinux to permissive for VM testing — the rootfs
                          # has no policy files, and enforcing mode causes systemd to
                          # freeze when it can't load the policy.
                          echo "    checking selinux config..."
                          if [ -f rootfs/etc/selinux/config ]; then
                            echo "    overriding selinux to permissive"
                            cat > rootfs/etc/selinux/config << 'SELINUXCFG'
            SELINUX=disabled
            SELINUXTYPE=targeted
            SELINUXCFG
                            echo "    selinux override done"
                          fi
                        fi

                        echo "==> Writing basic /etc files"
                        # Basic /etc for systemd
                        echo "${hostname}" > rootfs/etc/hostname
                        touch rootfs/etc/machine-id
                        # fstab so systemd-remount-fs mounts root read-write
                        printf '/dev/vda / ext4 defaults 0 1\n' > rootfs/etc/fstab
                        ${
                          if hostsEntries != null then
                            ''
                              cat > rootfs/etc/hosts << 'HOSTS'
                              127.0.0.1 localhost
                              ${hostsEntries}
                              HOSTS
                            ''
                          else
                            ""
                        }
                        ${
                          if networkConfig != null then
                            ''
                              mkdir -p rootfs/etc/systemd/network
                              cat > rootfs/etc/systemd/network/10-eth0.network << 'NETCFG'
                              ${networkConfig}
                              NETCFG
                            ''
                          else
                            ""
                        }

                        ${
                          if userdata != null then
                            ''
                              # Inject cloud-init userdata (NoCloud seed)
                              mkdir -p rootfs/var/lib/cloud/seed/nocloud
                              mkdir -p rootfs/var/lib/cloud/state
                              cat > rootfs/var/lib/cloud/seed/nocloud/user-data << 'USERDATAEOF'
                              ${userdata}
                              USERDATAEOF
                              cat > rootfs/var/lib/cloud/seed/nocloud/meta-data << 'METADATAEOF'
                              {"instance-id":"test-vm","local-hostname":"aos-test"}
                              METADATAEOF
                            ''
                          else
                            ""
                        }

                        cat > rootfs/etc/os-release << 'OSREL'
            ID=aos
            NAME="ANDYL OS"
            PRETTY_NAME="ANDYL OS (test)"
            VERSION_ID=0.1
            OSREL

                        # Only write fallback passwd/group/shadow if the toplevel
                        # etc merge didn't already provide them (the users module
                        # generates these with all module-defined users like chrony, sshd).
                        if [ ! -s rootfs/etc/passwd ]; then
                          cat > rootfs/etc/passwd << 'PASSWD'
            root:x:0:0:root:/root:/bin/sh
            nobody:x:65534:65534:Nobody:/:/sbin/nologin
            systemd-journal:x:101:101:systemd Journal:/:/sbin/nologin
            systemd-network:x:102:102:systemd Network:/:/sbin/nologin
            PASSWD
                        fi
                        if [ ! -s rootfs/etc/group ]; then
                          cat > rootfs/etc/group << 'GROUP'
            root:x:0:
            nobody:x:65534:
            utmp:x:22:
            systemd-journal:x:101:
            systemd-network:x:102:
            GROUP
                        fi
                        if [ ! -s rootfs/etc/shadow ]; then
                          cat > rootfs/etc/shadow << 'SHADOW'
            root:!:1::::::
            nobody:!:1::::::
            SHADOW
                        fi
                        chmod 640 rootfs/etc/shadow

                        # Minimal nsswitch.conf for systemd
                        cat > rootfs/etc/nsswitch.conf << 'NSS'
            passwd: files
            group:  files
            shadow: files
            hosts:  files dns
            NSS

                        # Guest agent handler — processes a single command from stdin,
                        # writes JSON response to stdout. Used by both vsock and virtio-serial modes.
                        cat > rootfs/opt/aos-test/bin/agent-handler << 'HANDLER'
            #!/bin/sh
            set -u
            export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            # Read one command from stdin
            read -r cmd
            if [ -z "$cmd" ]; then
              exit 0
            fi
            echo "aos-test-agent: received: $cmd" >&2
            if [ "$cmd" = "PING" ]; then
              printf '{"status":"ready"}\n'
              exit 0
            fi
            if [ "$cmd" = "SHUTDOWN" ]; then
              printf '{"status":"shutdown"}\n'
              # Detect driver: Firecracker needs reboot -f (poweroff hangs),
              # QEMU uses poweroff -f
              if [ -e /dev/vsock ]; then
                reboot -f
              else
                poweroff -f
              fi
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
              "$exit_code" "$stdout_escaped" "$stderr_escaped"
            HANDLER
                        chmod +x rootfs/opt/aos-test/bin/agent-handler

                        # Guest agent script — auto-detects vsock (Firecracker) vs
                        # virtio-serial (QEMU) and listens on the appropriate transport.
                        cat > rootfs/opt/aos-test/bin/aos-test-agent << 'AGENT'
            #!/bin/sh
            set -u
            export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

            # Detect transport: vsock (Firecracker) or virtio-serial (QEMU)
            if [ -e /dev/vsock ]; then
              # ---------------------------------------------------------------
              # vsock mode (Firecracker)
              # ---------------------------------------------------------------
              # Listen on vsock port 52. Each host CONNECT creates a new
              # connection handled by agent-handler via socat EXEC.
              echo "aos-test-agent: vsock mode, listening on port 52" >&2

              # Wait briefly for /dev/vsock to be fully ready
              sleep 0.5

              # socat accepts connections and forks agent-handler for each one.
              # reuseaddr allows rapid reconnect from the host side.
              exec socat VSOCK-LISTEN:52,reuseaddr,fork EXEC:/opt/aos-test/bin/agent-handler
            fi

            # ---------------------------------------------------------------
            # virtio-serial mode (QEMU)
            # ---------------------------------------------------------------
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

                        # Ensure the install dir exists for the agent symlink below.
                        # We do NOT mask serial-getty@ttyS0 anymore — the drivers now
                        # present a properly blocking serial backend, so a live getty
                        # (e.g. the debug profile's autologin) can coexist with the
                        # harness without respawn loops.
                        mkdir -p rootfs/etc/systemd/system/multi-user.target.wants

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

                        # Calculate image size: use --apparent-size because mkfs.ext4 -d
                        # does NOT preserve hardlinks — each hardlinked file becomes a
                        # separate copy, so apparent size is what matters.
                        APPARENT_KB=$(du -sk --apparent-size rootfs | cut -f1)
                        SIZE_MB=$(( APPARENT_KB / 1024 ))
                        # 50% overhead for ext4 metadata/journal + 256MB headroom
                        IMAGE_MB=$(( SIZE_MB * 3 / 2 + 256 ))
                        if [ "$IMAGE_MB" -lt 2048 ]; then
                          IMAGE_MB=2048
                        fi

                        echo "==> Rootfs data: ''${SIZE_MB}MB, image: ''${IMAGE_MB}MB"
                        # stdenv setup.sh creates $out as a directory; mkfs.ext4
                        # needs a file. Write to temp file, then replace $out.
                        rm -rf $out
                        mkfs.ext4 -d rootfs -L rootfs -m 1 -q $out ''${IMAGE_MB}M
          '';
        }
      ];
    };

  # ---------------------------------------------------------------------------
  # Create a VM test derivation
  # ---------------------------------------------------------------------------
  checksLib = import ./checks.nix;

  # ---------------------------------------------------------------------------
  # Headless test: test script IS init (PID 1), serial PASS/FAIL markers
  # ---------------------------------------------------------------------------
  mkHeadlessTest =
    {
      name,
      testScript,
      rootfsDeps ? [ ],
      memory ? 256,
      driver ? "firecracker",
    }:
    let
      rootfs = fcLib.mkFirecrackerRootfs {
        pname = name;
        inherit testScript rootfsDeps;
      };
      kernelPath = builtins.toString kernel;

      headlessBuildDeps =
        if driver == "firecracker" then
          [
            pkgs.coreutils
            pkgs.grep
            firecracker
          ]
        else if driver == "qemu" then
          [
            pkgs.coreutils
            pkgs.grep
            qemu
          ]
        else
          throw "mkVMTest '${name}': unknown driver '${driver}' (expected 'firecracker' or 'qemu')";

      headlessFirecrackerScript = ''
        set -eu

        SERIAL_LOG="$TMPDIR/serial.log"
        FC_LOG="$TMPDIR/fc.log"
        CONFIG="$TMPDIR/vm_config.json"

        VMLINUX=$(ls $KERNEL/boot/vmlinux-* | head -1)
        if [ -z "$VMLINUX" ]; then
          echo "ERROR: No vmlinux kernel image found in $KERNEL/boot/"
          exit 1
        fi

        cp $ROOTFS rootfs.img
        chmod u+w rootfs.img

        echo "Kernel: $VMLINUX"
        echo "Rootfs: rootfs.img ($(ls -lh rootfs.img | awk '{print $5}'))"
        echo "Memory: ${builtins.toString memory} MiB"
        ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

        cat > "$CONFIG" << CFGEOF
        {
          "boot-source": {
            "kernel_image_path": "$VMLINUX",
            "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet"
          },
          "drives": [
            {
              "drive_id": "rootfs",
              "path_on_host": "$(pwd)/rootfs.img",
              "is_root_device": true,
              "is_read_only": false,
              "cache_type": "Unsafe",
              "io_engine": "Sync"
            }
          ],
          "machine-config": {
            "vcpu_count": 1,
            "mem_size_mib": ${builtins.toString memory},
            "smt": false,
            "track_dirty_pages": false,
            "huge_pages": "None"
          }
        }
        CFGEOF

        unset LD_LIBRARY_PATH || true

        echo "==> Launching Firecracker for test: ${name}"

        FC_EXIT=0
        firecracker --no-api --config-file "$CONFIG" > "$SERIAL_LOG" 2>"$FC_LOG" || FC_EXIT=$?

        echo "Firecracker exited with code: $FC_EXIT"

        if grep -q "TEST_RESULT:PASS" "$SERIAL_LOG"; then
          echo ""
          echo "==> TEST PASSED: ${name}"
          mkdir -p $out
          cp "$SERIAL_LOG" $out/serial.log
          cp "$FC_LOG" $out/fc.log 2>/dev/null || true
          echo "PASS" > $out/result
        elif grep -q "TEST_RESULT:FAIL" "$SERIAL_LOG"; then
          echo ""
          echo "==> TEST FAILED: ${name}"
          echo "--- serial.log ---"
          cat "$SERIAL_LOG"
          echo "--- fc.log ---"
          cat "$FC_LOG" 2>/dev/null || true
          exit 1
        else
          echo ""
          echo "==> ERROR: No test result marker found in serial output"
          echo "--- serial.log ---"
          cat "$SERIAL_LOG"
          echo "--- fc.log ---"
          cat "$FC_LOG" 2>/dev/null || true
          exit 1
        fi
      '';

      headlessQemuScript = ''
        set -eu

        SERIAL_LOG="$TMPDIR/serial.log"
        QEMU_LOG="$TMPDIR/qemu.log"
        CONFIG="$TMPDIR/vm_config.json"

        VMLINUZ=$(ls $KERNEL/boot/vmlinuz-* | head -1)
        if [ -z "$VMLINUZ" ]; then
          echo "ERROR: No vmlinuz kernel image found in $KERNEL/boot/"
          exit 1
        fi

        cp $ROOTFS rootfs.img
        chmod u+w rootfs.img

        echo "Kernel: $VMLINUZ"
        echo "Rootfs: rootfs.img ($(ls -lh rootfs.img | awk '{print $5}'))"
        echo "Memory: ${builtins.toString memory} MiB"
        ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

        unset LD_LIBRARY_PATH || true

        echo "==> Launching QEMU for test: ${name}"

        qemu-system-x86_64 \
          -machine q35,accel=kvm \
          -cpu host \
          -m ${builtins.toString memory} \
          -smp 1 \
          -nographic \
          -kernel "$VMLINUZ" \
          -append "root=/dev/vda ro console=ttyS0 init=/init panic=1 quiet" \
          -drive file=rootfs.img,format=raw,if=virtio \
          -no-reboot > "$SERIAL_LOG" 2>"$QEMU_LOG" || true

        if grep -q "TEST_RESULT:PASS" "$SERIAL_LOG"; then
          echo ""
          echo "==> TEST PASSED: ${name}"
          mkdir -p $out
          cp "$SERIAL_LOG" $out/serial.log
          cp "$QEMU_LOG" $out/qemu.log 2>/dev/null || true
          echo "PASS" > $out/result
        elif grep -q "TEST_RESULT:FAIL" "$SERIAL_LOG"; then
          echo ""
          echo "==> TEST FAILED: ${name}"
          echo "--- serial.log ---"
          cat "$SERIAL_LOG"
          echo "--- qemu.log ---"
          cat "$QEMU_LOG" 2>/dev/null || true
          exit 1
        else
          echo ""
          echo "==> ERROR: No test result marker found in serial output"
          echo "--- serial.log ---"
          cat "$SERIAL_LOG"
          echo "--- qemu.log ---"
          cat "$QEMU_LOG" 2>/dev/null || true
          exit 1
        fi
      '';

      headlessScript = if driver == "firecracker" then headlessFirecrackerScript else headlessQemuScript;
    in
    pkgs.mkDerivation {
      pname = "aos-vm-test-${name}";
      version = "0";
      src = null;

      buildDeps = headlessBuildDeps;

      ROOTFS = builtins.toString rootfs;
      KERNEL = kernelPath;

      phases = [
        {
          name = "test";
          script = headlessScript;
        }
      ];

      requiredSystemFeatures = [ "kvm" ];
    };

  # ---------------------------------------------------------------------------
  # Unified VM test entry point
  # ---------------------------------------------------------------------------
  # Supports two modes:
  #   - System mode (system parameter): full systemd + agent, for module checks
  #   - Headless mode (rootfsDeps parameter): test script IS init, for package checks
  mkVMTest =
    {
      name,
      driver ? "firecracker",
      # System mode (full systemd + agent):
      system ? null,
      checks ? [ ],
      userdata ? null,
      # Headless mode (test script IS init):
      rootfsDeps ? null,
      # Shared:
      testScript ? null,
      timeout ? 120,
      memory ? null,
    }:
    if rootfsDeps != null then
      mkHeadlessTest {
        inherit
          name
          testScript
          rootfsDeps
          driver
          ;
        memory = if memory != null then memory else 256;
      }
    else if system != null then
      let
        systemRootfs = mkTestRootfs { inherit system userdata; };
        systemKernel = system.config.system.build.kernel;
        # Compose checks into script, then append testScript if provided
        checksScript = if checks != [ ] then checksLib.composeChecks checks else "";
        composedScript =
          if checksScript != "" && testScript != null then
            checksScript + "\n" + testScript
          else if checksScript != "" then
            checksScript
          else if testScript != null then
            testScript
          else
            throw "mkVMTest '${name}': must provide either testScript or checks (or both)";

        effectiveMemory = if memory != null then memory else 2048;

        # Driver-specific build dependencies
        driverBuildDeps =
          if driver == "firecracker" then
            [
              pkgs.coreutils
              hostSocat
              hostJq
              firecracker
            ]
          else if driver == "qemu" then
            [
              pkgs.coreutils
              hostSocat
              hostJq
              qemu
            ]
          else
            throw "mkVMTest '${name}': unknown driver '${driver}' (expected 'firecracker' or 'qemu')";

        # -----------------------------------------------------------------------
        # Firecracker driver test script (system mode)
        # -----------------------------------------------------------------------
        firecrackerScript = ''
          set -eu

          AGENT_SOCK="$TMPDIR/agent.sock"
          SERIAL_LOG="$TMPDIR/serial.log"
          FC_LOG="$TMPDIR/firecracker.log"
          VSOCK_UDS="$TMPDIR/vm.vsock"
          FC_CFG="$TMPDIR/fc-config.json"

          # Copy rootfs image to writable location (Firecracker needs rw for system tests)
          cp $ROOTFS rootfs.img
          chmod u+w rootfs.img

          # Find the uncompressed kernel image (Firecracker requires vmlinux, not vmlinuz)
          VMLINUX=$(ls $KERNEL/boot/vmlinux-* | head -1)

          # Generate a unique CID from the builder PID (range 3-65535)
          GUEST_CID=$(( ($$ % 65533) + 3 ))

          echo "Driver: firecracker"
          echo "Kernel: $VMLINUX"
          echo "Rootfs: rootfs.img ($(ls -lh rootfs.img | awk '{print $5}'))"
          echo "CID: $GUEST_CID"
          echo "Vsock UDS: $VSOCK_UDS"
          ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

          # Write Firecracker JSON config
          cat > "$FC_CFG" << FCCFGEOF
          {
            "boot-source": {
              "kernel_image_path": "$VMLINUX",
              "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/sbin/init systemd.journald.forward_to_console=1 enforcing=0"
            },
            "drives": [
              {
                "drive_id": "rootfs",
                "path_on_host": "$(pwd)/rootfs.img",
                "is_root_device": true,
                "is_read_only": false,
                "cache_type": "Unsafe",
                "io_engine": "Sync"
              }
            ],
            "machine-config": {
              "vcpu_count": 2,
              "mem_size_mib": ${builtins.toString effectiveMemory},
              "smt": false,
              "track_dirty_pages": false,
              "huge_pages": "None"
            },
            "vsock": {
              "guest_cid": $GUEST_CID,
              "uds_path": "$VSOCK_UDS"
            },
            "network-interfaces": []
          }
          FCCFGEOF

          # Clear LD_LIBRARY_PATH — AOS build libs can conflict
          unset LD_LIBRARY_PATH

          # Firecracker wires the guest's ttyS0 to its own stdin/stdout. Feed
          # stdin from a FIFO that has a permanent, silent writer (sleep holds
          # the write end open RDWR but never writes). Guest reads from ttyS0
          # then block indefinitely — no EOF → no agetty respawn — so the debug
          # profile's autologin can coexist with the harness.
          FC_STDIN="$TMPDIR/fc-stdin"
          mkfifo "$FC_STDIN"
          sleep infinity <>"$FC_STDIN" &
          FC_STDIN_PID=$!

          # Launch Firecracker (serial output goes to stdout, redirected to file)
          firecracker --no-api --config-file "$FC_CFG" \
            < "$FC_STDIN" > "$SERIAL_LOG" 2>"$FC_LOG" &
          FC_PID=$!
          echo "Firecracker PID: $FC_PID"
          sleep 1
          if ! kill -0 "$FC_PID" 2>/dev/null; then
            echo "ERROR: Firecracker exited immediately!"
            echo "--- Firecracker log ---"
            cat "$FC_LOG" 2>/dev/null || true
            echo "--- Serial log ---"
            cat "$SERIAL_LOG" 2>/dev/null || true
            exit 1
          fi

          cleanup() {
            kill "$FC_PID" 2>/dev/null || true
            wait "$FC_PID" 2>/dev/null || true
            kill "$FC_STDIN_PID" 2>/dev/null || true
            wait "$FC_STDIN_PID" 2>/dev/null || true
          }
          trap cleanup EXIT

          # Wait for the vsock UDS to appear (Firecracker creates it on start)
          echo "Waiting for vsock UDS..."
          VSOCK_WAIT=0
          while [ ! -S "$VSOCK_UDS" ]; do
            sleep 0.1
            VSOCK_WAIT=$((VSOCK_WAIT + 1))
            if [ "$VSOCK_WAIT" -gt 100 ]; then
              echo "ERROR: vsock UDS did not appear within 10s"
              cat "$FC_LOG" 2>/dev/null || true
              exit 1
            fi
          done
          echo "vsock UDS ready."

          # Import shared test helpers (assert_success, assert_output_contains).
          # These call run_in_guest() which we override below for vsock.
          ${assertions.vmHelpers}

          # Override run_in_guest for Firecracker vsock CONNECT protocol.
          # Each call: connect to the vsock UDS, send "CONNECT 52\n" to establish
          # a connection to guest port 52, skip the "OK <port>\n" response line,
          # then send the command and read the JSON response.
          run_in_guest() {
            local cmd="$1"
            {
              printf 'CONNECT 52\n'
              sleep 0.1
              printf '%s\n' "$cmd"
              sleep 30
            } | socat - UNIX-CONNECT:"$VSOCK_UDS" 2>/dev/null | tail -n +2 | head -1
          }

          # Wait for guest agent using PING/PONG
          echo "Waiting for guest agent..."
          START_TIME=$(date +%s)
          DEADLINE=$((START_TIME + ${builtins.toString timeout}))
          AGENT_READY=0
          while [ "$(date +%s)" -lt "$DEADLINE" ]; do
            if kill -0 "$FC_PID" 2>/dev/null; then
              RESPONSE=$(run_in_guest "PING" 2>/dev/null || true)
              if echo "$RESPONSE" | grep -q '"ready"'; then
                echo "Guest agent ready."
                AGENT_READY=1
                break
              fi
            else
              echo "ERROR: Firecracker exited while waiting for agent"
              echo "--- Firecracker log ---"
              cat "$FC_LOG" 2>/dev/null || true
              echo "--- Serial log ---"
              cat "$SERIAL_LOG" 2>/dev/null || true
              exit 1
            fi
            sleep 0.5
          done

          if [ "$AGENT_READY" -ne 1 ]; then
            echo "TIMEOUT: Guest agent did not become ready within ${builtins.toString timeout}s"
            echo "--- Firecracker log ---"
            cat "$FC_LOG" 2>/dev/null || true
            echo "--- Serial log ---"
            cat "$SERIAL_LOG" 2>/dev/null || true
            exit 1
          fi

          echo ""
          echo "==> Running test: ${name}"
          echo ""

          ${composedScript}

          echo ""
          echo "Shutting down guest..."
          run_in_guest "SHUTDOWN" || true
          sleep 2
          # Firecracker exits on reboot -f from guest
          wait "$FC_PID" 2>/dev/null || true
          trap - EXIT

          echo ""
          echo "==> All tests passed for: ${name}"
          mkdir -p $out
          cp "$SERIAL_LOG" $out/serial.log 2>/dev/null || true
          echo "PASS" > $out/result
        '';

        # -----------------------------------------------------------------------
        # QEMU driver test script (system mode)
        # -----------------------------------------------------------------------
        qemuScript = ''
          set -eu

          AGENT_SOCK="$TMPDIR/agent.sock"
          SERIAL_SOCK="$TMPDIR/serial.sock"
          SERIAL_LOG="$TMPDIR/serial.log"

          # Copy rootfs image to writable location
          cp $ROOTFS rootfs.img
          chmod u+w rootfs.img

          # Find the kernel image
          VMLINUZ=$(ls $KERNEL/boot/vmlinuz-* | head -1)

          # Pre-flight checks
          QEMU_LOG="$TMPDIR/qemu.log"
          echo "Driver: qemu"
          echo "Kernel: $VMLINUZ"
          echo "Rootfs: rootfs.img ($(ls -lh rootfs.img | awk '{print $5}'))"
          ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

          # Clear LD_LIBRARY_PATH — AOS build libs can conflict with QEMU
          # (QEMU is the sole nixpkgs binary; socat/jq are AOS packages)
          unset LD_LIBRARY_PATH

          qemu-system-x86_64 --version || echo "QEMU version check failed"

          # Serial console drain: socat listens on $SERIAL_SOCK and appends
          # everything the guest writes to $SERIAL_LOG. -u makes it strictly
          # one-way (socket → file), so any guest read from /dev/ttyS0 blocks
          # on the socket — socat never writes back — matching the behavior
          # of a real idle tty with no user typing. Must be up before QEMU
          # connects as client, else early-boot output would be lost.
          socat -u UNIX-LISTEN:"$SERIAL_SOCK",reuseaddr,fork \
                   OPEN:"$SERIAL_LOG",creat,append &
          DRAIN_PID=$!
          SOCK_WAIT=0
          while [ ! -S "$SERIAL_SOCK" ]; do
            sleep 0.05
            SOCK_WAIT=$((SOCK_WAIT + 1))
            if [ "$SOCK_WAIT" -gt 100 ]; then
              echo "ERROR: serial drain socket did not appear within 5s"
              exit 1
            fi
          done

          # Launch QEMU with direct kernel boot
          qemu-system-x86_64 \
            -machine q35,accel=kvm \
            -cpu host \
            -m ${builtins.toString effectiveMemory} \
            -smp 2 \
            -nographic \
            -kernel "$VMLINUZ" \
            -append "root=/dev/vda rw console=ttyS0 init=/sbin/init panic=1 systemd.journald.forward_to_console=1 enforcing=0" \
            -drive file=rootfs.img,format=raw,if=virtio \
            -device virtio-serial \
            -device virtserialport,chardev=agent,name=aos.test.agent \
            -chardev socket,id=agent,path="$AGENT_SOCK",server=on,wait=off \
            -chardev socket,id=ttyS0,path="$SERIAL_SOCK",server=off \
            -serial chardev:ttyS0 \
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
            kill "$DRAIN_PID" 2>/dev/null || true
            wait "$DRAIN_PID" 2>/dev/null || true
          }
          trap cleanup EXIT

          # Import shared test helpers (run_in_guest, assert_success, assert_output_contains)
          ${assertions.vmHelpers}

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
            sleep 0.5
          done

          if [ "$AGENT_READY" -ne 1 ]; then
            echo "TIMEOUT: Guest agent did not become ready within ${builtins.toString timeout}s"
            echo "--- QEMU log ---"
            cat "$QEMU_LOG" 2>/dev/null || true
            echo "--- Serial log ---"
            cat "$SERIAL_LOG" 2>/dev/null || true
            exit 1
          fi

          echo ""
          echo "==> Running test: ${name}"
          echo ""

          ${composedScript}

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

        testPhaseScript = if driver == "firecracker" then firecrackerScript else qemuScript;
      in
      pkgs.mkDerivation {
        pname = "aos-vm-test-${name}";
        version = "0";
        src = null;

        buildDeps = driverBuildDeps;

        ROOTFS = builtins.toString systemRootfs;
        KERNEL = builtins.toString systemKernel;

        phases = [
          {
            name = "test";
            script = testPhaseScript;
          }
        ];

        requiredSystemFeatures = [ "kvm" ];
      }
    else
      throw "mkVMTest '${name}': must provide either 'system' (for full VM tests) or 'rootfsDeps' (for headless tests)";
in
{
  inherit mkVMTest mkTestRootfs;
}
