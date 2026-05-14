# lib/testing/vm.nix — Single-VM test harness (Firecracker only)
#
# Architecture:
#   1. Build a rootfs ext4 image from the system's Nix store closure
#      (uses mkfs.ext4 -d — no losetup/mount, sandbox-compatible)
#   2. Boot a Firecracker microVM
#   3. Guest agent communicates over vsock
#   4. Host sends commands, asserts on results
#
# Multi-VM tests live in lib/testing/fleet.nix and use QEMU (virtio-serial
# transport, multicast L2 between guests). The two harnesses are deliberately
# segregated by transport — vsock (Firecracker) here, virtio-serial (QEMU)
# there — and don't share driver state.
#
# Requirements:
#   - Kernel with built-in: VIRTIO, VIRTIO_PCI, VIRTIO_BLK, EXT4_FS,
#     VIRTIO_CONSOLE, DEVTMPFS, DEVTMPFS_MOUNT, VIRTIO_VSOCKETS, VIRTIO_MMIO
#   - requiredSystemFeatures = [ "kvm" ] on the builder
{
  pkgs,
  lib,
}: let
  firecracker = pkgs.firecracker;

  # Headless rootfs builder (for integration tests without systemd/agent)
  fcLib = import ./firecracker.nix {inherit pkgs lib;};
  kernel = pkgs.linux;

  # Shared rootfs helper (lib/build/rootfs.nix) — produces root.img.
  mkRootfs = import ../build/rootfs.nix;

  # ---------------------------------------------------------------------------
  # Build a rootfs ext4 image for VM testing
  # ---------------------------------------------------------------------------
  # Uses exportReferencesGraph to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  # ---------------------------------------------------------------------------
  # Build a GPT disk image for VM testing
  # ---------------------------------------------------------------------------
  # Produces a single $out/disk.img with four partitions matching the
  # production layout closely enough for the production initrd + ignition
  # services to run unchanged against it:
  #
  #   1  boot  — 4 MiB, unformatted. Vestigial — kernel + initrd come in
  #              via `-kernel`/`-initrd`, partition 1 is never mounted.
  #              Reserving 4 MiB keeps root at /dev/vda2 matching
  #              production device naming.
  #   2  root  — ext4, sized to fit. The system's /etc is pre-split
  #              to /etc.lower at image-build time so the production
  #              etc-overlay-setup.service skips its first-boot remount-rw
  #              dance on ro root.
  #   3  swap  — 8 MiB stub with the Linux-swap GPT GUID, no body.
  #              cryptswap.service's `Requires=` on the auto-instantiated
  #              `dev-disk-by-partlabel-swap.device` would otherwise sit
  #              queued for 90 s on every boot waiting for udev to
  #              announce a partition that doesn't exist.
  #   4  var   — 32 MiB ext4, empty. Label `var` via GPT partlabel so
  #              the production mount-var.service mounts it on every boot.
  # `mkTestDisk` is a function of `system` only — two callers passing
  # the same system reference the same Nix derivation, which is what
  # lets fleet tests share one disk across every machine of a given
  # variant.
  #
  # Per-instance state (hostname, /etc/hosts, eth0 .network) is no
  # longer baked in here; the harnesses deliver it through ignition
  # via the metadata ISO. The default `/etc.lower/hostname` written
  # below is `aos-test` — at runtime, ignition's `/etc/hostname`
  # write lands on the etc-overlay's upper layer (`/var/etc/hostname`)
  # which shadows this lower-layer file. So the baked hostname is a
  # fallback for tests that never deliver an instance identity, and
  # the production-faithful identity flow shadows it when used.
  mkTestDisk = {
    system,
    name ? "aos-disk",
  }: let
    systemPackages = system.config.environment.systemPackages;

    # Shell fragment spliced into the shared rootfs helper's populate
    # phase after tree population, before mkfs. Runs with `rootfs/` as
    # the populated tree and `$ETC_TARGET` pointing at `etc.lower` —
    # the lower layer of the production /etc overlay (pre-split to skip
    # the first-boot remount-rw dance).
    postPopulate = ''
      # ── systemd's /lib/* subdirs into merged-usr /usr/lib ──
      # Provides udev rules, tmpfiles.d, sysctl.d, and systemd's own
      # library-adjacent helpers that tools look up at /lib/... paths.
      # Don't stomp on /usr/lib/modules which the helper already wired.
      for d in "${pkgs.systemd}/lib/"*; do
        n=$(basename "$d")
        [ -e "rootfs/usr/lib/$n" ] || ln -sfn "$d" "rootfs/usr/lib/$n"
      done

      # /etc is the overlay mountpoint — the helper populated
      # /etc.lower; leave /etc as an empty mountpoint.
      mkdir -p rootfs/etc
      # /run/etc-upper is where etc-overlay-setup mounts the tmpfs
      # that carries the overlay's upper+work dirs. Pre-creating
      # keeps the first-boot setup on the cold path.
      mkdir -p rootfs/run/etc-upper
      # /opt/aos-test/bin holds the test agent scripts.
      mkdir -p rootfs/opt/aos-test/bin

      # SELinux override — the test rootfs has no policy files and
      # enforcing mode causes systemd to freeze when it can't load
      # the policy. Only applies if the toplevel /etc had a config.
      if [ -f "rootfs/$ETC_TARGET/selinux/config" ]; then
        cat > "rootfs/$ETC_TARGET/selinux/config" << 'SELINUXCFG'
      SELINUX=disabled
      SELINUXTYPE=targeted
      SELINUXCFG
      fi

      # Default hostname goes into etc.lower (the overlay's lower
      # layer). Ignition's `/etc/hostname` write lands on the upper
      # layer at runtime and shadows this — so tests delivering a
      # per-instance identity through ignition see the identity
      # fragment's hostname; tests that don't see "aos-test".
      echo "aos-test" > "rootfs/$ETC_TARGET/hostname"
      # Empty fstab — systemd-fstab-generator synthesizes sysroot.mount
      # from root= on the cmdline; mount-var.service handles /var.
      : > "rootfs/$ETC_TARGET/fstab"

      # Pre-generate SSH host key so sshd can start without the keygen
      # service (which expects /var/etc/ssh from the production overlay
      # setup). The key lives in the etc-overlay lower layer so sshd
      # finds it via the overlay.
      mkdir -p "rootfs/$ETC_TARGET/ssh"
      ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" \
        -f "rootfs/$ETC_TARGET/ssh/ssh_host_ed25519_key" </dev/null

      cat > "rootfs/$ETC_TARGET/os-release" << 'OSREL'
      ID=aos
      NAME="ANDYL OS"
      PRETTY_NAME="ANDYL OS (test)"
      VERSION_ID=0.1
      OSREL

      # Fallback passwd/group/shadow if toplevel didn't provide them.
      # The users module generates these for module-defined users
      # (chrony, sshd, etc.); writing fallbacks keeps early-boot
      # systemd services functional when running a minimal system.
      if [ ! -s "rootfs/$ETC_TARGET/passwd" ]; then
        cat > "rootfs/$ETC_TARGET/passwd" << 'PASSWD'
      root:x:0:0:root:/root:/bin/sh
      nobody:x:65534:65534:Nobody:/:/sbin/nologin
      systemd-journal:x:101:101:systemd Journal:/:/sbin/nologin
      systemd-network:x:102:102:systemd Network:/:/sbin/nologin
      PASSWD
      fi
      if [ ! -s "rootfs/$ETC_TARGET/group" ]; then
        cat > "rootfs/$ETC_TARGET/group" << 'GROUP'
      root:x:0:
      nobody:x:65534:
      utmp:x:22:
      systemd-journal:x:101:
      systemd-network:x:102:
      GROUP
      fi
      if [ ! -s "rootfs/$ETC_TARGET/shadow" ]; then
        cat > "rootfs/$ETC_TARGET/shadow" << 'SHADOW'
      root:!:1::::::
      nobody:!:1::::::
      SHADOW
      fi
      chmod 640 "rootfs/$ETC_TARGET/shadow"

      cat > "rootfs/$ETC_TARGET/nsswitch.conf" << 'NSS'
      passwd: files
      group:  files
      shadow: files
      hosts:  files dns
      NSS

      # ── Guest agent handler: one framed request from stdin → framed
      # response to stdout. Wire format (v2):
      #   Frame:        <ascii-decimal body_len>\n<body bytes>
      #   Request body: bash blob, OR the literal ASCII "PING"/"SHUTDOWN".
      #   Response body:
      #     <exit_code> <stdout_len> <stderr_len>\n<stdout bytes><stderr bytes>
      # Header line is three space-separated ASCII-decimal integers
      # terminated by \n; the stdout/stderr payloads are raw bytes
      # concatenated immediately after. PING and SHUTDOWN replies are
      # the bare 6-byte body `0 0 0\n` (no payload) — matching how
      # bash succeed/fail responses on empty output would be encoded.
      cat > rootfs/opt/aos-test/bin/agent-handler << 'HANDLER'
      #!/bin/sh
      # LC_ALL=C makes parameter-length counting byte-based (not
      # character-based) and keeps printf locale-independent. Byte-
      # counting matters because the outer length prefix is in bytes.
      LC_ALL=C
      export LC_ALL
      set -u
      export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

      MAX=$((16 * 1024 * 1024))

      IFS= read -r len_line || exit 0
      case "$len_line" in
        '''|*[!0-9]*)
          echo "aos-test-agent: malformed length line: '$len_line'" >&2
          exit 1
          ;;
      esac
      if [ "$len_line" -gt "$MAX" ]; then
        echo "aos-test-agent: request length $len_line exceeds $MAX" >&2
        exit 1
      fi

      # head -c reads exactly N bytes from stdin (the socket); writing
      # to a file dodges $()'s trailing-newline strip and lets us run
      # multi-line scripts via `bash /tmp/agent-cmd`.
      head -c "$len_line" > /tmp/agent-cmd
      actual=$(stat -c %s /tmp/agent-cmd)
      if [ "$actual" -ne "$len_line" ]; then
        echo "aos-test-agent: short read ($actual / $len_line)" >&2
        exit 1
      fi

      cmd=$(cat /tmp/agent-cmd)
      echo "aos-test-agent: received ($len_line bytes)" >&2

      if [ "$cmd" = "PING" ]; then
        # Body is `0 0 0\n` (6 bytes); outer frame `6\n0 0 0\n`.
        printf '6\n0 0 0\n'
        exit 0
      fi
      if [ "$cmd" = "SHUTDOWN" ]; then
        printf '6\n0 0 0\n'
        # Firecracker needs reboot -f (poweroff hangs); QEMU uses poweroff -f.
        if [ -e /dev/vsock ]; then
          reboot -f
        else
          poweroff -f
        fi
        exit 0
      fi

      bash /tmp/agent-cmd >/tmp/agent-stdout 2>/tmp/agent-stderr
      exit_code=$?
      stdout_size=$(stat -c %s /tmp/agent-stdout)
      stderr_size=$(stat -c %s /tmp/agent-stderr)
      header="$exit_code $stdout_size $stderr_size"
      # +1 for the newline that terminates the header line.
      total=$(( ''${#header} + 1 + stdout_size + stderr_size ))
      printf '%d\n' "$total"
      printf '%s\n' "$header"
      cat /tmp/agent-stdout
      cat /tmp/agent-stderr
      HANDLER
      chmod +x rootfs/opt/aos-test/bin/agent-handler

      # ── Guest agent: auto-detect virtio-serial vs vsock, listen.
      # Detection ORDER matters. The AOS kernel has CONFIG_VSOCKETS=y
      # built-in (pkgs/kernel/config/drivers-vm.config), so /dev/vsock
      # is created on every guest regardless of whether the host
      # provided a virtio-vsock device. The virtio-serial port path
      # (/dev/virtio-ports/aos.test.agent) only appears when QEMU
      # actually attaches a virtserialport — making it the definitive
      # "QEMU + virtio-serial harness" indicator. Check that first;
      # only fall back to vsock when no virtio port shows up after a
      # short wait (Firecracker's transport).
      cat > rootfs/opt/aos-test/bin/aos-test-agent << 'AGENT'
      #!/bin/sh
      # See agent-handler for the wire format (v2). LC_ALL=C: byte-
      # counting parameter expansions and locale-independent printf.
      #
      # Each request reopens $AGENT_PORT on fd 3 (read+write) and closes
      # it after writing the response. A persistent open across multiple
      # host connections gets a hang-up when the host disconnects between
      # requests and subsequent reads return EOF — fd 3 must therefore be
      # scoped to a single request/response pair. Within one request the
      # fd MUST stay open between the LEN line and the body bytes so the
      # body bytes aren't lost between successive opens.
      LC_ALL=C
      export LC_ALL
      set -u
      export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

      MAX=$((16 * 1024 * 1024))

      AGENT_PORT=""
      echo "aos-test-agent: probing transports..." >&2
      TRIES=0
      while [ -z "$AGENT_PORT" ] && [ "$TRIES" -lt 30 ]; do
        if [ -e "/dev/virtio-ports/aos.test.agent" ]; then
          AGENT_PORT="/dev/virtio-ports/aos.test.agent"
          break
        fi
        if [ -e "/dev/vport0p1" ]; then
          AGENT_PORT="/dev/vport0p1"
          break
        fi
        TRIES=$((TRIES + 1))
        sleep 0.1
      done

      if [ -z "$AGENT_PORT" ] && [ -e /dev/vsock ]; then
        # vsock mode (Firecracker) — listen on port 52; each host CONNECT
        # spawns a new agent-handler via socat EXEC.
        echo "aos-test-agent: vsock mode, listening on port 52" >&2
        exec socat VSOCK-LISTEN:52,reuseaddr,fork EXEC:/opt/aos-test/bin/agent-handler
      fi

      if [ -z "$AGENT_PORT" ]; then
        echo "aos-test-agent: no transport found (no virtio port, no /dev/vsock)" >&2
        ls /dev/vport* 2>&1 >&2 || true
        ls /dev/virtio-ports/ 2>&1 >&2 || true
        exit 1
      fi
      echo "aos-test-agent: virtio-serial mode, using port $AGENT_PORT" >&2

      while true; do
        # Open the port for both directions on fd 3 for this one request.
        exec 3<> "$AGENT_PORT"

        if ! IFS= read -r len_line <&3; then
          exec 3<&-
          sleep 0.1
          continue
        fi
        case "$len_line" in
          '''|*[!0-9]*)
            echo "aos-test-agent: malformed length line: '$len_line'" >&2
            exec 3<&-
            continue
            ;;
        esac
        if [ "$len_line" -gt "$MAX" ]; then
          echo "aos-test-agent: request length $len_line exceeds $MAX" >&2
          exec 3<&-
          continue
        fi

        head -c "$len_line" <&3 > /tmp/agent-cmd
        actual=$(stat -c %s /tmp/agent-cmd)
        if [ "$actual" -ne "$len_line" ]; then
          echo "aos-test-agent: short read ($actual / $len_line)" >&2
          exec 3<&-
          continue
        fi

        cmd=$(cat /tmp/agent-cmd)
        echo "aos-test-agent: received ($len_line bytes)" >&2

        if [ "$cmd" = "PING" ]; then
          # Body is `0 0 0\n` (6 bytes); outer frame `6\n0 0 0\n`.
          printf '6\n0 0 0\n' >&3
          exec 3<&-
          continue
        fi
        if [ "$cmd" = "SHUTDOWN" ]; then
          printf '6\n0 0 0\n' >&3
          exec 3<&-
          poweroff -f
          exit 0
        fi

        bash /tmp/agent-cmd >/tmp/agent-stdout 2>/tmp/agent-stderr
        exit_code=$?
        stdout_size=$(stat -c %s /tmp/agent-stdout)
        stderr_size=$(stat -c %s /tmp/agent-stderr)
        header="$exit_code $stdout_size $stderr_size"
        # +1 for the newline terminating the header line.
        total=$(( ''${#header} + 1 + stdout_size + stderr_size ))
        # Stage the entire frame (outer length + body) in one file then
        # emit it with a single `cat` to fd 3. Multiple successive
        # writes to the virtio-serial chardev between host
        # disconnect/reconnect cycles race against QEMU's chardev
        # accept loop — the old wire's single-printf shape worked, and
        # the new wire matches that by composing the whole frame
        # off-fd-3 first.
        {
          printf '%d\n' "$total"
          printf '%s\n' "$header"
          cat /tmp/agent-stdout
          cat /tmp/agent-stderr
        } > /tmp/agent-frame
        cat /tmp/agent-frame >&3
        exec 3<&-
      done
      AGENT
      chmod +x rootfs/opt/aos-test/bin/aos-test-agent

      # Guest agent systemd service. Drivers present a properly blocking
      # serial backend so a live getty can coexist with the harness;
      # no masking of serial-getty@ttyS0 is needed.
      #
      # The agent is gated behind aos-test.target, which is ordered
      # After=multi-user.target. Systemd only activates aos-test.target
      # once multi-user.target has reached "active" (i.e. all its Wants=
      # — sshd, containerd, kubelet — have finished activating), so by
      # the time the agent's ExecStart fires, `systemctl is-active
      # multi-user.target` is provably true. No shell polling required.
      mkdir -p "rootfs/$ETC_TARGET/systemd/system/multi-user.target.wants"
      mkdir -p "rootfs/$ETC_TARGET/systemd/system/aos-test.target.wants"
      cat > "rootfs/$ETC_TARGET/systemd/system/aos-test.target" << 'UNIT'
      [Unit]
      Description=AOS VM Test Harness Ready
      After=multi-user.target
      Wants=multi-user.target

      [Install]
      WantedBy=multi-user.target
      UNIT
      cat > "rootfs/$ETC_TARGET/systemd/system/aos-test-agent.service" << 'UNIT'
      [Unit]
      Description=AOS VM Test Guest Agent
      After=systemd-udevd.service aos-test.target
      Wants=systemd-udevd.service
      Requires=aos-test.target

      [Service]
      Type=simple
      ExecStart=/opt/aos-test/bin/aos-test-agent
      Restart=on-failure
      RestartSec=1

      [Install]
      WantedBy=aos-test.target
      UNIT
      ln -sfn ../aos-test.target \
        "rootfs/$ETC_TARGET/systemd/system/multi-user.target.wants/aos-test.target"
      ln -sfn ../aos-test-agent.service \
        "rootfs/$ETC_TARGET/systemd/system/aos-test.target.wants/aos-test-agent.service"
    '';

    rootfs = mkRootfs {
      inherit pkgs lib system;
      pname = "vm-disk-${name}-rootfs";
      label = "aos-root";
      # /etc.lower layout — stage-2 etc-overlay-setup.service mounts an
      # overlayfs on /etc with /etc.lower as the base lower layer.
      etcTarget = "etc.lower";
      unwrapStoreSymlinks = true;
      # Leave the image at its initial over-provisioned size — tests
      # can write a lot during execution. 2048 MiB floor matches the
      # pre-refactor behavior.
      shrinkToFit = false;
      minSizeMiB = 2048;
      # Over and above toplevel + kernel: systemd/coreutils/bash/socat
      # are depended on transitively by toplevel, but the agent scripts
      # reference socat at a runtime-only path (not via environment.
      # systemPackages), so include explicitly to guarantee its closure
      # lands in /nix/store. The other three are no-ops if already in
      # toplevel's closure.
      extraClosures = [
        pkgs.systemd
        pkgs.coreutils
        pkgs.bash
        pkgs.socat
      ];
      # Symlink farm into /usr/bin, /usr/sbin, /usr/libexec. Ordering
      # is first-wins for collisions — coreutils before systemd so
      # coreutils' `env` / `ls` / etc. don't get shadowed.
      symlinkFarmPkgs =
        [
          pkgs.coreutils
          pkgs.systemd
          pkgs.socat
        ]
        ++ systemPackages;
      inherit postPopulate;
    };
  in
    pkgs.mkDerivation {
      pname = "vm-disk-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.e2fsprogs
        pkgs.coreutils
        pkgs.fakeroot
        pkgs.util-linux # sfdisk
      ];

      ROOT_IMG = "${rootfs}/root.img";
      ROOT_SIZE_FILE = "${rootfs}/rootfs-size-bytes";

      phases = [
        {
          name = "assemble";
          script = ''
            set -eu

            # ── /var partition staging ──────────────────────────────────
            mkdir -p var

            # fakeroot so the var partition's files land as uid/gid 0.
            fakeroot -- mkfs.ext4 -d var -L aos-var -m 0 -q var.img 32M

            # ── Root image from the shared rootfs helper ────────────────
            cp "$ROOT_IMG" root.img
            chmod u+w root.img
            root_bytes=$(cat "$ROOT_SIZE_FILE")

            # ── Assemble the GPT disk image ─────────────────────────────
            # Sizes in 512-byte sectors; 1 MiB alignment at start and end
            # for GPT headers. Partition 1 (boot) is vestigial in tests
            # — the harness passes kernel+initrd via -kernel/-initrd —
            # but reserving it keeps root at /dev/vda2 matching production.
            BOOT_SECTORS=$(( 4 * 1024 * 1024 / 512 ))   # 4 MiB
            ROOT_SECTORS=$(( root_bytes / 512 ))
            SWAP_SECTORS=$(( 8 * 1024 * 1024 / 512 ))   # 8 MiB
            VAR_SECTORS=$((  32 * 1024 * 1024 / 512 ))  # 32 MiB

            BOOT_START=2048
            ROOT_START=$(( BOOT_START + BOOT_SECTORS ))
            SWAP_START=$(( ROOT_START + ROOT_SECTORS ))
            VAR_START=$((  SWAP_START + SWAP_SECTORS ))
            DISK_SECTORS=$(( VAR_START + VAR_SECTORS + 2048 ))
            DISK_BYTES=$(( DISK_SECTORS * 512 ))

            echo "==> Assembling $(( DISK_BYTES / 1048576 )) MiB GPT disk image"
            truncate -s "$DISK_BYTES" disk.img

            # Standard Linux filesystem GUID for boot/root/var; Linux
            # swap GUID for the swap stub. The partlabel `var` is what
            # mount-var.service binds to via /dev/disk/by-partlabel/var.
            # The root partition is labelled `root-a` to match the
            # production A/B layout — aos-growfs triggers on
            # ConditionPathExists=/dev/disk/by-partlabel/root-a.
            sfdisk disk.img <<PTABLE
            label: gpt
            size=$BOOT_SECTORS, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="boot"
            size=$ROOT_SECTORS, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root-a"
            size=$SWAP_SECTORS, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, name="swap"
            size=$VAR_SECTORS,  type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="var"
            PTABLE

            dd if=root.img of=disk.img bs=512 seek="$ROOT_START" conv=notrunc status=none
            dd if=var.img  of=disk.img bs=512 seek="$VAR_START"  conv=notrunc status=none

            mkdir -p $out
            mv disk.img $out/disk.img
          '';
        }
      ];
    };

  # Metadata ISO builder (shared with fleet.nix). See metadata.nix.
  inherit (import ./metadata.nix {inherit pkgs lib;}) mkMetadataIso;

  # ---------------------------------------------------------------------------
  # Create a VM test derivation
  # ---------------------------------------------------------------------------
  checksLib = import ./checks.nix;

  # ---------------------------------------------------------------------------
  # Headless test: test script IS init (PID 1), serial PASS/FAIL markers
  # ---------------------------------------------------------------------------
  mkHeadlessTest = {
    name,
    testScript,
    rootfsDeps ? [],
    memory ? 256,
  }: let
    rootfs = fcLib.mkFirecrackerRootfs {
      pname = name;
      inherit testScript rootfsDeps;
    };
    kernelPath = builtins.toString kernel;

    headlessBuildDeps = [
      pkgs.coreutils
      pkgs.grep
      firecracker
    ];

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
          script = headlessFirecrackerScript;
        }
      ];

      requiredSystemFeatures = ["kvm"];
    };

  # ---------------------------------------------------------------------------
  # Unified VM test entry point
  # ---------------------------------------------------------------------------
  # Supports two modes:
  #   - System mode (system parameter): full systemd + agent, for module checks
  #   - Headless mode (rootfsDeps parameter): test script IS init, for package checks
  mkVMTest = {
    name,
    # System mode (full systemd + agent):
    system ? null,
    groupName ? name,
    checks ? [],
    instanceMetadata ? null,
    # Headless mode (test script IS init):
    rootfsDeps ? null,
    # Shared:
    testScript ? null,
    timeout ? 120,
    memory ? null,
  }:
    assert (instanceMetadata != null -> system != null)
    || throw "mkVMTest '${name}': instanceMetadata requires system mode (got rootfsDeps or neither)";
      if rootfsDeps != null
      then
        mkHeadlessTest {
          inherit
            name
            testScript
            rootfsDeps
            ;
          memory =
            if memory != null
            then memory
            else 256;
        }
      else if system != null
      then let
        systemDisk = mkTestDisk {inherit system;};
        systemKernel = system.config.system.build.kernel;
        systemInitrd = system.config.system.build.initrd;

        systemMetadataDisk =
          if instanceMetadata != null
          then
            mkMetadataIso {
              inherit name;
              ignitionConfig = instanceMetadata.config;
            }
          else null;

        hasMetadata = instanceMetadata != null;

        # Compose Python check fragments into the test source, then
        # append the user's testScript if provided. Both halves are
        # Python now; see lib/testing/checks.nix:composeChecks.
        checksPy =
          if checks != []
          then checksLib.composeChecks {inherit groupName checks;}
          else "";
        composedTestPy =
          if checksPy != "" && testScript != null
          then checksPy + "\n" + testScript
          else if checksPy != ""
          then checksPy
          else if testScript != null
          then testScript
          else throw "mkVMTest '${name}': must provide either testScript or checks (or both)";

        effectiveMemory =
          if memory != null
          then memory
          else 2048;

        # Driver manifest. The aos-test-driver consumes this JSON to
        # build one FirecrackerMachine; the testScript runs as a
        # Python module via runpy with `vm` exposed as a global. See
        # the v1 spec ("Manifest schema") for the full field list.
        manifest = {
          inherit name timeout;
          machines = [
            {
              name = "vm";
              transport = "firecracker";
              kernel = builtins.toString systemKernel;
              initrd = "${builtins.toString systemInitrd}/initrd.img";
              disk = "${builtins.toString systemDisk}/disk.img";
              metadata =
                if hasMetadata
                then "${builtins.toString systemMetadataDisk}/metadata.iso"
                else null;
              memory_mib = effectiveMemory;
              vcpu_count = 2;
            }
          ];
        };
        manifestFile = pkgs.writeTextFile {
          name = "aos-vm-test-${name}-manifest.json";
          text = builtins.toJSON manifest;
          destination = "/manifest.json";
        };
        testPyFile = pkgs.writeTextFile {
          name = "aos-vm-test-${name}-test.py";
          text = composedTestPy;
          destination = "/test.py";
        };

        driverBuildDeps = [
          pkgs.coreutils
          firecracker
          pkgs.socat
          pkgs.python3
          pkgs.aos-test-driver
        ];

        # -----------------------------------------------------------------------
        # Firecracker driver script (system mode)
        # -----------------------------------------------------------------------
        # The host-side glue is now thin: write manifest + test.py into
        # $TMPDIR, exec aos-test-driver, copy logs into $out. Boot
        # plumbing (Firecracker JSON, vsock handshake, agent wait,
        # shutdown) lives in aos_test_driver/firecracker.py.
        firecrackerDriverScript = ''
          set -eu

          # AOS build libs can conflict with the driver's child processes
          # (Firecracker, python's own runtime linker). Match what the
          # bash driver did.
          unset LD_LIBRARY_PATH

          cp ${manifestFile}/manifest.json "$TMPDIR/manifest.json"
          cp ${testPyFile}/test.py         "$TMPDIR/test.py"

          ${pkgs.aos-test-driver}/bin/aos-test-driver \
            --manifest "$TMPDIR/manifest.json" \
            --test     "$TMPDIR/test.py"

          mkdir -p "$out"
          for log in "$TMPDIR"/*-serial.log "$TMPDIR"/*-firecracker.log; do
            [ -f "$log" ] && cp "$log" "$out/"
          done
          echo PASS > "$out/result"
        '';
      in
        pkgs.mkDerivation {
          pname = "aos-vm-test-${name}";
          version = "0";
          src = null;

          buildDeps = driverBuildDeps;

          phases = [
            {
              name = "test";
              script = firecrackerDriverScript;
            }
          ];

          requiredSystemFeatures = ["kvm"];
        }
      else throw "mkVMTest '${name}': must provide either 'system' (for full VM tests) or 'rootfsDeps' (for headless tests)";
in {
  inherit mkVMTest mkTestDisk;
}
