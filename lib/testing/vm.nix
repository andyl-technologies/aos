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
  testTools ? {},
}: let
  # QEMU is the sole host-tool exception (CLAUDE.md) — too complex to bootstrap.
  # socat, jq, and firecracker are AOS packages built from source.
  qemu = testTools.qemu;
  hostSocat = pkgs.socat;
  hostJq = pkgs.jq;
  firecracker = pkgs.firecracker;

  # Headless rootfs builder (for integration tests without systemd/agent)
  fcLib = import ./firecracker.nix {inherit pkgs lib;};
  kernel = pkgs.linux;

  # Shared rootfs helper (lib/build/rootfs.nix) — produces root.img.
  mkRootfs = import ../build/rootfs.nix;

  # Shared shell assertion helpers
  assertions = import ./assertions.nix {inherit (pkgs) aos-agent-rpc;};

  # ---------------------------------------------------------------------------
  # Build a rootfs ext4 image for VM testing
  # ---------------------------------------------------------------------------
  # Uses exportReferencesGraph to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  # ---------------------------------------------------------------------------
  # Build a GPT disk image for VM testing
  # ---------------------------------------------------------------------------
  # Produces a single $out/disk.img with three partitions matching the
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
  #   3  var   — 32 MiB ext4, empty (apart from an optional NoCloud seed
  #              for cloudInitTests). Label `var` via GPT partlabel so
  #              the production mount-var.service mounts it on every boot.
  mkTestDisk = {
    system,
    name ? "aos-test",
    hostname ? "aos-test",
    networkConfig ? null,
    hostsEntries ? null,
    userdata ? null,
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

      echo "${hostname}" > "rootfs/$ETC_TARGET/hostname"
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

      ${
        if hostsEntries != null
        then ''
          cat > "rootfs/$ETC_TARGET/hosts" << 'HOSTS'
          127.0.0.1 localhost
          ${hostsEntries}
          HOSTS
        ''
        else ""
      }
      ${
        if networkConfig != null
        then ''
          mkdir -p "rootfs/$ETC_TARGET/systemd/network"
          cat > "rootfs/$ETC_TARGET/systemd/network/10-eth0.network" << 'NETCFG'
          ${networkConfig}
          NETCFG
        ''
        else ""
      }

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

      # ── Guest agent handler: one command from stdin → JSON to stdout.
      cat > rootfs/opt/aos-test/bin/agent-handler << 'HANDLER'
      #!/bin/sh
      set -u
      export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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
        # Firecracker needs reboot -f (poweroff hangs); QEMU uses poweroff -f.
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
      NL='
      '
      escape_json() {
        local s="$1"
        s="''${s//\\/\\\\}"
        s="''${s//\"/\\\"}"
        s="''${s//$'\t'/\\t}"
        s="''${s//$'\r'/\\r}"
        s="''${s//$NL/\\n}"
        printf '%s' "$s"
      }
      stdout_escaped=$(escape_json "$stdout")
      stderr_escaped=$(escape_json "$stderr")
      printf '{"exit_code":%d,"stdout":"%s","stderr":"%s"}\n' \
        "$exit_code" "$stdout_escaped" "$stderr_escaped"
      HANDLER
      chmod +x rootfs/opt/aos-test/bin/agent-handler

      # ── Guest agent: auto-detect vsock vs virtio-serial, listen.
      cat > rootfs/opt/aos-test/bin/aos-test-agent << 'AGENT'
      #!/bin/sh
      set -u
      export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

      if [ -e /dev/vsock ]; then
        # vsock mode (Firecracker) — listen on port 52; each host CONNECT
        # spawns a new agent-handler via socat EXEC.
        echo "aos-test-agent: vsock mode, listening on port 52" >&2
        sleep 0.5
        exec socat VSOCK-LISTEN:52,reuseaddr,fork EXEC:/opt/aos-test/bin/agent-handler
      fi

      # virtio-serial mode (QEMU)
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

      while true; do
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
        NL='
      '
        escape_json() {
          local s="$1"
          s="''${s//\\/\\\\}"
          s="''${s//\"/\\\"}"
          s="''${s//$'\t'/\\t}"
          s="''${s//$'\r'/\\r}"
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

      # Guest agent systemd service. Drivers present a properly blocking
      # serial backend so a live getty can coexist with the harness;
      # no masking of serial-getty@ttyS0 is needed.
      mkdir -p "rootfs/$ETC_TARGET/systemd/system/multi-user.target.wants"
      cat > "rootfs/$ETC_TARGET/systemd/system/aos-test-agent.service" << 'UNIT'
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
        "rootfs/$ETC_TARGET/systemd/system/multi-user.target.wants/aos-test-agent.service"
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
            # For cloudInitTests the NoCloud seed files live on this
            # partition so cloud-init finds them once /var is mounted.
            mkdir -p var
            ${
              if userdata != null
              then ''
                mkdir -p var/lib/cloud/seed/nocloud
                mkdir -p var/lib/cloud/state
                cat > var/lib/cloud/seed/nocloud/user-data << 'USERDATAEOF'
                ${userdata}
                USERDATAEOF
                cat > var/lib/cloud/seed/nocloud/meta-data << 'METADATAEOF'
                {"instance-id":"test-vm","local-hostname":"aos-test"}
                METADATAEOF
              ''
              else ""
            }

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
            VAR_SECTORS=$((  32 * 1024 * 1024 / 512 )) # 32 MiB

            BOOT_START=2048
            ROOT_START=$(( BOOT_START + BOOT_SECTORS ))
            VAR_START=$(( ROOT_START + ROOT_SECTORS ))
            DISK_SECTORS=$(( VAR_START + VAR_SECTORS + 2048 ))
            DISK_BYTES=$(( DISK_SECTORS * 512 ))

            echo "==> Assembling $(( DISK_BYTES / 1048576 )) MiB GPT disk image"
            truncate -s "$DISK_BYTES" disk.img

            # Standard Linux filesystem GUID for all three partitions.
            # The partlabel `var` is what mount-var.service binds to via
            # /dev/disk/by-partlabel/var. The root partition is labelled
            # `root-a` to match the production A/B layout — aos-growfs
            # triggers on ConditionPathExists=/dev/disk/by-partlabel/root-a.
            sfdisk disk.img <<PTABLE
            label: gpt
            size=$BOOT_SECTORS, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="boot"
            size=$ROOT_SECTORS, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root-a"
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

  # ---------------------------------------------------------------------------
  # Per-test metadata ISO (ISO9660, volume label aos-metadata)
  # ---------------------------------------------------------------------------
  # Produces a small ISO9660 image with one file — config.json — that the
  # initrd-side aos-platform-detect.service mounts at /run/aos-metadata and
  # reads via IGNITION_CONFIG_FILE. Same developer ergonomics as the old
  # ext4 + HTTP channel, zero guest-side daemons, and the transport matches
  # what bare-metal operators attach over IPMI virtual media.
  #
  # Serialisation and `ignition-validate` both live in
  # `lib/formats/ignition.nix`, so this derivation only has to package
  # an already-validated `config.json` into an ext4 image.
  ignitionTestFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };

  mkMetadataIso = {
    name,
    ignitionConfig,
  }: let
    configDrv = ignitionTestFormat.generate "config.json" ignitionConfig;
  in
    pkgs.mkDerivation {
      pname = "vm-metadata-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.libisoburn # provides xorriso
      ];

      # `configDrv` is a directory (AOS `mkDerivation` convention) —
      # the JSON file sits at `${configDrv}/config.json`.
      CONFIG_JSON = "${configDrv}/config.json";

      phases = [
        {
          name = "build-metadata";
          script = ''
            mkdir staging
            cp "$CONFIG_JSON" staging/config.json

            mkdir -p $out
            # Volume label `aos-metadata` is what blkid picks up via
            # ISO9660's volume descriptor; the guest-side detector
            # gates on /dev/disk/by-label/aos-metadata.
            xorriso -as mkisofs \
              -volid aos-metadata \
              -output $out/metadata.iso \
              -r staging/
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
  mkHeadlessTest = {
    name,
    testScript,
    rootfsDeps ? [],
    memory ? 256,
    driver ? "firecracker",
  }: let
    rootfs = fcLib.mkFirecrackerRootfs {
      pname = name;
      inherit testScript rootfsDeps;
    };
    kernelPath = builtins.toString kernel;

    headlessBuildDeps =
      if driver == "firecracker"
      then [
        pkgs.coreutils
        pkgs.grep
        firecracker
      ]
      else if driver == "qemu"
      then [
        pkgs.coreutils
        pkgs.grep
        qemu
      ]
      else throw "mkVMTest '${name}': unknown driver '${driver}' (expected 'firecracker' or 'qemu')";

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

    headlessScript =
      if driver == "firecracker"
      then headlessFirecrackerScript
      else headlessQemuScript;
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
    driver ? "firecracker",
    # System mode (full systemd + agent):
    system ? null,
    groupName ? name,
    checks ? [],
    userdata ? null,
    instanceMetadata ? null,
    # Headless mode (test script IS init):
    rootfsDeps ? null,
    # Shared:
    testScript ? null,
    timeout ? 120,
    memory ? null,
  }:
    if rootfsDeps != null
    then
      mkHeadlessTest {
        inherit
          name
          testScript
          rootfsDeps
          driver
          ;
        memory =
          if memory != null
          then memory
          else 256;
      }
    else if system != null
    then let
      systemDisk = mkTestDisk {inherit system userdata;};
      systemKernel = system.config.system.build.kernel;
      systemInitrd = system.config.system.build.initrd;

      # When instanceMetadata is set the harness must boot against a
      # system that has ignition enabled, otherwise ignition-fetch is
      # absent from the initrd and the metadata channel is dead.
      # Assert at eval-time with a clear message.
      _ignitionCheck =
        if instanceMetadata != null && !(system.config.aos.services.ignition.enable or false)
        then throw "mkVMTest '${name}': instanceMetadata requires aos.services.ignition.enable = true on the system under test"
        else null;

      systemMetadataDisk =
        if instanceMetadata != null
        then
          mkMetadataIso {
            inherit name;
            ignitionConfig = instanceMetadata.config;
          }
        else null;

      hasMetadata = instanceMetadata != null;

      # Firecracker has no CD-ROM support, so the ISO is attached as a
      # read-only virtio-blk drive. blkid probes the ISO9660 superblock
      # regardless of transport, so the guest-side detector still finds
      # /dev/disk/by-label/aos-metadata.
      fcMetadataDrive =
        if hasMetadata
        then ''
          ,
            {
              "drive_id": "metadata",
              "path_on_host": "$(pwd)/metadata.iso",
              "is_root_device": false,
              "is_read_only": true,
              "cache_type": "Unsafe",
              "io_engine": "Sync"
            }''
        else "";
      # Compose checks into script, then append testScript if provided
      checksScript =
        if checks != []
        then checksLib.composeChecks {inherit groupName checks;}
        else "";
      composedScript =
        if checksScript != "" && testScript != null
        then checksScript + "\n" + testScript
        else if checksScript != ""
        then checksScript
        else if testScript != null
        then testScript
        else throw "mkVMTest '${name}': must provide either testScript or checks (or both)";

      effectiveMemory =
        if memory != null
        then memory
        else 2048;

      # Driver-specific build dependencies
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
        else throw "mkVMTest '${name}': unknown driver '${driver}' (expected 'firecracker' or 'qemu')";

      # -----------------------------------------------------------------------
      # Firecracker driver test script (system mode)
      # -----------------------------------------------------------------------
      # The VM boots through the production initrd path (stage-1 systemd
      # → ignition stages → switch-root → stage-2 systemd), matching the
      # real boot sequence. Firecracker's `boot_args` replaces the image's
      # built-in cmdline; no `ignition.platform.id=` or
      # `ignition.config.url=` kargs — `aos-platform-detect.service`
      # infers the platform from DMI (→ `qemu`) and mounts the ISO9660
      # metadata channel when the test harness attaches one.
      firecrackerScript = ''
        set -eu

        AGENT_SOCK="$TMPDIR/agent.sock"
        SERIAL_LOG="$TMPDIR/serial.log"
        FC_LOG="$TMPDIR/firecracker.log"
        VSOCK_UDS="$TMPDIR/vm.vsock"
        FC_CFG="$TMPDIR/fc-config.json"

        # Copy disk image to writable location (Firecracker needs rw for system tests)
        cp $DISK/disk.img disk.img
        chmod u+w disk.img

        # Copy the metadata ISO (when attached) to a writable location.
        # virtio-blk backends open the file at launch and hold it for the
        # run — a local copy isolates the run from any read-side caching
        # quirks with store files on certain filesystems.
        ${lib.optionalString hasMetadata ''
          cp $METADATA/metadata.iso metadata.iso
          chmod u+w metadata.iso
        ''}

        # Find the uncompressed kernel image (Firecracker requires vmlinux, not vmlinuz)
        VMLINUX=$(ls $KERNEL/boot/vmlinux-* | head -1)
        INITRD_IMG=$INITRD/initrd.img

        # Generate a unique CID from the builder PID (range 3-65535)
        GUEST_CID=$(( ($$ % 65533) + 3 ))

        echo "Driver: firecracker"
        echo "Kernel: $VMLINUX"
        echo "Initrd: $INITRD_IMG"
        echo "Disk:   disk.img ($(ls -lh disk.img | awk '{print $5}'))"
        echo "CID: $GUEST_CID"
        echo "Vsock UDS: $VSOCK_UDS"
        ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

        # Write Firecracker JSON config
        cat > "$FC_CFG" << FCCFGEOF
        {
          "boot-source": {
            "kernel_image_path": "$VMLINUX",
            "initrd_path": "$INITRD_IMG",
            "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 systemd.journald.forward_to_console=1 enforcing=0"
          },
          "drives": [
            {
              "drive_id": "rootfs",
              "path_on_host": "$(pwd)/disk.img",
              "is_root_device": false,
              "is_read_only": false,
              "cache_type": "Unsafe",
              "io_engine": "Sync"
            }${fcMetadataDrive}
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

        # Import shared test helpers (run_in_guest, assert_success, assert_output_contains).
        ${assertions.vmFirecrackerHelpers}

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

        # Copy disk image to writable location
        cp $DISK/disk.img disk.img
        chmod u+w disk.img

        # Copy the metadata ISO (when attached) to a writable location.
        ${lib.optionalString hasMetadata ''
          cp $METADATA/metadata.iso metadata.iso
          chmod u+w metadata.iso
        ''}

        # Find the kernel image
        VMLINUZ=$(ls $KERNEL/boot/vmlinuz-* | head -1)
        INITRD_IMG=$INITRD/initrd.img

        # Pre-flight checks
        QEMU_LOG="$TMPDIR/qemu.log"
        echo "Driver: qemu"
        echo "Kernel: $VMLINUZ"
        echo "Initrd: $INITRD_IMG"
        echo "Disk:   disk.img ($(ls -lh disk.img | awk '{print $5}'))"
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

        # Launch QEMU with direct kernel boot through the initrd. The
        # -append cmdline replaces the image's built-in cmdline; no
        # `ignition.platform.id=` or `ignition.config.url=` —
        # aos-platform-detect infers qemu from DMI and mounts the
        # metadata ISO when attached.
        # Metadata ISO (when attached) rides on a SCSI CD-ROM so the
        # guest sees it as /dev/sr0; blkid then picks up the ISO9660
        # volume label `aos-metadata` for the detector.
        qemu-system-x86_64 \
          -machine q35,accel=kvm \
          -cpu host \
          -m ${builtins.toString effectiveMemory} \
          -smp 2 \
          -nographic \
          -kernel "$VMLINUZ" \
          -initrd "$INITRD_IMG" \
          -append "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 systemd.journald.forward_to_console=1 enforcing=0" \
          -drive file=disk.img,format=raw,if=virtio \
          ${lib.optionalString hasMetadata ''
          -drive id=metadata,file=metadata.iso,if=none,format=raw,readonly=on \
          -device virtio-scsi-pci,id=scsi0 \
          -device scsi-cd,drive=metadata,bus=scsi0.0 \
        ''}
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

      testPhaseScript =
        if driver == "firecracker"
        then firecrackerScript
        else qemuScript;
    in
      pkgs.mkDerivation {
        pname = "aos-vm-test-${name}";
        version = "0";
        src = null;

        buildDeps = driverBuildDeps;

        DISK = builtins.toString systemDisk;
        KERNEL = builtins.toString systemKernel;
        INITRD = builtins.toString systemInitrd;
        METADATA = lib.optionalString hasMetadata (builtins.toString systemMetadataDisk);

        phases = [
          {
            name = "test";
            script = testPhaseScript;
          }
        ];

        requiredSystemFeatures = ["kvm"];
      }
    else throw "mkVMTest '${name}': must provide either 'system' (for full VM tests) or 'rootfsDeps' (for headless tests)";
in {
  inherit mkVMTest mkTestDisk;
}
