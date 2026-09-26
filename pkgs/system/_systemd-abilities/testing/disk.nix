##! Package-owned mutable test-disk constructor for the selected systemd image platform.
##!
##! The generic VM harness supplies a resolved system and transport-neutral test
##! inputs. This package-owned builder defines the filesystem layout, persistent
##! state seed, service-manager units, and partition scheme needed to boot that
##! system through the systemd platform.
{
  closureInfoFor,
  lib,
  packages,
}: let
  pkgs = packages;

  buildRootfs = import ../platform/_rootfs-builder.nix;
  buildSystemdTestRootfs = arguments:
    buildRootfs (arguments // {inherit closureInfoFor lib pkgs;});

  # ---------------------------------------------------------------------------
  # Build a rootfs ext4 image for VM testing
  # ---------------------------------------------------------------------------
  # Uses exportReferencesGraph to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  # ---------------------------------------------------------------------------
  # Build a GPT disk image for VM testing
  # ---------------------------------------------------------------------------
  # Produces a single $out/disk.img with the partitions needed to match the
  # production layout closely enough for the production initrd and early-boot
  # provisioning services to run unchanged against it:
  #
  #   1  boot  — 4 MiB, unformatted. Vestigial — kernel + initrd come in
  #              via `-kernel`/`-initrd`, partition 1 is never mounted.
  #              Reserving 4 MiB keeps root at /dev/vda2 matching
  #              production device naming.
  #   2  root  — ext4, sized to fit. /etc is an empty mountpoint; the
  #              system /etc content lives in the composefs EROFS image
  #              shipped at ${toplevel}/etc-metadata.erofs, mounted by
  #              etc-overlay-setup.service in stage-1.
  #   3  root-b — an empty slot with the same capacity as root-a. Tests
  #              initially boot only slot A, but stage-2 identity validation
  #              requires the complete A/B device contract.
  #   4  swap  — 8 MiB stub with the Linux-swap GPT GUID, no body.
  #              cryptswap.service's `Requires=` on the auto-instantiated
  #              `dev-disk-by-partlabel-swap.device` would otherwise sit
  #              queued for 90 s on every boot waiting for udev to
  #              announce a partition that doesn't exist.
  #   5  provenance — 1 MiB reserved AOS marker on baked-var disks. It
  #              identifies this out-of-band layout as already committed.
  #   6  var   — 256 MiB ext4. Carries the /var/etc allowlist plus
  #              test-specific overrides (host SSH key, SELinux off,
  #              test units) and package state used by fleet tests.
  #              Label `var` via GPT partlabel so mount-var.service
  #              finds it.
  #
  # Spec v12 §5.4 names /var/etc as the tight host-persistent
  # allowlist (machine-id, ssh host keys). For test infrastructure we
  # widen that scope: the test units (aos-test.target,
  # aos-test-agent.service) and the per-test fallbacks (nsswitch.conf,
  # etc.) also live there. This is a deliberate test-only deviation;
  # production package policy must use the `environment.etc` route
  # through the EROFS image.
  #
  # `mkTestDisk` is a function of `{system, extraClosures, varSizeMiB}`:
  # two callers passing identical inputs reference the same Nix derivation,
  # which lets fleet tests share disks where their machine images match.
  mkTestDisk = {
    system,
    name ? "aos-disk",
    # Extra derivations whose full closures land in /nix/store on the
    # rootfs, over and above `system`'s own closure. Upgrade tests pass
    # a second system toplevel here so `apm upgrade --system` finds its
    # store paths already present locally (no network fetch) — see
    # the selected test root builder's `extraClosures` and tests/fleet/
    # apm-system-upgrade.nix.
    extraClosures ? [],
    # Size of the /var partition (partition 6 on baked disks) in MiB. Raise for tests
    # whose guests stage large payloads under /var (e.g. a fleet registry
    # peer writing a static binary cache of a full system closure).
    # Only consulted when `varProvisioning == "baked"`; under "repart"
    # the image carries no /var partition and the size is applied at boot.
    varSizeMiB ? 256,
    # Most VM tests run without an SELinux policy and need the test
    # /var/etc lower to keep SELinux disabled. SELinux-specific tests
    # opt out so the system-generated /etc/selinux/config is visible.
    seedSELinuxDisabledConfig ? true,
    # How /var is provisioned. "baked" (default): /var is partition 6 of
    # this image, formatted and seeded at build time. "repart": the
    # image is boot+root-a+root-b+swap only — systemd-repart creates and formats /var
    # on first boot, so machines differing
    # only in /var size share one base image. The build-time `varSeed` is
    # skipped under "repart"; the guest agent arrives via the
    # `aos-test-agent` package instead.
    varProvisioning ? "baked",
  }: let
    systemPackages = system.config.environment.systemPackages;
    bakeVar = varProvisioning == "baked";

    # rootfsPost — shell fragment spliced into the shared rootfs
    # helper's populate phase after tree population, before mkfs.
    # Only touches rootfs/ paths (the system /etc tree no longer
    # lives on the rootfs; see varSeed below).
    postPopulate = ''
      # ── systemd's /lib/* subdirs into merged-usr /usr/lib ──
      # Provides udev rules, tmpfiles.d, sysctl.d, and systemd's own
      # library-adjacent helpers that tools look up at /lib/... paths.
      # Don't stomp on /usr/lib/modules which the helper already wired.
      for d in "${pkgs.systemd}/lib/"*; do
        n=$(basename "$d")
        [ -e "rootfs/usr/lib/$n" ] || ln -sfn "$d" "rootfs/usr/lib/$n"
      done

      # /opt/aos-test/bin holds the test agent scripts.
      mkdir -p rootfs/opt/aos-test/bin

      # Mount points for declared ZFS datasets. systemd creates a missing
      # Where= directory itself but cannot do so on the read-only root, so a
      # dataset mounting directly onto the image needs its directory here.
      ${lib.concatMapStringsSep "\n" (mountPoint: ''
          mkdir -p ${lib.escapeShellArg "rootfs${mountPoint}"}
        '') (
          builtins.filter (point: point != null && point != "/")
          (map (dataset: dataset.mountPoint)
            (builtins.attrValues system.config.aos.filesystems.zfs.datasets))
        )}

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

      mirror_and_capture() {
        pipe="$1"
        output="$2"
        if [ -c /dev/console ]; then
          tee "$output" < "$pipe" > /dev/console
        else
          cat < "$pipe" > "$output"
        fi
      }

      rm -f /tmp/agent-stdout /tmp/agent-stderr \
        /tmp/agent-stdout.pipe /tmp/agent-stderr.pipe
      mkfifo /tmp/agent-stdout.pipe /tmp/agent-stderr.pipe
      mirror_and_capture /tmp/agent-stdout.pipe /tmp/agent-stdout &
      stdout_mirror=$!
      mirror_and_capture /tmp/agent-stderr.pipe /tmp/agent-stderr &
      stderr_mirror=$!

      bash /tmp/agent-cmd >/tmp/agent-stdout.pipe 2>/tmp/agent-stderr.pipe
      exit_code=$?
      wait "$stdout_mirror" 2>/dev/null || true
      wait "$stderr_mirror" 2>/dev/null || true
      rm -f /tmp/agent-stdout.pipe /tmp/agent-stderr.pipe

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
      # The test-agent package owns the protocol client used by both mutable
      # test disks and image-boot fleet machines.
      cp ${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent \
        rootfs/opt/aos-test/bin/aos-test-agent
      chmod +x rootfs/opt/aos-test/bin/aos-test-agent
    '';

    # varSeed — shell fragment spliced into the disk-assembly phase
    # below. Populates `var/etc/...` and `var/etc/systemd/system/...`
    # before `mkfs.ext4 -d var var.img`, so the resulting var
    # partition surfaces these files at `/etc/<path>` via the runtime
    # overlay (spec v12 §5.4: /var/etc is the persistent lower).
    #
    # The test-only entries (selinux off, baked hostname, fstab,
    # pre-generated SSH host key, passwd/group fallbacks,
    # nsswitch.conf, aos-test units) all live on the var partition
    # rather than going through `environment.etc` — they're test
    # infrastructure, not production state.
    varSeed = ''
      mkdir -p var/etc/systemd/system/multi-user.target.wants
      mkdir -p var/etc/systemd/system/aos-test.target.wants
      mkdir -p var/etc/ssh
      ${lib.optionalString seedSELinuxDisabledConfig ''
        mkdir -p var/etc/selinux

        # SELinux off — most test rootfs images have no policy files;
        # enforcing mode would freeze systemd. The toplevel may write
        # /etc/selinux/config from refpolicy's native module; this
        # var entry shadows it via the /var/etc overlay lower.
        cat > var/etc/selinux/config << 'SELINUXCFG'
        SELINUX=disabled
        SELINUXTYPE=targeted
        SELINUXCFG
      ''}

      # Empty fstab — systemd-fstab-generator synthesises
      # sysroot.mount from `root=` on the cmdline; mount-var.service
      # handles /var.
      : > var/etc/fstab

      # Pre-generate SSH host key so sshd starts without waiting on
      # sshd-keygen.service (the production path writes the same
      # /var/etc/ssh/ssh_host_ed25519_key on first boot).
      ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" \
        -f var/etc/ssh/ssh_host_ed25519_key </dev/null

      # NOTE: we deliberately do NOT seed /var/etc/os-release here.
      # /var/etc is the highest-precedence persistent /etc-overlay lower,
      # so a var-seed os-release would
      # shadow the generation's EROFS os-release on every boot — masking
      # the real NAME/VERSION_ID and breaking upgrade tests that assert
      # the active generation's version. The toplevel's own os-release
      # (modules/base/system.nix, baked into the EROFS) surfaces instead.

      # Fallback nsswitch.conf — matches the toplevel default but
      # shadowing here means even a minimal test system gets sane
      # NSS resolution.
      cat > var/etc/nsswitch.conf << 'NSS'
      passwd: files
      group:  files
      shadow: files
      hosts:  files dns
      NSS

      # Test guest agent target + service. The unit refers to
      # /opt/aos-test/bin/aos-test-agent which lives on the rootfs
      # (postPopulate creates it). The aos-test.target is ordered
      # After=multi-user.target so by the time the agent fires,
      # systemctl is-active multi-user.target is provably true.
      cat > var/etc/systemd/system/aos-test.target << 'UNIT'
      [Unit]
      Description=AOS VM Test Harness Ready
      After=multi-user.target
      Wants=multi-user.target

      [Install]
      WantedBy=multi-user.target
      UNIT
      cat > var/etc/systemd/system/aos-test-agent.service << 'UNIT'
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
        var/etc/systemd/system/multi-user.target.wants/aos-test.target
      ln -sfn ../aos-test-agent.service \
        var/etc/systemd/system/aos-test.target.wants/aos-test-agent.service
    '';

    rootfs = buildSystemdTestRootfs {
      inherit system;
      kernel = system.config.aos.kernel.selected;
      managerConfiguration = system.config.system.build.managerConfiguration;
      managerRootfsPlan = system.config.aos.manager.selected.configuration.rootfs;
      pname = "vm-disk-${name}-rootfs";
      label = "aos-root";
      # Leave the image at its initial over-provisioned size — tests
      # can write a lot during execution. 2048 MiB floor matches the
      # pre-refactor behavior.
      shrinkToFit = false;
      minSizeMiB = 2048;
      # Out-of-tree modules the system under test declares. Without these the
      # guest's module tree holds only the in-tree set, and a subject built
      # around an external module -- ZFS, the NVIDIA driver -- boots with that
      # module simply absent, which reads as the feature being broken rather
      # than missing from the test image.
      kernelModulePackages = system.config.aos.kernel.modulePackages;
      # Over and above toplevel + kernel, retain the selected manager and test
      # agent payload. Caller-supplied `extraClosures` (e.g. a
      # second system toplevel for upgrade tests) are appended.
      extraClosures =
        [
          pkgs.systemd
          pkgs.coreutils
          pkgs.bash
          pkgs.aos-test-agent
        ]
        ++ extraClosures;
      # Symlink farm into /usr/bin, /usr/sbin, /usr/libexec. Ordering
      # is first-wins for collisions — coreutils before systemd so
      # coreutils' `env` / `ls` / etc. don't get shadowed.
      symlinkFarmPkgs =
        [
          pkgs.coreutils
          pkgs.systemd
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
            ${lib.optionalString bakeVar ''
              VAR_SIZE_MIB=${builtins.toString varSizeMiB}

              # ── /var partition staging ────────────────────────────────
              mkdir -p var

              # Spec v12 model: the test-only /etc overrides + test units
              # live on /var/etc (the persistent overlay lower), not on
              # the rootfs's /etc tree (which is now empty by design).
              ${varSeed}

              # fakeroot so the var partition's files land as uid/gid 0.
              fakeroot -- mkfs.ext4 -d var -L aos-var -m 0 -q var.img "''${VAR_SIZE_MIB}M"
            ''}
            # ── Root image from the shared rootfs helper ────────────────
            cp "$ROOT_IMG" root.img
            chmod u+w root.img
            root_bytes=$(cat "$ROOT_SIZE_FILE")

            # ── Assemble the GPT disk image ─────────────────────────────
            # Sizes in 512-byte sectors; 1 MiB alignment at start and end
            # for GPT headers. Partition 1 (boot) is vestigial in tests
            # — the harness passes kernel+initrd via -kernel/-initrd —
            # but reserving it keeps root at /dev/vda2 matching production.
            #
            # Under varProvisioning="repart" the image stops at
            # boot+root-a+root-b+swap: systemd-repart creates /var in the
            # first boot, so machines differing only in /var size share
            # this one base image. The driver grows the per-run copy to
            # make room before boot (see lib/testing/fleet.nix).
            BOOT_SECTORS=$(( 4 * 1024 * 1024 / 512 ))   # 4 MiB
            ROOT_SECTORS=$(( root_bytes / 512 ))
            SWAP_SECTORS=$(( 8 * 1024 * 1024 / 512 ))   # 8 MiB
            SENTINEL_SECTORS=$(( 1 * 1024 * 1024 / 512 ))

            BOOT_START=2048
            ROOT_START=$(( BOOT_START + BOOT_SECTORS ))
            ROOT_B_START=$(( ROOT_START + ROOT_SECTORS ))
            SWAP_START=$(( ROOT_B_START + ROOT_SECTORS ))
            ${
              if bakeVar
              then ''
                VAR_SECTORS=$(( VAR_SIZE_MIB * 1024 * 1024 / 512 ))
                SENTINEL_START=$(( SWAP_START + SWAP_SECTORS ))
                VAR_START=$(( SENTINEL_START + SENTINEL_SECTORS ))
                DISK_SECTORS=$(( VAR_START + VAR_SECTORS + 2048 ))
              ''
              else ''
                DISK_SECTORS=$(( SWAP_START + SWAP_SECTORS + 2048 ))
              ''
            }
            DISK_BYTES=$(( DISK_SECTORS * 512 ))

            echo "==> Assembling $(( DISK_BYTES / 1048576 )) MiB GPT disk image"
            truncate -s "$DISK_BYTES" disk.img

            # The x86-64 DPS root GUID isolates root-a from operator
            # linux-generic data. The reserved AOS GUID marks a baked /var
            # disk as provisioned out-of-band. The partlabel `var` is what
            # mount-var.service binds to via /dev/disk/by-partlabel/var.
            # The root partition is labelled `root-a` to match the
            # production A/B layout. The var line is omitted under "repart"
            # because it is created at first boot.
            {
              echo "label: gpt"
              echo "size=$BOOT_SECTORS, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=boot"
              echo "size=$ROOT_SECTORS, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, name=root-a"
              echo "size=$ROOT_SECTORS, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, name=root-b"
              echo "size=$SWAP_SECTORS, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, name=swap"
              ${lib.optionalString bakeVar ''echo "size=$SENTINEL_SECTORS, type=163BEA60-58C7-46E7-B69A-6846A5A688AF, name=aos-provenance-fallback-v1"''}
              ${lib.optionalString bakeVar ''echo "size=$VAR_SECTORS,  type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=var"''}
            } > ptable.sfdisk
            sfdisk disk.img < ptable.sfdisk

            # Partition starts are MiB-aligned. Copy at that granularity so
            # production-scale /var fixtures do not issue tens of millions of
            # 512-byte writes during every fleet image build.
            [ $((ROOT_START % 2048)) -eq 0 ]
            dd if=root.img of=disk.img bs=1M seek="$((ROOT_START / 2048))" conv=notrunc status=none
            ${lib.optionalString bakeVar ''
              [ $((VAR_START % 2048)) -eq 0 ]
              dd if=var.img of=disk.img bs=1M seek="$((VAR_START / 2048))" conv=notrunc status=none
            ''}

            mkdir -p $out
            mv disk.img $out/disk.img
          '';
        }
      ];
    };
in
  mkTestDisk
