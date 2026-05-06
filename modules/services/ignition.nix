##! modules/services/ignition.nix — First-boot provisioning via Ignition
##!
##! Configures the Ignition first-boot provisioning tool. Ignition runs
##! inside the systemd-based initrd (`boot.initrd.systemd.services`)
##! before the real root is mounted at `/sysroot`. The platform is
##! auto-detected at initrd time by `aos-platform-detect.service`,
##! which writes `/run/ignition/platform.env`; every ignition stage
##! unit inherits that env file and invokes
##! `ignition --platform=${PLATFORM_ID}`.
##!
##! When the detector finds a `/dev/disk/by-label/aos-metadata` ISO9660
##! filesystem (test harness or operator IPMI virtual media), it mounts
##! it at `/run/aos-metadata`, writes `PLATFORM_ID=file` +
##! `IGNITION_CONFIG_FILE=/run/aos-metadata/config.json` — ignition's
##! `file` provider reads the env var directly, so no HTTP plumbing.
##!
##! A marker file at `/sysroot/var/etc/.ignition-result.json` (compiled
##! in as `resultFilePath`) guards against re-execution; ignition runs
##! idempotently on subsequent boots.
##!
##! Paired with:
##!   - `mount-var.service`         — mounts /var partition (created by
##!                                    Ignition) before ignition-files
##!   - `etc-overlay-setup.service` — /etc overlay with /var/etc + /etc.lower
##!   - `nix-overlay-setup.service` — /nix overlay with persistent upper
##!                                    on /var (writable Nix store layer)
{
  pkgs,
  lib,
  ...
}: let
  # Ignition shells out to external tools at each stage: `modprobe`,
  # `mount`/`umount`, `sgdisk`/`blkid`/`wipefs`, `mkfs.ext4`, etc.
  # It looks them up via $PATH. sbin lookups are covered by the
  # `lib.makeSearchPath "sbin"` side. Upstream reference for which
  # commands each stage invokes: internal/distro/distro.go.
  ignitionTools = [
    pkgs.kmod
    pkgs.util-linux
    pkgs.e2fsprogs
    pkgs.dosfstools
    pkgs.gptfdisk
    pkgs.cryptsetup
    pkgs.systemd
    pkgs.coreutils
    pkgs.bash
  ];
  ignitionPath = lib.concatStringsSep ":" [
    (lib.makeBinPath ignitionTools)
    (lib.makeSearchPath "sbin" ignitionTools)
  ];

  # Shared config for every ignition stage unit: inherit the platform
  # env from aos-platform-detect, wire PATH for the shell-outs, and
  # run a oneshot that stays active across subsequent stages.
  stageServiceConfig = stage: {
    Type = "oneshot";
    RemainAfterExit = true;
    EnvironmentFile = "/run/ignition/platform.env";
    ExecStart = "${pkgs.ignition}/bin/ignition --platform=\${PLATFORM_ID} --root=/sysroot --stage=${stage} --log-to-stdout";
    StandardOutput = "journal+console";
    StandardError = "journal+console";
  };
in {
  config = {
    # Ignition ships the binary in every stage-2 installation too so
    # operators can re-run or inspect state after first boot.
    environment.systemPackages = [pkgs.ignition];

    # Initrd services. The cpio assembler in modules/base/initrd-builder.nix
    # picks these up via `system.build.systemdInitrdUnits`.
    #
    # Ignition runs as a sequence of stages (fetch → disks → mount →
    # files → umount). Upstream's dracut module splits each stage
    # into its own unit so they can be ordered around `sysroot.mount`
    # — disks happens before, mount/files after. Mirror that here.
    # See ignition/dracut/30ignition/*.service in the ignition repo.
    boot.initrd.systemd.services = {
      "aos-platform-detect" = {
        description = "AOS platform auto-detect (ignition)";
        wantedBy = ["initrd-root-fs.target"];
        before = ["ignition-fetch.service"];
        requires = ["systemd-udev-settle.service"];
        after = ["systemd-udev-settle.service"];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.aos-platform-detect}/bin/aos-platform-detect";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      "aos-growfs" = {
        description = "Grow root-a ext4 filesystem to fill its partition";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "sysroot.mount"
          "initrd-root-fs.target"
        ];
        requires = ["ignition-disks.service"];
        after = ["ignition-disks.service"];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathExists = "/dev/disk/by-partlabel/root-a";
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.aos-growfs}/bin/aos-growfs";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };

      "ignition-fetch" = {
        description = "Ignition (fetch)";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "ignition-disks.service"
          "initrd-root-fs.target"
          "sysroot.mount"
        ];
        requires = [
          "systemd-modules-load.service"
          "systemd-udevd.service"
          "aos-platform-detect.service"
        ];
        after = [
          "systemd-modules-load.service"
          "systemd-udevd.service"
          "aos-platform-detect.service"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = stageServiceConfig "fetch";
      };

      "ignition-disks" = {
        description = "Ignition (disks)";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "initrd-root-device.target"
          "initrd-root-fs.target"
          "sysroot.mount"
        ];
        requires = [
          "systemd-udevd.service"
          "aos-platform-detect.service"
        ];
        after = [
          "ignition-fetch.service"
          "systemd-udevd.service"
          "aos-platform-detect.service"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = stageServiceConfig "disks";
      };

      "ignition-mount" = {
        description = "Ignition (mount)";
        wantedBy = ["initrd-fs.target"];
        before = [
          "ignition-files.service"
          "initrd-switch-root.target"
          "initrd-fs.target"
        ];
        requires = [
          "initrd-root-fs.target"
          "aos-platform-detect.service"
        ];
        after = [
          "ignition-disks.service"
          "sysroot.mount"
          "initrd-root-fs.target"
          "aos-platform-detect.service"
        ];
        environment.PATH = ignitionPath;
        serviceConfig =
          stageServiceConfig "mount"
          // {
            # Run umount on service stop (i.e. during initrd-cleanup)
            # so filesystems ignition mounted are torn down cleanly
            # before switch_root. Matches upstream ignition-mount.service.
            ExecStop = "${pkgs.ignition}/bin/ignition --platform=\${PLATFORM_ID} --root=/sysroot --stage=umount --log-to-stdout";
          };
      };

      "ignition-files" = {
        description = "Ignition (files)";
        wantedBy = ["initrd-fs.target"];
        before = [
          "initrd-parse-etc.service"
          "initrd-switch-root.target"
          "initrd-fs.target"
        ];
        requires = [
          "aos-platform-detect.service"
          "mount-var.service"
        ];
        after = [
          "ignition-mount.service"
          "aos-platform-detect.service"
          "mount-var.service"
        ];
        environment.PATH = ignitionPath;
        serviceConfig =
          stageServiceConfig "files"
          // {
            # Ignition writes systemd unit files at /etc/systemd/system/<name>
            # and its preset at /etc/systemd/system-preset/20-ignition.preset
            # — both paths are hardcoded in upstream
            # (internal/exec/util/path.go and unit.go). /sysroot is mounted
            # ro at this point, so direct writes would fail with EROFS.
            #
            # BindPaths runs in this service's private mount namespace:
            # the bind appears only here, the underlying writes go to the
            # rw /var partition, and the original /sysroot/etc content is
            # left untouched on disk. Stage 2 surfaces the writes through
            # the /etc overlay's `lowerdir=/var/etc:/etc.lower` layering
            # set up by etc-overlay-setup.service.
            BindPaths = "/sysroot/var/etc:/sysroot/etc";
          };
      };

      # Apply ignition's systemd presets to /sysroot. Runs after
      # ignition-files writes the preset file (via the same BindPaths
      # redirect into /var/etc/systemd/system-preset/20-ignition.preset)
      # and before etc-overlay-setup mounts the /etc overlay. Inside
      # this service's private mount namespace, /sysroot/etc is bound
      # to /sysroot/var/etc so the symlinks the script lays down end
      # up on the rw /var partition; stage 2 sees them through the
      # /var/etc lower layer of the eventual /etc overlay.
      #
      # We don't use `systemctl preset-all`: AOS systemd is built with
      # `--sysconfdir=$out/etc` (pkgs/system/systemd.nix:238), so its
      # compiled-in SYSTEM_CONFIG_UNIT_DIR points inside the read-only
      # systemd package, and `systemctl enable` writes symlinks there
      # rather than under /etc/systemd/system — fails on every unit.
      # The inline script below applies our preset file directly,
      # walking each enabled unit's `[Install]` section to lay down
      # the four directive types (Alias / WantedBy / RequiredBy /
      # UpheldBy) the renderer in lib/modules/systemd/lib.nix emits.
      "aos-ignition-preset" = {
        description = "Apply ignition's systemd presets to /sysroot";
        wantedBy = ["initrd-fs.target"];
        before = [
          "etc-overlay-setup.service"
          "initrd-fs.target"
        ];
        requires = [
          "ignition-files.service"
          "sysroot.mount"
          "mount-var.service"
        ];
        after = [
          "ignition-files.service"
          "sysroot.mount"
          "mount-var.service"
        ];
        unitConfig = {
          DefaultDependencies = "no";
          # The preset file lives at /var/etc/systemd/system-preset/
          # on disk; in this service's private namespace it surfaces
          # at /sysroot/etc/systemd/system-preset/ via the BindPaths
          # below. ConditionPathExists is evaluated by PID 1 BEFORE
          # the namespace is set up, so check the on-disk path
          # directly to gate the unit on whether ignition wrote a
          # preset file at all.
          ConditionPathExists = "/sysroot/var/etc/systemd/system-preset/20-ignition.preset";
        };
        # awk / ln / mkdir / coreutils for the inline script below.
        # `gawk` isn't in `ignitionPath` (the existing ignition stages
        # don't need it); prepend it here.
        environment.PATH = "${pkgs.gawk}/bin:${ignitionPath}";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          BindPaths = "/sysroot/var/etc:/sysroot/etc";
        };
        script = builtins.readFile ./aos-ignition-preset.bash;
      };

      # Mount the /var partition created by ignition-disks so that
      # ignition-files can write to /sysroot/var/etc/* and the mount
      # persists through switch-root into stage-2 (no ExecStop).
      # Stage-2 systemd sees the existing mount and considers its
      # fstab-generated var.mount unit already active.
      "mount-var" = {
        description = "Mount /var Partition";
        wantedBy = ["initrd-fs.target"];
        before = [
          "ignition-files.service"
          "etc-overlay-setup.service"
          "initrd-fs.target"
        ];
        requires = [
          "sysroot.mount"
          "ignition-disks.service"
        ];
        after = [
          "sysroot.mount"
          "ignition-disks.service"
          "systemd-udev-settle.service"
        ];
        unitConfig = {
          ConditionPathExists = "/dev/disk/by-partlabel/var";
        };
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          if ! mountpoint -q /sysroot/var; then
            mkdir -p /sysroot/var
            mount -o nosuid,nodev /dev/disk/by-partlabel/var /sysroot/var
          fi
          # Standard /var subdirectories expected by systemd and daemons.
          mkdir -p /sysroot/var/{log,lib,tmp}
          # /var/etc is the persistent lower layer of the production
          # /etc overlay (set up later by etc-overlay-setup). Create it
          # eagerly so ignition-files / aos-ignition-preset can use it
          # as a BindPaths source — those services bind /sysroot/var/etc
          # over /sysroot/etc inside their private mount namespaces so
          # ignition's hardcoded /etc/systemd/* writes land on the rw
          # /var partition instead of failing on ro /sysroot.
          mkdir -p /sysroot/var/etc
          # /var/run → /run is the modern-Linux convention; many daemons
          # (dbus, various PID files) still reference /var/run paths.
          ln -sfn /run /sysroot/var/run
        '';
      };

      # /etc overlay: moves the image's /etc → /etc.lower on first boot,
      # then mounts an overlayfs at /etc with two lower layers:
      #   1. /var/etc   — persistent state written by ignition (shadows)
      #   2. /etc.lower — immutable image /etc
      # The upper layer is a tmpfs under /run so runtime writes to /etc
      # are not persisted across reboots.
      "etc-overlay-setup" = {
        description = "Set Up /etc Overlay Filesystem";
        wantedBy = ["initrd-fs.target"];
        before = [
          "initrd-fs.target"
          "initrd-switch-root.target"
        ];
        requires = [
          "sysroot.mount"
          "mount-var.service"
          "ignition-files.service"
        ];
        after = [
          "sysroot.mount"
          "mount-var.service"
          "ignition-files.service"
          "initrd-root-fs.target"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          sysroot=/sysroot

          # 1. First-boot setup: move /etc aside and create the
          #    /run/etc-upper mountpoint. Root is read-only so we
          #    remount rw briefly for these on-disk changes.
          needs_rw=false
          if [ ! -d "$sysroot/etc.lower" ]; then needs_rw=true; fi
          if [ ! -d "$sysroot/run/etc-upper" ]; then needs_rw=true; fi

          if [ "$needs_rw" = true ]; then
            mount -o remount,rw "$sysroot"
            if [ ! -d "$sysroot/etc.lower" ]; then
              mv "$sysroot/etc" "$sysroot/etc.lower"
              mkdir -p "$sysroot/etc"
            fi
            mkdir -p "$sysroot/run/etc-upper"
            mount -o remount,ro "$sysroot"
          fi

          # 2. Tmpfs for the overlay upper/work dirs. The mountpoint
          #    on the root ext4 means this appears as a sibling of /run
          #    in findmnt rather than nested — cosmetic only, the overlay
          #    functions correctly either way.
          if ! mountpoint -q "$sysroot/run/etc-upper"; then
            mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs "$sysroot/run/etc-upper"
          fi
          mkdir -p "$sysroot/run/etc-upper/upper"
          mkdir -p "$sysroot/run/etc-upper/work"

          # 3. Ensure /var/etc exists on the persistent /var partition.
          mkdir -p "$sysroot/var/etc/ssh/authorized_keys"

          # 4. Mount the overlay. /var/etc is listed first so its files
          #    shadow /etc.lower; the tmpfs upper captures runtime writes.
          ${pkgs.util-linux}/bin/mount -t overlay overlay \
            -o nosuid,nodev,lowerdir="$sysroot/var/etc:$sysroot/etc.lower",upperdir="$sysroot/run/etc-upper/upper",workdir="$sysroot/run/etc-upper/work" \
            "$sysroot/etc"
        '';
      };

      # /nix overlay: stack a writable upper on /var over the image's
      # immutable /nix.lower so the Nix package manager can install new
      # store paths at runtime. The image builder ships /nix.lower
      # populated and /nix as an empty mountpoint (lib/build/rootfs.nix),
      # so this unit is unconditional — no first-boot rename, no
      # remount,rw window, identical on fresh installs and post-upgrade
      # boots.
      #
      # Garbage collection only ever evicts upper-layer paths: the lower
      # is read-only by physics, not by gcroots, so image-shipped store
      # paths are protected as a property of the layout.
      "nix-overlay-setup" = {
        description = "Set Up /nix Overlay Filesystem";
        wantedBy = ["initrd-fs.target"];
        before = [
          "initrd-fs.target"
          "initrd-switch-root.target"
        ];
        requires = [
          "sysroot.mount"
          "mount-var.service"
        ];
        after = [
          "sysroot.mount"
          "mount-var.service"
          "initrd-root-fs.target"
        ];
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          sysroot=/sysroot

          # Upper and work must share a filesystem (overlayfs requires
          # workdir to be on the same fs as upperdir for atomic
          # rename-into-upper). Both live on the /var partition.
          mkdir -p "$sysroot/var/lib/nix-overlay/upper"
          mkdir -p "$sysroot/var/lib/nix-overlay/work"

          if ! mountpoint -q "$sysroot/nix"; then
            ${pkgs.util-linux}/bin/mount -t overlay overlay \
              -o nosuid,nodev,lowerdir="$sysroot/nix.lower",upperdir="$sysroot/var/lib/nix-overlay/upper",workdir="$sysroot/var/lib/nix-overlay/work" \
              "$sysroot/nix"
          fi
        '';
      };
    };
  };
}
