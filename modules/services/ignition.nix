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
    # jq is needed by aos-seed-profiles.service to assemble apm's
    # initial state.json. Spec v12 §6.1.1.
    pkgs.jq
  ];
  ignitionPath = lib.concatStringsSep ":" [
    (lib.makeBinPath ignitionTools)
    (lib.makeSearchPath "sbin" ignitionTools)
  ];

  # Shared config for every ignition stage unit: inherit the platform
  # env from aos-platform-detect, wire PATH for the shell-outs, and
  # run a oneshot that stays active across subsequent stages. `root`
  # defaults to `/sysroot` (which is what the fetch / disks / mount
  # stages want); the files stage overrides it to the per-gen
  # /sysroot/run/etc/ignition-<gen> path (spec v12 §6.1.3).
  stageServiceConfig = {
    stage,
    root ? "/sysroot",
  }: {
    Type = "oneshot";
    RemainAfterExit = true;
    EnvironmentFile = "/run/ignition/platform.env";
    ExecStart = "${pkgs.ignition}/bin/ignition --platform=\${PLATFORM_ID} --root=${root} --stage=${stage} --log-to-stdout";
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
        serviceConfig = stageServiceConfig {stage = "fetch";};
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
        serviceConfig = stageServiceConfig {stage = "disks";};
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
          stageServiceConfig {stage = "mount";}
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
          "etc-overlay-setup.service"
          "initrd-switch-root.target"
          "initrd-fs.target"
        ];
        requires = [
          "aos-platform-detect.service"
          "mount-var.service"
          "aos-seed-profiles.service"
          "run-etc-setup.service"
        ];
        after = [
          "ignition-mount.service"
          "aos-platform-detect.service"
          "mount-var.service"
          "aos-seed-profiles.service"
          "run-etc-setup.service"
        ];
        environment.PATH = ignitionPath;
        # Spec v12 §6.1.3 — write into the per-gen lower under
        # /sysroot/run/etc/ignition-<gen>/ instead of bind-mounting
        # /var/etc over /sysroot/etc. Ignition's `--root=$ign`
        # prepends $ign to absolute paths, so a
        # `storage.links.path = "/etc/foo"` write lands at
        # `$ign/etc/foo`. The per-gen subtree is created by the
        # ExecStartPre below; etc-overlay-setup mounts it as the
        # role lowerdir in the three-layer /etc overlay.
        serviceConfig =
          stageServiceConfig {
            stage = "files";
            root = "/sysroot/run/etc/ignition-\${AOS_PROFILE_GEN}";
          }
          // {
            EnvironmentFile = [
              "/run/ignition/platform.env"
              "/run/aos-profile-gen.env"
            ];
            ExecStartPre =
              "${pkgs.coreutils}/bin/mkdir -p "
              + "/sysroot/run/etc/ignition-\${AOS_PROFILE_GEN}/etc";
          };
      };

      # aos-ignition-preset.service was removed in spec v12 §6.1.6 —
      # the [Install] symlinks now ride in the system EROFS image
      # (via environment.etc."systemd/system" and the composefs dump
      # script's directory recursion at spec v12 §5.2) and in the
      # per-gen ignition lower (via render-role.nix's predicted
      # storage.links, spec v12 §5.6). The runtime preset-walker is
      # redundant.

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
          # /var/etc is the host-persistent allowlist of the /etc
          # overlay (spec v12 §5.4) — created eagerly so
          # aos-machine-id and sshd-keygen find it on first boot.
          mkdir -p /sysroot/var/etc
          # /var/run → /run is the modern-Linux convention; many daemons
          # (dbus, various PID files) still reference /var/run paths.
          ln -sfn /run /sysroot/var/run
        '';
      };

      # /etc overlay (spec v12 §6.1.4) — three-layer composition:
      #
      #   lowerdir+=/var/etc                      — host-persistent allowlist
      #                                             (machine-id, ssh host keys)
      #   lowerdir+=/run/etc/ignition-<gen>/etc   — per-gen role lower
      #                                             (ignition's storage.links
      #                                             from render-role.nix)
      #   lowerdir+=/run/etc/system-<gen>/metadata — system EROFS (composefs)
      #   datadir+= /run/etc/system-<gen>/content  — basedir for octal-mode
      #                                              entries (metacopy)
      #   upperdir = /run/etc/upper-<gen>/upper    — tmpfs, runtime writes
      #
      # The active toplevel is read at runtime by
      # `readlink /sysroot/var/lib/profiles/system/current/toplevel`;
      # baking `${config.system.build.toplevel}` here would create an
      # initrd→toplevel→initrd cycle (the toplevel ships the initrd).
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
          "aos-seed-profiles.service"
          "run-etc-setup.service"
          "nix-overlay-setup.service"
          "aos-machine-id.service"
        ];
        after = [
          "sysroot.mount"
          "mount-var.service"
          "ignition-files.service"
          "aos-seed-profiles.service"
          "run-etc-setup.service"
          "nix-overlay-setup.service"
          "aos-machine-id.service"
          "initrd-root-fs.target"
        ];
        unitConfig.DefaultDependencies = "no";
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          . /run/aos-profile-gen.env

          # Resolve the active toplevel at runtime; do NOT bake
          # ${"\${config.system.build.toplevel}"} into this script
          # (initrd→toplevel→initrd cycle). nix-overlay-setup mounts
          # /sysroot/nix as the merged overlay, so /sysroot$toplevel
          # resolves through that.
          toplevel=$(readlink /sysroot/var/lib/profiles/system/current/toplevel)
          gen=$AOS_PROFILE_GEN
          sys=/sysroot/run/etc/system-$gen
          ign=/sysroot/run/etc/ignition-$gen
          upper_root=/sysroot/run/etc/upper-$gen

          mkdir -p "$sys/metadata" "$sys/content" \
                   "$upper_root/upper" "$upper_root/work"
          # $ign/etc already exists from ignition-files.service's
          # ExecStartPre.

          # $toplevel is a /nix/store/... path; prefix /sysroot
          # because the real root is still under /sysroot in the
          # initrd. /sysroot/nix is the merged overlay (set up by
          # nix-overlay-setup.service, which we ordered After).
          #
          # `etc-basedir` and `etc-metadata.erofs` are symlinks inside
          # the toplevel that point at other /nix/store/... paths.
          # `mount --bind` follows those symlinks, but the resolved
          # /nix/store/... target isn't reachable from PID 1's
          # process root in the initrd — only /sysroot/nix/store/
          # is. Read the symlinks ourselves and prefix /sysroot so
          # the bind sources resolve in the initrd's view.
          basedir=$(readlink "/sysroot$toplevel/etc-basedir")
          metadata=$(readlink "/sysroot$toplevel/etc-metadata.erofs")
          ${pkgs.util-linux}/bin/mount --bind \
            "/sysroot$basedir" "$sys/content"
          ${pkgs.util-linux}/bin/mount -t erofs -o ro,nodev,nosuid \
            "/sysroot$metadata" "$sys/metadata"

          ${pkgs.util-linux}/bin/mount -t overlay overlay -o \
            nodev,nosuid,metacopy=on,redirect_dir=on,lowerdir+=/sysroot/var/etc,lowerdir+=$ign/etc,lowerdir+=$sys/metadata,datadir+=$sys/content,upperdir=$upper_root/upper,workdir=$upper_root/work \
            /sysroot/etc

          # Inspection symlinks (relative targets so they survive
          # switch_root from /sysroot/run/etc/... to /run/etc/...).
          ln -sfn system-$gen   /sysroot/run/etc/system
          ln -sfn ignition-$gen /sysroot/run/etc/ignition
          ln -sfn upper-$gen    /sysroot/run/etc/upper
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

      # Seed apm system-profile state on first boot. Reads the
      # toplevel path from `/sysroot/aos-toplevel` (the seed pointer
      # the rootfs ships at lib/build/rootfs.nix) rather than
      # interpolating `${config.system.build.toplevel}` directly —
      # the initrd builder's closure scan
      # (modules/base/_initrd-builder.nix) would otherwise drag the
      # toplevel into the initrd's closure and create a cycle
      # (toplevel ships the initrd). Spec v12 §6.1.1, §6.1.
      "aos-seed-profiles" = {
        description = "Seed apm system-profile state on first boot";
        wantedBy = ["initrd-fs.target"];
        before = [
          "ignition-files.service"
          "run-etc-setup.service"
          "aos-machine-id.service"
          "initrd-fs.target"
        ];
        requires = [
          "sysroot.mount"
          "mount-var.service"
          "nix-overlay-setup.service"
        ];
        after = [
          "sysroot.mount"
          "mount-var.service"
          "nix-overlay-setup.service"
        ];
        unitConfig.DefaultDependencies = "no";
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          profile_dir=/sysroot/var/lib/profiles/system

          # The seed pointer is a symlink the rootfs builder writes at
          # /aos-toplevel -> /nix/store/<hash>-toplevel. readlink
          # returns the literal target (a /nix/store/... path); we
          # access toplevel-resident files by prefixing /sysroot
          # because the real root is still under /sysroot in the
          # initrd. /sysroot/nix is the merged overlay (set up by
          # nix-overlay-setup.service, which we ordered After).
          toplevel=$(readlink /sysroot/aos-toplevel)

          read_meta() {
            tr -d '\n' < "/sysroot$toplevel/meta/$1" 2>/dev/null \
              || printf 'unknown'
          }

          if [ ! -e "$profile_dir/state.json" ]; then
            mkdir -p "$profile_dir/gen-1"
            ln -sfn "$toplevel" "$profile_dir/gen-1/toplevel"
            ln -sfn gen-1 "$profile_dir/current"
            # `registry: "seed"` is a sentinel for the gen baked into
            # the image (no apm install). The apm follow-up may
            # special-case it or migrate the schema to Option<String>;
            # until then the sentinel keeps the file parseable by
            # today's apm (which types `registry` as String,
            # non-optional, at crates/aos-package/src/types.rs:622).
            ${pkgs.jq}/bin/jq -n \
              --arg pn  "$(read_meta package-name)" \
              --arg ver "$(read_meta version)" \
              --arg top "$toplevel" \
              --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
              '{
                 current: 1,
                 next: 2,
                 generations: [{
                   number: 1,
                   toplevel: $top,
                   package_name: $pn,
                   version: $ver,
                   registry: "seed",
                   created_at: $now,
                   kernel_path: ($top + "/kernel")
                 }]
               }' > "$profile_dir/state.json"
          fi

          link=$(readlink "$profile_dir/current")
          GEN=''${link#gen-}
          printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
        '';
      };

      # Mount a tmpfs on /sysroot/run/etc once, before anything else
      # writes under it. ignition-files writes its per-gen
      # /sysroot/run/etc/ignition-<gen>/ subtree here, and
      # etc-overlay-setup later creates the system/upper mountpoints
      # alongside. Spec v12 §6.1.2.
      "run-etc-setup" = {
        description = "Mount /sysroot/run/etc tmpfs";
        wantedBy = ["initrd-fs.target"];
        before = [
          "ignition-files.service"
          "etc-overlay-setup.service"
          "initrd-fs.target"
        ];
        requires = ["sysroot.mount"];
        after = ["sysroot.mount"];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathIsMountPoint = "!/sysroot/run/etc";
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart =
            "${pkgs.util-linux}/bin/mount -t tmpfs -o nosuid,nodev,mode=755 "
            + "tmpfs /sysroot/run/etc";
        };
      };

      # Seed /var/etc/machine-id on first boot, before
      # etc-overlay-setup mounts the overlay (so stage-2
      # systemd-machine-id-setup.service sees the file via the
      # /var/etc lower and skips regeneration). Replaces the
      # legacy rootfs-builder `touch /etc/machine-id` write. Stage-1
      # placement avoids the race where stage-2's
      # systemd-machine-id-setup writes to the tmpfs upperdir,
      # regenerating the ID every reboot. Spec v12 §6.1.5.
      "aos-machine-id" = {
        description = "Seed /var/etc/machine-id on first boot";
        wantedBy = ["initrd-fs.target"];
        before = [
          "etc-overlay-setup.service"
          "initrd-fs.target"
        ];
        requires = [
          "sysroot.mount"
          "mount-var.service"
        ];
        after = [
          "sysroot.mount"
          "mount-var.service"
        ];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathExists = "!/sysroot/var/etc/machine-id";
        };
        environment.PATH = ignitionPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          mkdir -p /sysroot/var/etc
          # /proc/sys/kernel/random/uuid emits
          # "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n". systemd's
          # machine-id format is 32 lowercase hex chars (no dashes)
          # followed by a newline; tr removes the dashes, the
          # trailing newline from /proc survives.
          tr -d '-' < /proc/sys/kernel/random/uuid \
            > /sysroot/var/etc/machine-id
          chmod 0444 /sysroot/var/etc/machine-id
        '';
      };
    };
  };
}
