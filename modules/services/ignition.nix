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
##! RFC-0011 cutover: the Ignition stage units (fetch/disks/mount/files,
##! platform-detect, network, gpt-relocate, growfs) are gated behind
##! `aos.provisioning.ignition.enable` (default true). The *neutral* boot
##! infrastructure — `mount-var`, the `/etc` + `/nix` overlays,
##! `aos-seed-profiles`, `run-etc-setup`, `aos-machine-id` — is always
##! emitted and orders against the active provisioning backend through the
##! `disksUnit`/`filesUnit` indirection below, so a system that disables
##! Ignition and enables the `aos metadata` agent + `systemd-repart` +
##! on-host `config-eval` reuses it unchanged. With Ignition default-on the
##! indirection resolves to the Ignition unit names, so every existing
##! system evaluates byte-identically.
##!
##! Paired with:
##!   - `mount-var.service`         — mounts /var partition (created by the
##!                                    disks backend) before files provisioning
##!   - `etc-overlay-setup.service` — /etc overlay with /var/etc + /etc.lower
##!   - `nix-overlay-setup.service` — /nix overlay with persistent upper
##!                                    on /var (writable Nix store layer)
{
  config,
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

  # RFC-0011: when the systemd-repart convention substrate owns disk carving
  # (modules/services/repart.nix), the Ignition grow/relocate units stand down —
  # repart adds/grows partitions and rewrites the GPT itself. Default false, so
  # the Ignition path is unchanged on every existing system.
  repartEnabled = config.aos.provisioning.repart.enable;

  # RFC-0011 cutover gate. Default true → every existing system keeps the
  # Ignition provisioning graph and evaluates byte-identically. A new-path
  # system sets this false and enables `aos.metadata`/`aos.provisioning.repart`/
  # `aos.config.evalAtBoot`, which provide the fetch/disks/files backends below.
  ignitionEnabled = config.aos.provisioning.ignition.enable;

  # Provisioning-backend indirection. The neutral boot units order against the
  # *active* disks/files backend by name; with Ignition on these resolve to the
  # Ignition stage units (byte-identical), and with it off to the `systemd-repart`
  # substrate + the on-host config-gen seed.
  disksUnit =
    if ignitionEnabled
    then "ignition-disks.service"
    else "aos-repart.service";
  filesUnit =
    if ignitionEnabled
    then "ignition-files.service"
    else "aos-config-seed.service";

  # Shared config for every ignition stage unit: inherit the platform
  # env from aos-platform-detect, wire PATH for the shell-outs, and
  # run a oneshot that stays active across subsequent stages. `root`
  # defaults to `/sysroot` (which is what the fetch / disks / mount
  # stages want); the files stage overrides it to the per-gen
  # /run/etc/ignition-<gen> path. The per-gen path lives in the
  # initrd's `/run` tmpfs so that systemd-initrd's `mount --move /run
  # /sysroot/run` during switch_root carries it (and its sub-mounts)
  # into stage-2 — see the note above `run-etc-setup.service` below.
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

  # The Ignition-specific initrd stage units, gated by `ignitionEnabled`.
  ignitionStageServices = {
    "aos-platform-detect" = {
      description = "AOS platform auto-detect (ignition)";
      wantedBy = ["initrd-root-fs.target"];
      before = ["ignition-fetch.service"];
      requires = [
        "systemd-udevd.service"
        "systemd-udev-trigger.service"
      ];
      after = [
        "systemd-udevd.service"
        "systemd-udev-trigger.service"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.aos-platform-detect}/bin/aos-platform-detect";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
    };

    # Bring up DHCP networking before ignition-fetch, but ONLY on
    # network-dependent platforms. aos-platform-detect drops
    # /run/ignition/need-network for cloud platforms; the
    # ConditionPathExists makes this gate a no-op (and, crucially, pull in
    # nothing) on file/qemu/metal. The whole initrd.target closure is one
    # transaction at boot, so a static Wants=network-online.target can't be
    # gated — only a fresh, additive `systemctl start` issued here, after
    # the post-udev ISO-aware detector ran, is correct. The start blocks
    # until network-online.target is reached (wait-online is pulled via the
    # .wants symlink the builder installs). wait-online sits behind a weak
    # Wants= of the target, so a wait-online timeout doesn't fail the
    # target's job — but SuccessExitStatus=0 1 keeps even a non-zero
    # systemctl result best-effort rather than failing the gate and (via
    # ignition-fetch's Requires=) wedging boot into emergency. ExecStart is
    # not shell-parsed, so no `|| true` here — SuccessExitStatus is the hatch.
    "aos-ignition-network" = {
      description = "Bring up networking for ignition (network-dependent platforms only)";
      wantedBy = ["initrd-root-fs.target"];
      requires = ["aos-platform-detect.service"];
      after = ["aos-platform-detect.service"];
      before = ["ignition-fetch.service"];
      unitConfig = {
        DefaultDependencies = "no";
        ConditionPathExists = "/run/ignition/need-network";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.systemd}/bin/systemctl start network-online.target";
        SuccessExitStatus = "0 1";
      };
    };

    # Relocate the GPT backup header to the true end of the boot disk
    # before ignition's disks stage runs. The server image is built
    # sized-to-fit (modules/image/_builder.nix): its backup GPT header
    # sits right after root-a, so the primary header's LastUsableLBA
    # describes the *image*, not the device it is written to. When that
    # image lands on a larger disk — bare-metal `dd`, or a custom cloud
    # image (e.g. DigitalOcean) on a bigger volume — ignition's disks
    # stage cannot create or grow partitions past the stale boundary and
    # fails with "Could not create partition N from X to Y" (sgdisk exit
    # 4). `sgdisk -e` moves the backup header to the real end of the
    # device and expands LastUsableLBA; it is a no-op when the image
    # already spans the disk (disk == image size, or the qemu-uefi doc's
    # host-side `sgdisk -e`). Ignition itself won't do this: its disks
    # stage is strictly declarative and treats the existing table as
    # authoritative input — repairing the GPT is the boot pipeline's job.
    #
    # Gated to the pre-provisioning boot only: once ignition has laid out
    # the disk the var partition exists and the backup header is already
    # at the end, so we skip and never rewrite the GPT on later boots.
    "aos-gpt-relocate" = {
      description = "Relocate GPT backup header to end of boot disk";
      wantedBy = ["initrd-root-fs.target"];
      before = [
        "ignition-disks.service"
        "initrd-root-fs.target"
      ];
      requires = ["dev-disk-by\\x2dpartlabel-root\\x2da.device"];
      after = ["dev-disk-by\\x2dpartlabel-root\\x2da.device"];
      unitConfig = {
        DefaultDependencies = "no";
        ConditionPathExists = "/dev/disk/by-partlabel/root-a";
      };
      environment.PATH = ignitionPath;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        set -euo pipefail
        ${lib.optionalString repartEnabled ''
          # systemd-repart relocates the GPT backup header to the device end
          # as part of growing the last partition; nothing to do here.
          echo "aos-gpt-relocate: repart owns GPT relocation; skipping"
          exit 0
        ''}
        # The var partition is created by ignition, never by the image.
        # Its presence means ignition already provisioned this disk and
        # the GPT spans the full device — nothing to relocate.
        if [ -e /dev/disk/by-partlabel/var ]; then
          echo "aos-gpt-relocate: disk already provisioned (var present); skipping"
          exit 0
        fi

        part=$(readlink -f /dev/disk/by-partlabel/root-a)
        disk=$(lsblk -ndo PKNAME "$part" 2>/dev/null || true)
        if [ -z "$disk" ]; then
          echo "aos-gpt-relocate: cannot resolve parent disk of $part; skipping" >&2
          exit 0
        fi
        disk="/dev/$disk"

        echo "aos-gpt-relocate: relocating GPT backup header to end of $disk"
        sgdisk -e "$disk"
        sgdisk -v "$disk" || true
      '';
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
        # Only a writable ext4 root is grown to fill its partition, and only
        # when repart is not the carver. A read-only erofs root is the fixed
        # immutable base (the writable Nix store layer and all mutable state
        # live on /var) — growing it would change bytes and, under dm-verity
        # (RFC-0011 F1), break the root hash; running resize2fs on erofs would
        # also just fail. When the repart substrate is enabled it grows /var
        # itself, so this unit becomes a no-op.
        ExecStart =
          if config.aos.filesystems.rootFsType == "ext4" && !repartEnabled
          then "${pkgs.aos-growfs}/bin/aos-growfs"
          else "${pkgs.coreutils}/bin/true";
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
        "aos-ignition-network.service"
      ];
      after = [
        "systemd-modules-load.service"
        "systemd-udevd.service"
        "aos-platform-detect.service"
        "aos-ignition-network.service"
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
        "aos-gpt-relocate.service"
      ];
      after = [
        "ignition-fetch.service"
        "systemd-udevd.service"
        "aos-platform-detect.service"
        "aos-gpt-relocate.service"
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
      # Write into the per-gen lower under /run/etc/ignition-<gen>/.
      # Ignition's `--root=$ign` prepends $ign to absolute paths,
      # so a `storage.links.path = "/etc/foo"` write lands at
      # `$ign/etc/foo`. The per-gen subtree is created by the
      # ExecStartPre below; etc-overlay-setup mounts it as the
      # per-generation lowerdir in the three-layer /etc overlay.
      #
      # `--root` and the ExecStartPre target the initrd's own
      # /run/etc/... (not /sysroot/run/etc/...) so the per-gen
      # subtree is rooted under the /run tmpfs that
      # systemd-initrd's switch_root moves to /sysroot/run — i.e.
      # so the per-gen path remains reachable post-pivot as
      # /run/etc/ignition-<gen>/ rather than getting shadowed by
      # the moved /run mount.
      serviceConfig =
        stageServiceConfig {
          stage = "files";
          root = "/run/etc/ignition-\${AOS_PROFILE_GEN}";
        }
        // {
          EnvironmentFile = [
            "/run/ignition/platform.env"
            "/run/aos-profile-gen.env"
          ];
          ExecStartPre =
            "${pkgs.coreutils}/bin/mkdir -p "
            + "/run/etc/ignition-\${AOS_PROFILE_GEN}/etc";
        };
    };
  };

  # The neutral boot-infrastructure units — always emitted, ordered against
  # the active provisioning backend via `disksUnit`/`filesUnit`. Not specific
  # to Ignition: a new-path system reuses these unchanged.
  neutralBootServices = {
    # Best-effort wait-online: succeed as soon as ANY managed link is
    # routable. Without --any the default "all links online" wedges ~90 s
    # whenever a second NIC is managed but has no DHCP server (e.g. the
    # fleet test's mcast NIC). overrideStrategy=asDropin emits only a
    # <unit>.d/overrides.conf over the upstream unit symlinked by the
    # builder; the empty-then-set ExecStart list is the systemd reset idiom.
    "systemd-networkd-wait-online" = {
      overrideStrategy = "asDropin";
      serviceConfig.ExecStart = [
        ""
        "${pkgs.systemd}/lib/systemd/systemd-networkd-wait-online --any"
      ];
    };

    # aos-ignition-preset.service was removed in spec v12 §6.1.6 —
    # the [Install] symlinks now ride in the system EROFS image
    # (via environment.etc."systemd/system" and the composefs dump
    # script's directory recursion at spec v12 §5.2) and in the
    # per-gen ignition lower (via generated storage.links,
    # spec v12 §5.6). The runtime preset-walker is
    # redundant.

    # Mount the /var partition created by the disks backend so that the
    # files backend can write to /sysroot/var/etc/* and the mount
    # persists through switch-root into stage-2 (no ExecStop).
    # Stage-2 systemd sees the existing mount and considers its
    # fstab-generated var.mount unit already active.
    "mount-var" = {
      description = "Mount /var Partition";
      wantedBy = ["initrd-fs.target"];
      before = [
        filesUnit
        "etc-overlay-setup.service"
        "initrd-fs.target"
      ];
      requires = [
        "sysroot.mount"
        disksUnit
      ];
      after = [
        "sysroot.mount"
        disksUnit
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
          # When measured boot seals /var (RFC-0006 phase 3), the
          # aos-var-crypt service runs first and exposes the unlocked
          # LUKS volume as /dev/mapper/var; mount that. Otherwise the
          # raw partition is mounted directly (unchanged behaviour).
          if [ -e /dev/mapper/var ]; then
            mount -o nosuid,nodev /dev/mapper/var /sysroot/var
          else
            mount -o nosuid,nodev /dev/disk/by-partlabel/var /sysroot/var
          fi
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
    #   lowerdir+=/run/etc/ignition-<gen>/etc   — per-gen files-backend lower
    #                                             (Ignition storage.links, or
    #                                             empty seed on the new path)
    #   lowerdir+=/run/etc/system-<gen>/metadata — system EROFS (composefs)
    #   datadir+= /run/etc/system-<gen>/content  — basedir for octal-mode
    #                                              entries (metacopy)
    #   upperdir = /run/etc/upper-<gen>/dir      — runtime writes (tmpfs-backed)
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
        filesUnit
        "aos-seed-profiles.service"
        "run-etc-setup.service"
        "nix-overlay-setup.service"
        "aos-machine-id.service"
      ];
      after = [
        "sysroot.mount"
        "mount-var.service"
        filesUnit
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
        # Per-gen mountpoints live under the initrd's own /run/etc
        # (the tmpfs that run-etc-setup.service mounted before
        # this unit runs). systemd-initrd does `mount --move /run
        # /sysroot/run` during switch_root, which carries the
        # /run/etc sub-mounts into stage-2 unchanged. Placing them
        # on /sysroot/run/etc instead would make /run/etc a sibling
        # of the moved /run rather than a child of it, so the
        # moved /run would shadow the whole subtree post-pivot.
        sys=/run/etc/system-$gen
        ign=/run/etc/ignition-$gen
        upper_root=/run/etc/upper-$gen

        mkdir -p "$sys/metadata" "$sys/content" \
                 "$upper_root/dir" "$upper_root/work"
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

        # /sysroot/var/etc keeps its /sysroot prefix because /var is
        # mounted on /sysroot/var in stage-1; the overlay records
        # vfsmount refs at mount time, so the literal source string
        # in the option line never gets re-resolved post-pivot.
        ${pkgs.util-linux}/bin/mount -t overlay overlay -o \
          nodev,nosuid,metacopy=on,redirect_dir=on,lowerdir+=/sysroot/var/etc,lowerdir+=$ign/etc,lowerdir+=$sys/metadata,datadir+=$sys/content,upperdir=$upper_root/dir,workdir=$upper_root/work \
          /sysroot/etc

        # Inspection symlinks (relative targets so they survive
        # switch_root). Created under the initrd's /run/etc so they
        # move into stage-2 along with the rest of /run.
        ln -sfn system-$gen   /run/etc/system
        ln -sfn ignition-$gen /run/etc/ignition
        ln -sfn upper-$gen    /run/etc/upper

        # Both readers have run; drop the gen-handoff file so it
        # doesn't ride mount --move into stage-2 with a stale value.
        rm -f /run/aos-profile-gen.env
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
    # Once the Nix DB is seeded, GC safety depends on roots. The lower
    # filesystem cannot be physically deleted, but unreferenced lower store
    # paths can still be hidden by overlay whiteouts; the stage-2 GC-root
    # bridge keeps the live AOS profile closure reachable.
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
        filesUnit
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
          # kernel_path must be the `kernel` symlink's TARGET — the
          # same form apm's resolve_kernel_path stores for installed
          # generations (crates/aos-package/src/sysroot.rs). Recording
          # the symlink itself made every upgrade/rollback against the
          # seeded gen report a spurious kernel change ("Kernel
          # updated: 6.18.33 -> kernel") and rewrite the boot loader.
          kern=$(readlink "/sysroot$toplevel/kernel" 2>/dev/null || true)
          [ -n "$kern" ] || kern="$toplevel/kernel"
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
            --arg kern "$kern" \
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
                 kernel_path: $kern
               }]
             }' > "$profile_dir/state.json"
        fi

        link=$(readlink "$profile_dir/current")
        GEN=''${link#gen-}
        printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
      '';
    };

    # Mount a tmpfs on /run/etc once, before anything else writes
    # under it. The files backend writes its per-gen
    # /run/etc/ignition-<gen>/ subtree here, and etc-overlay-setup
    # later creates the system-<gen> mount points and the upper-<gen>
    # dir (a plain directory, not its own mount) alongside.
    #
    # Why the initrd's /run rather than /sysroot/run:
    # systemd-initrd-switch-root does `mount --move /run
    # /sysroot/run` (then pivots) when handing off to stage-2. The
    # move carries the initrd's /run mount and any sub-mounts of
    # it; a separate mount on /sysroot/run/etc would be parented
    # to the sysroot fs, end up as a sibling of the moved /run
    # mount post-pivot, and be shadowed (path traversal goes
    # through the moved /run's empty /etc directory). Mounting
    # /run/etc here makes it a true child of the initrd's /run,
    # so the move carries it and its sub-mounts (the system EROFS,
    # the content bind, the per-gen files lower, the tmpfs
    # upper) into stage-2 still reachable at /run/etc/... by path.
    "run-etc-setup" = {
      description = "Mount /run/etc tmpfs";
      wantedBy = ["initrd-fs.target"];
      before = [
        filesUnit
        "etc-overlay-setup.service"
        "initrd-fs.target"
      ];
      unitConfig = {
        DefaultDependencies = "no";
        ConditionPathIsMountPoint = "!/run/etc";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p /run/etc";
        ExecStart =
          "${pkgs.util-linux}/bin/mount -t tmpfs -o nosuid,nodev,mode=755 "
          + "tmpfs /run/etc";
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
in {
  options.aos.provisioning.ignition.enable =
    lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to provision the host at first boot with Ignition (the legacy
        path). Default true. When false, the Ignition stage units stand down and
        a new-path system provides the fetch/disks/files backends via the
        `aos metadata` agent (`aos.metadata.enable`), the `systemd-repart`
        substrate (`aos.provisioning.repart.enable`), and on-host config
        evaluation (`aos.config.evalAtBoot.enable`). The neutral boot
        infrastructure (mount-var, the /etc + /nix overlays, profile seeding,
        machine-id) is emitted either way and orders against whichever backend
        is active.
      '';
    };

  config = {
    # Initrd services. The cpio assembler in modules/base/initrd-builder.nix
    # picks these up via `system.build.systemdInitrdUnits`.
    #
    # Ignition runs as a sequence of stages (fetch → disks → mount →
    # files → umount). Upstream's dracut module splits each stage
    # into its own unit so they can be ordered around `sysroot.mount`
    # — disks happens before, mount/files after. Mirror that here.
    # See ignition/dracut/30ignition/*.service in the ignition repo.
    boot.initrd.systemd.services =
      lib.mkMerge [
        neutralBootServices
        (lib.mkIf ignitionEnabled ignitionStageServices)
      ];

    # DHCP on every physical NIC in the initrd. Kind=!* excludes virtual
    # links (bridges/bonds/etc.); matching only physical ether devices
    # mirrors the stage-2 80-dhcp.network and nixpkgs' default. Brought up
    # only when the network gate fires (cloud platforms).
    boot.initrd.systemd.network."80-dhcp" = {
      matchConfig = {
        Type = "ether";
        Kind = "!*";
      };
      networkConfig.DHCP = "yes";
    };
  };
}
