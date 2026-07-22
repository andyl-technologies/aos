##! modules/services/boot-substrate.nix — Neutral first-boot substrate
##!
##! The provisioning-backend-agnostic initrd units that assemble the running
##! system on first boot, regardless of who carves the disk or delivers the
##! per-generation `/etc`:
##!
##!   - `mount-var.service`         — mounts the /var partition before the
##!                                    /etc overlay and profile seeding
##!   - `etc-overlay-setup.service` — the three-layer /etc overlay
##!                                    (/var/etc + per-gen files lower + system
##!                                    EROFS metadata)
##!   - `nix-overlay-setup.service` — the /nix overlay (writable upper on /var)
##!   - `aos-seed-profiles.service` — seeds apm's system-profile state.json
##!   - `run-etc-setup.service`     — the /run/etc tmpfs the overlay lives on
##!   - `aos-machine-id.service`    — seeds /var/etc/machine-id
##!
##! These order against `aos-repart.service` and the on-host config-generation
##! seed (`aos-config-seed.service`). Repart is idempotent when `/var` already
##! exists.
{
  config,
  pkgs,
  lib,
  ...
}: let
  # The neutral units shell out to a small toolset: `mount`/`mountpoint`
  # (util-linux), `mkdir`/`ln`/`tr` (coreutils), and `jq` (aos-seed-profiles
  # assembles apm's initial state.json). sbin lookups are covered by the
  # `lib.makeSearchPath "sbin"` side.
  bootTools = [
    pkgs.kmod
    pkgs.util-linux
    pkgs.systemd
    pkgs.coreutils
    pkgs.bash
    pkgs.jq
  ];
  bootPath = lib.concatStringsSep ":" [
    (lib.makeBinPath bootTools)
    (lib.makeSearchPath "sbin" bootTools)
  ];

  # `systemd-repart` carves and grows the substrate before the neutral boot
  # units consume it. It is idempotent when /var is already present.
  disksUnit = "aos-repart.service";

  # The files backend is always the on-host config-gen seed
  # (modules/base/config-seed.nix), which scaffolds the empty per-generation
  # /etc lower; subsequent generations are rendered by the stage-2 config-eval
  # fixpoint and switched in by `activate`.
  filesUnit = "aos-config-seed.service";

  # The neutral boot-infrastructure units are always emitted and ordered
  # against `disksUnit` and `filesUnit`.
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

    # The [Install] symlinks ride in the system EROFS image
    # (via environment.etc."systemd/system" and the composefs dump
    # script's directory recursion at spec v12 §5.2) and in the
    # per-gen config lower (via generated storage.links,
    # spec v12 §5.6). The runtime preset-walker is
    # sufficient.

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
      requires = ["sysroot.mount"] ++ lib.optional (disksUnit != null) disksUnit;
      after =
        ["sysroot.mount"]
        ++ lib.optional (disksUnit != null) disksUnit
        ++ ["systemd-udev-settle.service"];
      unitConfig = {
        ConditionPathExists = "/dev/disk/by-partlabel/var";
      };
      environment.PATH = bootPath;
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
    #   lowerdir+=/run/etc/config-<gen>/etc   — per-gen files-backend lower
    #                                             (Ignition storage.links, or
    #                                             empty initial seed)
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
      environment.PATH = bootPath;
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
        ign=/run/etc/config-$gen
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
        ln -sfn config-$gen /run/etc/config
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
      environment.PATH = bootPath;
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
      environment.PATH = bootPath;
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
    # /run/etc/config-<gen>/ subtree here, and etc-overlay-setup
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
      environment.PATH = bootPath;
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
  config = {
    # Initrd services. The cpio assembler in modules/base/initrd-builder.nix
    # picks these up via `system.build.systemdInitrdUnits`.
    boot.initrd.systemd.services = neutralBootServices;

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
