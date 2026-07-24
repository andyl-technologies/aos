##! modules/services/repart.nix — systemd-repart convention substrate
##!
##! Systemd-native substrate provisioning that carves and grows `/var` (and swap) in the
##! initrd via convention `repart.d` drop-ins. It is
##! **idempotent by construction**: `systemd-repart` computes the delta between
##! declared and observed partitions and only *adds* missing partitions and
##! *grows* growable ones — running it every boot equals running it once, so it
##! carries no guard.
##!
##! It runs on every boot before `mount-var.service`; its additive partition
##! model makes an already-provisioned disk a no-op.
##!
##! The no-plan path uses image-baked convention drop-ins. An authenticated
##! `aos.provisioning/v1` storage plan is validated and rendered under
##! `/run/aos-metadata/repart.d` before this unit starts. Full `host.nix`
##! evaluation remains in stage 2.
##!
##! Measured boot: the `var` partition is left **raw** (no `Format=`) so
##! `aos-var-crypt` (modules/base/secure-boot.nix) performs the LUKS2
##! signed-PCR-11-policy seal (RFC-0006); repart only carves + grows. Without
##! measured boot, repart formats it ext4 directly (convergent).
{
  config,
  pkgs,
  lib,
  ...
}: let
  measured = config.aos.boot.secureBoot.measuredBoot.enable;

  # Convention repart.d drop-ins baked into the initrd. systemd-repart only
  # adds/grows, so the existing ESP + root-a (and, with verity, root-a-hash)
  # partitions that have no matching definition are preserved untouched; these
  # definitions describe only what first boot must CREATE.
  #
  # NOTE (future A/B): a reserved `root-b` slot is intentionally NOT carved
  # here. systemd-repart matches config partitions to existing ones by type
  # GUID, and a Linux-data `root-b` definition would match the existing
  # (Linux-data) `root-a` instead of creating a new partition. The A/B update
  # flow (RFC-0012 §Future work) will introduce `root-b` with a distinct
  # root-verity/DPS type when it actually consumes the slot.

  # Fixed-size swap: `SizeMinBytes == SizeMaxBytes` so repart neither grows nor
  # shrinks it. Without the cap, swap has the same implicit weight as var and
  # grows to soak half the free space, starving /var (which is meant to take
  # the rest of the disk). An operator wanting more swap overrides this module.
  swapConf = ''
    [Partition]
    Type=swap
    Label=swap
    SizeMinBytes=2G
    SizeMaxBytes=2G
  '';

  # var soaks up all remaining space (Weight grow), replacing both aos-growfs
  # and aos-gpt-relocate. Measured boot omits Format= (aos-var-crypt seals it);
  # otherwise repart formats ext4 convergently.
  varConf =
    ''
      [Partition]
      Type=var
      Label=var
      SizeMinBytes=4G
      Weight=1000
    ''
    + lib.optionalString (!measured) ''
      Format=ext4
    '';

  # repart applies definitions in filename order and places new partitions in
  # the free space in that order: `50-swap` immediately after the image's
  # `root-a`, then `60-var` grows into the remaining tail.
  repartDefinitions = pkgs.runCommand "aos-repart-definitions" {} ''
    mkdir -p $out/repart.d
    cat > $out/repart.d/50-swap.conf <<'SWAP'
    ${swapConf}
    SWAP
    cat > $out/repart.d/60-var.conf <<'VAR'
    ${varConf}
    VAR
  '';
in {
  config = lib.mkMerge [
    {
      # The repart definitions closure must be reachable from the initrd store.
      aos.boot.initrd.extraPackages = [repartDefinitions];

      # Named aos-repart (not systemd-repart) to avoid any collision with an
      # upstream systemd-repart.service the initrd might carry once
      # -Drepart=enabled.
      boot.initrd.systemd.services."aos-repart" = {
        description = "Provision substrate partitions (systemd-repart convention)";
        requiredBy = ["initrd-root-fs.target"];
        before = [
          "mount-var.service"
          "sysroot.mount"
          "initrd-root-fs.target"
        ];
        # Wait for the root-a *device unit*, not just udevd — otherwise this
        # unit (pulled in early by initrd-root-fs.target) starts and evaluates
        # its ConditionPathExists before udev has created the
        # `/dev/disk/by-partlabel/root-a` symlink, skips, and the substrate is
        # never carved.
        requires = [
          "systemd-udevd.service"
          "dev-disk-by\\x2dpartlabel-root\\x2da.device"
          "aos-metadata-authorize.service"
        ];
        after = [
          "aos-metadata-authorize.service"
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
          "systemd-udev-settle.service"
          "dev-disk-by\\x2dpartlabel-root\\x2da.device"
        ];
        unitConfig = {
          DefaultDependencies = "no";
          # Redundant with the .device dependency above (the symlink exists by
          # the time this runs), but kept as a cheap belt-and-suspenders guard.
          ConditionPathExists = "/dev/disk/by-partlabel/root-a";
        };
        # systemd-repart shells out to the filesystem formatters for the
        # partitions it creates: `mkswap` (util-linux, in sbin) for the swap
        # slot and `mkfs.ext4` (e2fsprogs, in sbin) for var. Both the bin and
        # sbin dirs must be on PATH or repart aborts with "mkswap binary not
        # available" / "mkfs.ext4 binary not available".
        environment.PATH = let
          repartTools = [
            pkgs.coreutils
            pkgs.util-linux
            pkgs.e2fsprogs
            pkgs.systemd
          ];
        in
          lib.concatStringsSep ":" [
            (lib.makeBinPath repartTools)
            (lib.makeSearchPath "sbin" repartTools)
          ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          set -uo pipefail
          # Trace to /dev/kmsg: the console goes quiet to systemd's own log once
          # journald starts, but the kernel ring buffer always reaches the
          # serial. Mirrors aos-var-crypt's klog.
          klog() { echo "aos-repart: $*" > /dev/kmsg 2>/dev/null || echo "aos-repart: $*" >&2; }
          klog "starting"
          # Resolve the whole disk backing root-a; systemd-repart grows the last
          # partition and rewrites the GPT (incl. the backup header) to the real
          # device end, so no separate sgdisk -e relocation is needed.
          part=$(readlink -f /dev/disk/by-partlabel/root-a)
          disk=$(lsblk -ndo PKNAME "$part")
          klog "root-a=$part disk=$disk"
          if [ -z "$disk" ]; then
            klog "cannot resolve parent disk of $part"
            exit 1
          fi
          definitions=${repartDefinitions}/repart.d
          if [ -d /run/aos-metadata/repart.d ]; then
            definitions=/run/aos-metadata/repart.d
            klog "using authenticated provisioning storage plan"
          else
            klog "using image-baked storage convention"
          fi
          if ! systemd-repart \
            --definitions="$definitions" \
            --dry-run=yes \
            --empty=allow \
            "/dev/$disk" > /dev/kmsg 2>&1; then
            klog "storage plan preflight failed; partition table left unchanged"
            exit 1
          fi
          systemd-repart \
            --definitions="$definitions" \
            --dry-run=no \
            --empty=allow \
            "/dev/$disk" > /dev/kmsg 2>&1
          rc=$?
          klog "systemd-repart rc=$rc"

          # systemd-repart adds the new partitions online (BLKPG), but udev is
          # slow to materialise the `/dev/disk/by-partlabel/{var,swap,root-b}`
          # symlinks. `mount-var` guards on `ConditionPathExists=…/var`, which
          # systemd evaluates the instant this unit completes — so settle udev
          # here first, otherwise mount-var races the symlink, skips, and the
          # boot collapses with no /var. Mirrors the poll in aos-var-crypt.
          udevadm settle || true
          i=0
          while [ ! -e /dev/disk/by-partlabel/var ] && [ "$i" -lt 60 ]; do
            i=$((i + 1))
            sleep 0.5
          done
          klog "var=$(readlink -f /dev/disk/by-partlabel/var 2>/dev/null || echo MISSING) swap=$(readlink -f /dev/disk/by-partlabel/swap 2>/dev/null || echo MISSING) rootb=$(readlink -f /dev/disk/by-partlabel/root-b 2>/dev/null || echo MISSING)"
          klog "done"
          exit 0
        '';
      };

      # Order the existing /var consumer after repart carved the partition
      # (additive: merges with the unit's existing After= list).
      boot.initrd.systemd.services."mount-var".after = ["aos-repart.service"];
    }

    # aos-var-crypt only exists under measured boot (modules/base/secure-boot.nix
    # gates it on measuredBoot.enable). Only contribute its After= retarget when
    # that unit actually exists, else the initrd builder would render a partial
    # ExecStart-less unit.
    (lib.mkIf measured {
      boot.initrd.systemd.services."aos-var-crypt".after = ["aos-repart.service"];
    })
  ];
}
