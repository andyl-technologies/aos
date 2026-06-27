##! modules/services/repart.nix — systemd-repart convention substrate (RFC-0011)
##!
##! Opt-in (`aos.provisioning.repart.enable`, default false) systemd-native
##! substrate provisioning that carves and grows `/var` (and swap) in the
##! initrd via convention `repart.d` drop-ins, replacing Ignition's
##! `disks`/`aos-growfs`/`aos-gpt-relocate` for the zero-config cloud VM. It is
##! **idempotent by construction**: `systemd-repart` computes the delta between
##! declared and observed partitions and only *adds* missing partitions and
##! *grows* growable ones — running it every boot equals running it once, so it
##! carries no guard.
##!
##! GATED + ADDITIVE: when disabled (every existing ext4/VM-test system) this
##! module contributes nothing — no initrd unit, no definitions, no ordering
##! edges — so the Ignition disk path is untouched. When enabled, it runs
##! `systemd-repart` before `mount-var.service` and the Ignition disk-carving
##! units (`ignition-disks`, `aos-growfs`, `aos-gpt-relocate`) gate themselves
##! off (see modules/services/ignition.nix).
##!
##! First-boot substrate is **image-only** (review M-repart-order): repart runs
##! in the initrd, before host.nix is evaluated in stage-2, so only the
##! image-baked convention drop-ins drive first-boot carving. Operator custom
##! topologies are a documented two-boot flow (build-spec §7) and are not
##! implemented here.
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
  cfg = config.aos.provisioning.repart;
  measured = config.aos.boot.secureBoot.measuredBoot.enable;

  # Convention repart.d drop-ins baked into the initrd. systemd-repart only
  # adds/grows, so the existing ESP + root-a (and, with verity, root-a-hash)
  # partitions that have no matching definition are preserved untouched; these
  # definitions describe only what first boot must CREATE.
  swapConf = ''
    [Partition]
    Type=swap
    Label=swap
    SizeMinBytes=1G
    SizeMaxBytes=8G
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
  options.aos.provisioning.repart = {
    ## Carve/grow `/var` (and swap) in the initrd via systemd-repart.
    ##
    ## Opt-in convention substrate (RFC-0011 provisioning). When false (the
    ## default, and every existing system) this module is inert and Ignition
    ## owns disk carving. Enable it on a systemd-native production variant; the
    ## Ignition disk units then gate themselves off.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Provision substrate with systemd-repart convention drop-ins in the
        initrd instead of Ignition's disks/growfs/gpt-relocate. Idempotent:
        adds only missing partitions and grows growable ones every boot.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      # The repart definitions closure must be reachable from the initrd store.
      aos.boot.initrd.extraPackages = [repartDefinitions];

      # Named aos-repart (not systemd-repart) to avoid any collision with an
      # upstream systemd-repart.service the initrd might carry once
      # -Drepart=enabled.
      boot.initrd.systemd.services."aos-repart" = {
        description = "Provision substrate partitions (systemd-repart convention)";
        wantedBy = ["initrd-root-fs.target"];
        before = [
          "mount-var.service"
          "sysroot.mount"
          "initrd-root-fs.target"
        ];
        requires = ["systemd-udevd.service"];
        after = [
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
          "systemd-udev-settle.service"
        ];
        unitConfig = {
          DefaultDependencies = "no";
          # Only meaningful once the root-a partition is visible (so the parent
          # disk is resolvable). Cheap pre-filter; repart itself is the carver.
          ConditionPathExists = "/dev/disk/by-partlabel/root-a";
        };
        environment.PATH = lib.concatStringsSep ":" [
          "${pkgs.coreutils}/bin"
          "${pkgs.util-linux}/bin"
          "${pkgs.systemd}/bin"
        ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          set -euo pipefail
          # Resolve the whole disk backing root-a; systemd-repart grows the last
          # partition and rewrites the GPT (incl. the backup header) to the real
          # device end, so no separate sgdisk -e relocation is needed.
          part=$(readlink -f /dev/disk/by-partlabel/root-a)
          disk=$(lsblk -ndo PKNAME "$part")
          if [ -z "$disk" ]; then
            echo "systemd-repart: cannot resolve parent disk of $part" >&2
            exit 1
          fi
          systemd-repart \
            --definitions=${repartDefinitions}/repart.d \
            --dry-run=no \
            --empty=allow \
            "/dev/$disk"
        '';
      };

      # Order the existing /var consumer after repart carved the partition
      # (additive: merges with the After= list declared in ignition.nix; harmless
      # ordering only).
      boot.initrd.systemd.services."mount-var".after = ["aos-repart.service"];
    }

    # aos-var-crypt only exists under measured boot (modules/base/secure-boot.nix
    # gates it on measuredBoot.enable). Only contribute its After= retarget when
    # that unit actually exists, else the initrd builder would render a partial
    # ExecStart-less unit.
    (lib.mkIf measured {
      boot.initrd.systemd.services."aos-var-crypt".after = ["aos-repart.service"];
    })
  ]);
}
