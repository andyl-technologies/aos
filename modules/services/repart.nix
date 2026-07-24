##! modules/services/repart.nix — one-time host-driven storage provisioning
##!
##! The initrd evaluates `aos.provisioning.storage` from authenticated
##! `host.nix` (or the same schema defaults), validates it in Rust, and renders
##! per-device transient repart definitions. This unit dry-runs every target,
##! mutates each target once, then commits a GPT-resident provenance marker.
##! Committed disks never depend on metadata again; a pending marker fails
##! closed for explicit recovery instead of guessing whether a partial plan is
##! safe to replay.
{
  config,
  pkgs,
  lib,
  ...
}: let
  measured = config.aos.boot.secureBoot.measuredBoot.enable;
in {
  config = lib.mkMerge [
    {
      boot.initrd.systemd.services."aos-repart" = {
        description = "Commit one-time host storage provisioning";
        requiredBy = ["initrd-root-fs.target"];
        before = [
          "mount-var.service"
          "sysroot.mount"
          "initrd-root-fs.target"
        ];
        requires = [
          "systemd-udevd.service"
          "dev-disk-by\\x2dpartlabel-root\\x2da.device"
          "aos-provisioning-state.service"
          "aos-provisioning-eval.service"
        ];
        after = [
          "aos-provisioning-state.service"
          "aos-provisioning-eval.service"
          "systemd-udevd.service"
          "systemd-udev-trigger.service"
          "systemd-udev-settle.service"
          "dev-disk-by\\x2dpartlabel-root\\x2da.device"
        ];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathExists = "/dev/disk/by-partlabel/root-a";
        };
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
          klog() { echo "aos-repart: $*" > /dev/kmsg 2>/dev/null || echo "aos-repart: $*" >&2; }

          if [ -e /dev/disk/by-partlabel/aos-provenance-operator-v1 ] \
            || [ -e /dev/disk/by-partlabel/aos-provenance-fallback-v1 ]; then
            klog "durable provisioning marker present; disk mutation is frozen"
            exit 0
          fi
          if [ -e /dev/disk/by-partlabel/aos-provisioning-pending-v1 ]; then
            klog "pending provisioning marker found; refusing automatic replay"
            exit 1
          fi

          root_part=$(readlink -f /dev/disk/by-partlabel/root-a)
          root_name=$(lsblk -ndo PKNAME "$root_part")
          if [ -z "$root_name" ]; then
            klog "cannot resolve parent disk of $root_part"
            exit 1
          fi
          root_disk="/dev/$root_name"
          targets=/run/aos-metadata/repart-targets
          if [ ! -s "$targets" ]; then
            klog "validated repart target index is missing"
            exit 1
          fi

          # Preflight every disk before mutating any disk.
          while IFS="$(printf '\t')" read -r target definitions; do
            [ "$target" = root ] && target="$root_disk"
            klog "preflight target=$target definitions=$definitions"
            systemd-repart \
              --definitions="/run/aos-metadata/repart.d/$definitions" \
              --dry-run=yes \
              --empty=allow \
              "$target" > /dev/kmsg 2>&1 || exit 1
          done < "$targets"

          while IFS="$(printf '\t')" read -r target definitions; do
            [ "$target" = root ] && target="$root_disk"
            klog "applying target=$target definitions=$definitions"
            if ! systemd-repart \
              --definitions="/run/aos-metadata/repart.d/$definitions" \
              --dry-run=no \
              --empty=allow \
              "$target" > /dev/kmsg 2>&1; then
              klog "systemd-repart failed; pending marker requires explicit recovery"
              exit 1
            fi
          done < "$targets"

          udevadm settle || true
          i=0
          while [ ! -e /dev/disk/by-partlabel/aos-provisioning-pending-v1 ] \
            && [ "$i" -lt 60 ]; do
            i=$((i + 1))
            sleep 0.5
          done
          if [ ! -e /dev/disk/by-partlabel/aos-provisioning-pending-v1 ]; then
            klog "pending marker did not materialize"
            exit 1
          fi

          pending=$(readlink -f /dev/disk/by-partlabel/aos-provisioning-pending-v1)
          part_number=$(cat "/sys/class/block/$(basename "$pending")/partition")
          source=$(tr -d '\n' < /run/aos-metadata/provisioning-source)
          case "$source" in
            operator) committed=aos-provenance-operator-v1 ;;
            fallback) committed=aos-provenance-fallback-v1 ;;
            *) klog "unknown provisioning source '$source'"; exit 1 ;;
          esac
          sfdisk --part-label "$root_disk" "$part_number" "$committed"
          udevadm settle || true

          i=0
          while [ ! -e "/dev/disk/by-partlabel/$committed" ] && [ "$i" -lt 60 ]; do
            i=$((i + 1))
            sleep 0.5
          done
          if [ ! -e "/dev/disk/by-partlabel/$committed" ]; then
            klog "committed marker did not materialize"
            exit 1
          fi
          klog "committed $committed; future boots will not mutate disks"
        '';
      };

      boot.initrd.systemd.services."mount-var".after = ["aos-repart.service"];
    }

    (lib.mkIf measured {
      boot.initrd.systemd.services."aos-var-crypt".after = ["aos-repart.service"];
    })
  ];
}
