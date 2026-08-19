##! modules/services/repart.nix — one-time host-driven storage provisioning
##!
##! The initrd evaluates `aos.provisioning.storage` from authenticated
##! `host.nix` (or the same schema defaults), validates it in Rust, and renders
##! per-device transient repart definitions. This unit dry-runs every target,
##! mutates each target once, then commits a GPT-resident provenance marker.
##! A committed marker freezes mutation but permits an authenticated,
##! non-mutating dry-run that reports drift. A pending marker fails closed for
##! explicit recovery instead of guessing whether a partial plan is safe.
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
            pkgs.dosfstools
            pkgs.jq
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
          # The service already routes stderr to the journal and console.
          # Writing command output synchronously through /dev/kmsg can keep a
          # completed repart process stuck in the oneshot on some virtio block
          # devices, so diagnostics must use the service output channel only.
          klog() { echo "aos-repart: $*" >&2; }

          if [ -e /dev/disk/by-partlabel/aos-provisioning-pending-v1 ]; then
            klog "pending provisioning marker found; refusing automatic replay"
            exit 1
          fi

          committed=""
          if [ -e /dev/disk/by-partlabel/aos-provenance-operator-v1 ]; then
            committed=operator
          elif [ -e /dev/disk/by-partlabel/aos-provenance-fallback-v1 ]; then
            committed=fallback
          fi

          root_part=$(readlink -f /dev/disk/by-partlabel/root-a)
          root_name=$(lsblk -ndo PKNAME "$root_part")
          if [ -z "$root_name" ]; then
            klog "cannot resolve parent disk of $root_part"
            exit 1
          fi
          root_disk="/dev/$root_name"
          targets=/run/aos-metadata/repart-targets

          repart_seed() {
            seed=$(blkid -p -s PTUUID -o value "$1") || return 1
            case "$seed" in
              ""|*[!0-9A-Fa-f-]*) return 1 ;;
            esac
            [ "''${#seed}" -eq 36 ] || return 1
            printf '%s\n' "$seed"
          }

          if [ -n "$committed" ]; then
            klog "durable $committed provisioning marker present; disk mutation is frozen"
            if [ ! -s "$targets" ]; then
              klog "no current validated storage plan; skipping advisory drift check"
              if [ ! -s /run/aos-metadata/storage-coherence ]; then
                printf '%s\n' unavailable > /run/aos-metadata/storage-coherence
              fi
              exit 0
            fi
            drift=0
            while IFS="$(printf '\t')" read -r target definitions; do
              [ "$target" = root ] && target="$root_disk"
              seed=$(repart_seed "$target") || {
                klog "cannot derive a GPT repart seed for $target"
                drift=1
                continue
              }
              klog "checking committed target=$target definitions=$definitions"
              if ! result=$(systemd-repart \
                --definitions="/run/aos-metadata/repart.d/$definitions" \
                --dry-run=yes \
                --empty=allow \
                --seed="$seed" \
                --json=short \
                "$target"); then
                klog "unable to compare current storage intent for $target; continuing"
                drift=1
                continue
              fi
              if ! printf '%s\n' "$result" | jq -e \
                'all(.[]; .activity == "unchanged")' >/dev/null; then
                klog "storage intent diverges for $target; factory reset is required to apply it"
                drift=1
              fi
            done < "$targets"
            if [ "$drift" -eq 0 ]; then
              klog "current storage intent matches the committed layout"
              printf '%s\n' coherent > /run/aos-metadata/storage-coherence
            else
              printf '%s\n' divergent > /run/aos-metadata/storage-coherence
            fi
            exit 0
          fi

          if [ ! -s "$targets" ]; then
            klog "validated repart target index is missing"
            exit 1
          fi

          # Preflight every disk before mutating any disk.
          while IFS="$(printf '\t')" read -r target definitions; do
            [ "$target" = root ] && target="$root_disk"
            seed=$(repart_seed "$target") || {
              klog "cannot derive a GPT repart seed for $target"
              exit 1
            }
            klog "preflight target=$target definitions=$definitions"
            systemd-repart \
              --definitions="/run/aos-metadata/repart.d/$definitions" \
              --dry-run=yes \
              --empty=allow \
              --seed="$seed" \
              "$target" >&2 || exit 1
          done < "$targets"

          while IFS="$(printf '\t')" read -r target definitions; do
            [ "$target" = root ] && target="$root_disk"
            seed=$(repart_seed "$target") || {
              klog "cannot derive a GPT repart seed for $target"
              exit 1
            }
            klog "applying target=$target definitions=$definitions"
            timeout --signal=TERM --kill-after=5s 30s systemd-repart \
              --definitions="/run/aos-metadata/repart.d/$definitions" \
              --dry-run=no \
              --empty=allow \
              --seed="$seed" \
              "$target" >&2
            repart_status=$?
            if [ "$repart_status" -eq 124 ]; then
              # A kernel partition-table rescan can leave repart waiting on
              # teardown even after it has logged successful completion. The
              # transaction remains ambiguous until a fresh, bounded dry run
              # proves that every requested partition is unchanged.
              klog "systemd-repart timed out after applying $target; verifying the resulting layout"
              result=$(timeout --signal=TERM --kill-after=5s 15s systemd-repart \
                --definitions="/run/aos-metadata/repart.d/$definitions" \
                --dry-run=yes \
                --empty=allow \
                --seed="$seed" \
                --json=short \
                "$target") || {
                  klog "cannot verify the layout after the timed-out repart operation"
                  exit 1
                }
              printf '%s\n' "$result" | jq -e \
                'all(.[]; .activity == "unchanged")' >/dev/null || {
                  klog "repart timed out before the requested layout was complete"
                  exit 1
                }
              klog "verified the complete layout after the bounded repart timeout"
            elif [ "$repart_status" -ne 0 ]; then
              klog "systemd-repart failed; pending marker requires explicit recovery"
              exit 1
            fi
          done < "$targets"

          # The label polls below are the authoritative readiness checks.
          # Bound udev's global queue wait so an unrelated device event cannot
          # wedge the one-time provisioning transaction after repart succeeds.
          udevadm settle --timeout=10 || true
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
          udevadm settle --timeout=10 || true

          i=0
          while [ ! -e "/dev/disk/by-partlabel/$committed" ] && [ "$i" -lt 60 ]; do
            i=$((i + 1))
            sleep 0.5
          done
          if [ ! -e "/dev/disk/by-partlabel/$committed" ]; then
            klog "committed marker did not materialize"
            exit 1
          fi
          # The durable marker is the transaction boundary. Report completion
          # through the service's journal/console stream.
          echo "aos-repart: committed $committed; future boots will not mutate disks" >&2
          exit 0
        '';
      };

      boot.initrd.systemd.services."mount-var".after = ["aos-repart.service"];
    }

    (lib.mkIf measured {
      boot.initrd.systemd.services."aos-var-crypt".after = ["aos-repart.service"];
    })
  ];
}
