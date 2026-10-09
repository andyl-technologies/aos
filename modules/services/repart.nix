##! modules/services/repart.nix — one-time host-driven storage provisioning
##!
##! The initrd evaluates `aos.provisioning.storage` from authenticated
##! `host.nix` (or the same schema defaults), validates it in Rust, and renders
##! per-device transient repart definitions. This unit dry-runs every target,
##! mutates each target once, and reserves a pending GPT-resident provenance
##! marker. `aos-storage-topology.service` (modules/services/storage-topology.nix)
##! then creates the declared arrays and filesystems and relabels the marker as
##! committed. A committed marker freezes mutation but permits an authenticated,
##! non-mutating dry-run that reports drift. A pending marker fails closed for
##! explicit recovery instead of guessing whether a partial plan is safe.
{
  config,
  pkgs,
  lib,
  ...
}: let
  measured = config.aos.boot.secureBoot.measuredBoot.enable;
  protectedVar =
    config.aos.security.selinux.protectedSandboxNetworkRoots.enable
    || config.aos.sandbox.controllerService.method46TpmFloor.required
    || config.aos.sandbox.storageBroker.method46TpmFloor.required;
  varRootContext = config.aos.security.selinux.protectedSandboxNetworkRoots._varRootContext;
in {
  config = lib.mkMerge [
    {
      boot.initrd.systemd.services."aos-repart".enable =
        !(config.aos.filesystems.zfs.enable && config.aos.filesystems.zfs.systemState);
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

          ${lib.optionalString protectedVar ''
            # Only a plain partition is formatted by repart. A raw member of
            # the var array belongs to the later topology/crypto format owner.
            plain_var_partition=0
            var_device=""
            var_created=0
            if [ ! -s /run/aos-metadata/storage-volumes ]; then
              klog "validated protected /var volume index is missing"
              exit 1
            fi
            while IFS="$(printf '\t')" read -r name kind device label encryption filesystem; do
              [ "$name" = var ] || continue
              [ "$kind" = partition ] || continue
              [ "$encryption" = none ] || continue
              if [ "$filesystem" != ext4 ] || [ "$label" != var ]; then
                klog "protected /var requires its exact plain ext4 partition identity"
                exit 1
              fi
              plain_var_partition=1
              var_device="$device"
            done < /run/aos-metadata/storage-volumes
          ''}
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
            ${lib.optionalString protectedVar ''
              if [ "$plain_var_partition" -eq 1 ] && [ "$target" = "$root_disk" ]; then
                plan=$(systemd-repart \
                  --definitions="/run/aos-metadata/repart.d/$definitions" \
                  --dry-run=yes --empty=allow --seed="$seed" \
                  --json=short "$target") || exit 1
                if printf '%s\n' "$plan" | jq -e \
                  '[.[] | select(.label == "var")] | length == 1 and .[0].activity == "create"' \
                  >/dev/null; then
                  var_created=1
                fi
              fi
            ''}
          done < "$targets"

          ${lib.optionalString protectedVar ''
            if [ "$var_created" -eq 1 ] && [ -e "$var_device" ]; then
              klog "planned-new /var already exists before repart"
              exit 1
            fi
          ''}

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

          ${lib.optionalString protectedVar ''
            if [ "$plain_var_partition" -eq 1 ]; then
              # Repart briefly mounts a freshly formatted ext4 /var while
              # populating it. That leaves inode 2 explicitly unlabeled under
              # enforcing SELinux; rootcontext= on a later mount does not make
              # the label durable. Never relabel an existing volume.
              var_device=$(readlink -f "$var_device") || exit 1
              if [ "$(lsblk -ndo PKNAME "$var_device")" != "$root_name" ] \
                || [ "$(blkid -p -s TYPE -o value "$var_device")" != ext4 ] \
                || findmnt -n -S "$var_device" >/dev/null; then
                klog "protected /var is not an unmounted ext4 partition on the root disk"
                exit 1
              fi

              var_label=$(debugfs -R 'ea_get / security.selinux' "$var_device" 2>/dev/null) || {
                klog "cannot read protected /var root SELinux label"
                exit 1
              }
              expected_label='security.selinux (23) = "${varRootContext}"'
              if [ "$var_created" -eq 1 ]; then
                case "$var_label" in
                  ""|'security.selinux (23) = "system_u:object_r:unlabeled_t"') ;;
                  *) klog "new /var root has an unexpected SELinux label"; exit 1 ;;
                esac
                debugfs -w -R \
                  'ea_set / security.selinux ${varRootContext}' "$var_device" >&2 || exit 1
                sync "$var_device" || exit 1
                var_label=$(debugfs -R 'ea_get / security.selinux' "$var_device" 2>/dev/null) || {
                  klog "cannot verify protected /var root SELinux label"
                  exit 1
                }
              fi
              if [ "$var_label" != "$expected_label" ]; then
                klog "protected /var root lacks its durable exact SELinux label"
                exit 1
              fi
            fi
          ''}

          # The partition layer is complete but the transaction is not: the
          # marker stays pending until aos-storage-topology has created every
          # declared array and filesystem, then relabels it as committed. A
          # crash before that point is observable on the next boot above.
          klog "partition layer applied; pending marker reserved for the array and volume layers"
          exit 0
        '';
      };

      boot.initrd.systemd.services."mount-var".after = ["aos-repart.service"];
    }

    (lib.mkIf (measured && !(config.aos.filesystems.zfs.enable && config.aos.filesystems.zfs.systemState)) {
      boot.initrd.systemd.services."aos-var-crypt".after = ["aos-repart.service"];
    })
  ];
}
