##! modules/services/storage-topology.nix — MD arrays and ext4 volumes
##!
##! The layers above the partitions that `aos-repart.service` carves:
##!
##!   - Linux MD arrays declared in `aos.provisioning.storage.arrays`, created
##!     once in the first-boot storage transaction and assembled by the initrd
##!     on every later boot;
##!   - the filesystems those arrays carry, formatted here when plain and by
##!     `aos-var-crypt.service` when TPM-sealed;
##!   - the durable provenance marker commit, which moves here from repart so
##!     a crash between carving and array creation leaves the marker pending
##!     and the next boot fails closed instead of guessing;
##!   - stage-2 mount units for data volumes, declared through
##!     `aos.filesystems.volumes` against the same logical names.
##!
##! Volumes are mounted by filesystem label: `systemd-repart` labels a plain
##! partition's filesystem with its GPT label, an array's filesystem carries
##! the array name, and a sealed volume's inner filesystem carries the label
##! of its container. `/dev/disk/by-label/<label>` therefore resolves the right
##! device for every topology without the mount unit knowing which one it is.
##!
##! Data volumes are ext4 or xfs; `/var` is always ext4. Both are created with
##! their tools' defaults, which already detect md stripe geometry, so no
##! per-filesystem tuning is declared here.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.filesystems.volumes;
  storage = config.aos.provisioning.storage;

  # A pool that carries /var owns the whole system-state path; the md layer
  # is then never part of the boot-time storage chain.
  zfsState = config.aos.filesystems.zfs.enable && config.aos.filesystems.zfs.systemState;
  measured = config.aos.boot.secureBoot.measuredBoot.enable;
  protectedVar =
    config.aos.security.selinux.protectedSandboxNetworkRoots.enable
    || config.aos.sandbox.controllerService.method46TpmFloor.required
    || config.aos.sandbox.storageBroker.method46TpmFloor.required;
  varRootContext = config.aos.security.selinux.protectedSandboxNetworkRoots._varRootContext;

  # RAID personalities and xfs are loadable modules
  # (pkgs/kernel/config/storage.config); the md core and ext4 are built in.
  # Force-loading them in the initrd keeps assembly and formatting independent
  # of whether the kernel's module autoload can reach kmod there.
  initrdModules = ["raid0" "raid1" "raid10" "raid456" "xfs"];

  topologyTools = [
    pkgs.coreutils
    pkgs.e2fsprogs
    pkgs.mdadm
    pkgs.systemd
    pkgs.util-linux
    pkgs.xfsprogs
  ];
  topologyPath = lib.concatStringsSep ":" [
    (lib.makeBinPath topologyTools)
    (lib.makeSearchPath "sbin" topologyTools)
  ];

  volumeType = lib.types.submodule {
    options = {
      mountPoint = lib.mkOption {
        type = lib.types.strMatching "/.*";
        description = ''
          Absolute mount point for the volume, beneath `/srv` or `/var`.
          The image root is read-only, so a mount point can only be created
          under a writable tree: `/srv` is a persistent bind of `/var/srv`
          that every host provides for data volumes.
        '';
      };

      mountOptions = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = ["nosuid" "nodev"];
        description = "Mount options passed to the generated mount unit.";
      };
    };
  };

  # The filesystem label a volume name resolves to: an array carries its own
  # name, a partition carries its GPT label.
  volumeLabel = name:
    if storage.arrays ? ${name}
    then name
    else storage.partitions.${name}.label;

  volumeExists = name: storage.arrays ? ${name} || storage.partitions ? ${name};

  # Partitions that are array members never carry a mountable filesystem.
  memberPartitions = lib.concatMap (array: array.members) (builtins.attrValues storage.arrays);

  volumeHasFilesystem = name:
    if storage.arrays ? ${name}
    then storage.arrays.${name}.format != null
    else
      !(builtins.elem name memberPartitions)
      && builtins.elem storage.partitions.${name}.format ["ext4" "xfs" "vfat"];

  volumeFsType = name:
    if storage.arrays ? ${name}
    then storage.arrays.${name}.format
    else storage.partitions.${name}.format;

  # mkfs.ext4 truncates longer labels and mkfs.xfs rejects them; either way
  # the mount identity would point at nothing.
  labelLimit = name:
    if volumeFsType name == "xfs"
    then 12
    else 16;

  mountedVolumes = builtins.attrNames cfg;

  # The image root is read-only and cannot know host.nix mount points, so a
  # volume may only mount under a tree that is writable by the time
  # local-fs.target assembles: /srv (a bind of the persistent /var/srv, see
  # below) or /var itself.
  writableRoots = ["/srv/" "/var/"];
  mountPointIsWritable = name:
    builtins.any (root: lib.hasPrefix root cfg.${name}.mountPoint) writableRoots;
in {
  options.aos.filesystems.volumes = lib.mkOption {
    type = lib.types.attrsOf volumeType;
    default = {};
    description = ''
      Mount units for data volumes declared in `aos.provisioning.storage`,
      keyed by the logical partition or array name. The system-state volume
      `var` is mounted by the initrd and must not be listed here. A volume
      that is TPM-sealed is unavailable until the first Secure Boot enforcing
      boot has sealed it; its mount unit is wanted rather than required by
      `local-fs.target`, so an absent volume degrades the host without
      blocking boot.
    '';
  };

  config = lib.mkMerge [
    {
      assertions =
        [
          {
            assertion = !(cfg ? var);
            message = "aos.filesystems.volumes must not declare 'var'; the initrd mounts the system-state volume.";
          }
        ]
        ++ map (name: {
          assertion = volumeExists name;
          message = "aos.filesystems.volumes.${name} names no aos.provisioning.storage partition or array.";
        })
        mountedVolumes
        ++ map (name: {
          assertion = mountPointIsWritable name;
          message = "aos.filesystems.volumes.${name}.mountPoint must lie under /srv or /var; the image root is read-only and cannot hold '${cfg.${name}.mountPoint}'.";
        })
        mountedVolumes
        ++ map (name: {
          assertion = !(volumeExists name) || volumeHasFilesystem name;
          message = "aos.filesystems.volumes.${name} refers to a raw partition, an array member, or a raw array; only a formatted volume can be mounted.";
        })
        mountedVolumes
        ++ map (name: {
          assertion = !(volumeExists name && volumeHasFilesystem name) || builtins.stringLength (volumeLabel name) <= labelLimit name;
          message = "aos.filesystems.volumes.${name}: filesystem label '${volumeLabel name}' exceeds the ${toString (labelLimit name)}-byte ${toString (volumeFsType name)} label limit; shorten the partition label.";
        })
        mountedVolumes;

      # /srv lives on the state volume. The image bakes the empty mount point
      # (lib/build/rootfs.nix) and the initrd creates /var/srv with the other
      # standard /var directories, so this bind is available to every host
      # whether or not it declares volumes. systemd orders nested mount units
      # after their parent, so a volume under /srv waits for the bind.
      systemd.mounts =
        [
          {
            what = "/var/srv";
            where = "/srv";
            type = "none";
            options = "bind";
            wantedBy = ["local-fs.target"];
            before = ["local-fs.target"];
          }
        ]
        # One mount unit per declared volume, wanted by local-fs.target so a
        # sealed volume that has not been created yet degrades rather than
        # blocks the boot.
        ++ map (name: {
          what = "/dev/disk/by-label/${volumeLabel name}";
          where = cfg.${name}.mountPoint;
          type = volumeFsType name;
          options = lib.concatStringsSep "," cfg.${name}.mountOptions;
          wantedBy = ["local-fs.target"];
          before = ["local-fs.target"];
        })
        mountedVolumes;
    }

    (lib.mkIf (!zfsState) {
      # mdadm's udev rules publish /dev/md/<name> after assembly and start
      # incremental assembly as members appear; both phases need them. The
      # xfs tools are needed wherever a volume may be formatted or repaired.
      environment.systemPackages = [pkgs.mdadm pkgs.xfsprogs];
      environment.etc."mdadm.conf".source = "${pkgs.mdadm}/etc/mdadm.conf";
      aos.boot.initrd.extraPackages = [pkgs.mdadm pkgs.xfsprogs];
      aos.boot.initrd.modules = initrdModules;

      boot.initrd.systemd.services."aos-storage-topology" = {
        description = "Assemble storage arrays and commit host provisioning";
        requiredBy = ["initrd-root-fs.target"];
        before = [
          "mount-var.service"
          "initrd-root-fs.target"
          # The marker relabel rewrites the GPT and triggers a partition-table
          # rescan. dm-verity must not hold root-a during that rescan, so both
          # verity units order after this unit exactly as they do after
          # aos-repart (modules/security/verity.nix); a boot without verity
          # simply has no such units to wait for.
          "systemd-veritysetup@root.service"
          "aos-verity-root-verify.service"
        ];
        requires = ["aos-repart.service"];
        after = [
          "aos-repart.service"
          "systemd-udev-settle.service"
        ];
        unitConfig.DefaultDependencies = "no";
        environment.PATH = topologyPath;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          set -uo pipefail
          klog() { echo "aos-storage-topology: $*" >&2; }

          stash=/run/aos-metadata
          arrays="$stash/storage-arrays"
          volumes="$stash/storage-volumes"
          pending=/dev/disk/by-partlabel/aos-provisioning-pending-v1
          ${lib.optionalString protectedVar ''created_var_array=0''}

          wait_for() {
            i=0
            while [ ! -e "$1" ] && [ "$i" -lt 60 ]; do
              i=$((i + 1))
              sleep 0.5
            done
            [ -e "$1" ]
          }

          # Tool defaults are the intended defaults: both detect the md
          # stripe geometry of an array device, and xfs enables crc, finobt,
          # and reflink on its own.
          make_filesystem() {
            case "$1" in
              ext4)
                ${lib.optionalString protectedVar ''
                  if [ "$4" = var ]; then
                    mkfs.ext4 -q -L "$2" -E root_selinux=${varRootContext} "$3" || return 1
                    sync "$3" || return 1
                    require_var_label "$3" || return 1
                    return 0
                  fi
                ''}
                mkfs.ext4 -q -L "$2" "$3"
                ;;
              xfs) mkfs.xfs -q -L "$2" "$3" ;;
              *) klog "unsupported filesystem $1 for $3"; return 1 ;;
            esac
          }

          ${lib.optionalString protectedVar ''
            require_var_label() {
              if [ "$(blkid -p -s TYPE -o value "$1")" != ext4 ] \
                || findmnt -n -S "$1" >/dev/null; then
                klog "protected /var is not an unmounted ext4 filesystem"
                return 1
              fi
              var_label=$(debugfs -R 'ea_get / security.selinux' "$1" 2>/dev/null) || return 1
              if [ "$var_label" != 'security.selinux (23) = "${varRootContext}"' ]; then
                klog "protected /var root lacks its durable exact SELinux label"
                return 1
              fi
            }
          ''}

          # Incremental udev assembly usually has every complete array running
          # by now; --scan finishes any whose members surfaced late.
          assemble() {
            mdadm --assemble --scan >/dev/null 2>&1 || true
            udevadm settle --timeout=10 || true
          }

          # Arrays the plan expects to exist. Without a plan (metadata outage
          # after commit), the system-state array is still inferred from the
          # on-disk fact that the var partition is a RAID member.
          expected_arrays() {
            if [ -s "$arrays" ]; then
              cut -f1 "$arrays"
            elif [ -e /dev/disk/by-partlabel/var ] \
              && [ "$(blkid -p -s TYPE -o value /dev/disk/by-partlabel/var 2>/dev/null)" = linux_raid_member ]; then
              echo var
            fi
          }

          assemble

          if [ -e "$pending" ]; then
            # First-boot transaction: aos-repart carved the partitions and
            # reserved the pending marker. Create every declared array on its
            # still-blank members, format plain array filesystems, then commit.
            if [ ! -s "$stash/provisioning-source" ]; then
              klog "pending marker present without a provisioning source"
              exit 1
            fi
            if [ -s "$arrays" ]; then
              while IFS="$(printf '\t')" read -r name level count members; do
                if [ -e "/dev/md/$name" ]; then
                  klog "array $name is already active"
                  continue
                fi
                devices=()
                IFS=, read -r -a devices <<< "$members"
                for device in "''${devices[@]}"; do
                  if ! wait_for "$device"; then
                    klog "member $device of array $name did not appear"
                    exit 1
                  fi
                  signature=$(blkid -p -s TYPE -o value "$device" 2>/dev/null || true)
                  if [ -n "$signature" ]; then
                    klog "member $device of array $name already carries $signature; refusing to overwrite"
                    exit 1
                  fi
                done
                klog "creating $level array $name from ''${count} members"
                mdadm --create "/dev/md/$name" \
                  --run \
                  --metadata=1.2 \
                  --homehost=aos \
                  --name="$name" \
                  --level="$level" \
                  --raid-devices="$count" \
                  "''${devices[@]}" >&2 || exit 1
                ${lib.optionalString protectedVar ''
                  [ "$name" != var ] || created_var_array=1
                ''}
              done < "$arrays"
              udevadm settle --timeout=10 || true
              while IFS="$(printf '\t')" read -r name level count members; do
                if ! wait_for "/dev/md/$name"; then
                  klog "array $name did not appear after creation"
                  exit 1
                fi
              done < "$arrays"
            fi

            # Plain array filesystems are created here; repart already
            # formatted plain partitions, and aos-var-crypt formats sealed
            # volumes inside the container it creates once Secure Boot is
            # enforcing.
            if [ -s "$volumes" ]; then
              while IFS="$(printf '\t')" read -r name kind device label encryption filesystem; do
                [ "$kind" = array ] || continue
                [ "$encryption" = none ] || continue
                [ "$filesystem" != - ] || continue
                ${lib.optionalString protectedVar ''
                  if [ "$name" = var ]; then
                    if [ "$filesystem" != ext4 ] || [ "$label" != var ]; then
                      klog "protected /var requires its exact plain ext4 array identity"
                      exit 1
                    fi
                    if [ "$created_var_array" -ne 1 ]; then
                      # An already active array is not our fresh format output.
                      # Verify it without repairing or overwriting its contents.
                      require_var_label "$device" || exit 1
                      continue
                    fi
                    signature_status=0
                    signature=$(blkid -p -s TYPE -o value "$device" 2>/dev/null) \
                      || signature_status=$?
                    if [ -n "$signature" ] || [ "$signature_status" -ne 2 ] \
                      || findmnt -n -S "$device" >/dev/null; then
                      klog "new protected var array is not provably blank and unmounted"
                      exit 1
                    fi
                  fi
                ''}
                klog "formatting $device as $filesystem '$label'"
                make_filesystem "$filesystem" "$label" "$device" "$name" || exit 1
              done < "$volumes"
              udevadm settle --timeout=10 || true
            fi

            # The durable marker is the transaction boundary: relabel only
            # after every array and filesystem exists.
            source=$(tr -d '\n' < "$stash/provisioning-source")
            case "$source" in
              operator) committed=aos-provenance-operator-v1 ;;
              fallback) committed=aos-provenance-fallback-v1 ;;
              *) klog "unknown provisioning source '$source'"; exit 1 ;;
            esac
            pending_dev=$(readlink -f "$pending")
            part_number=$(cat "/sys/class/block/$(basename "$pending_dev")/partition")
            root_disk="/dev/$(lsblk -ndo PKNAME "$pending_dev")"
            sfdisk --part-label "$root_disk" "$part_number" "$committed" || exit 1
            udevadm settle --timeout=10 || true
            if ! wait_for "/dev/disk/by-partlabel/$committed"; then
              klog "committed marker did not materialize"
              exit 1
            fi
            echo "aos-storage-topology: committed $committed; future boots will not mutate disks" >&2
            exit 0
          fi

          # Provisioned boot: every expected array must be running. A member
          # that is merely slow gets one more chance before the array is
          # started degraded, which is what keeps a mirror bootable after a
          # disk failure.
          missing=""
          for name in $(expected_arrays); do
            [ -e "/dev/md/$name" ] || missing="$missing $name"
          done
          if [ -n "$missing" ]; then
            klog "waiting for late members of:$missing"
            sleep 5
            udevadm settle --timeout=10 || true
            mdadm --assemble --scan --run >/dev/null 2>&1 || true
            udevadm settle --timeout=10 || true
          fi
          still_missing=""
          for name in $(expected_arrays); do
            if [ -e "/dev/md/$name" ]; then
              klog "array $name is active"
            else
              still_missing="$still_missing $name"
            fi
          done
          if [ -n "$still_missing" ]; then
            klog "declared arrays are not running:$still_missing"
            if [ -s "$stash/storage-coherence" ]; then
              printf '%s\n' divergent > "$stash/storage-coherence"
            fi
          fi
          exit 0
        '';
      };

      boot.initrd.systemd.services."mount-var" = {
        requires = ["aos-storage-topology.service"];
        after = ["aos-storage-topology.service"];
      };
    })

    (lib.mkIf (!zfsState && measured) {
      boot.initrd.systemd.services."aos-var-crypt".after = ["aos-storage-topology.service"];
    })
  ];
}
