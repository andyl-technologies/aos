# Check a fixed Mount carrier mapper identity on two independent exact-kernel boots.
{
  pkgs,
  testing,
}: let
  carrier = pkgs.aosMountExecutableCarrierForKernel pkgs.linux;
  probeSource = builtins.path {
    path = ../sandbox/filesystem-capability-probe.c;
    name = "aos-sandbox-filesystem-capability-probe.c";
  };
  rootfs = testing.mkFirecrackerRootfs {
    pname = "mount-carrier-reboot";
    rootfsDeps = [
      pkgs.attr
      pkgs.cryptsetup
      pkgs.device-mapper
      pkgs.gawk
      pkgs.grep
      pkgs.linux-headers
      probeSource
    ];
    testScript = ''
      root_hash=
      for field in $(cat /proc/cmdline); do
        case "$field" in
          aos.carrier.roothash=*) root_hash="''${field#*=}" ;;
        esac
      done
      [[ "$root_hash" =~ ^[0-9a-f]{64}$ ]]

      ${pkgs.cryptsetup}/sbin/veritysetup verify \
        /dev/vdb /dev/vdc "$root_hash"
      verity_profile=$(${pkgs.cryptsetup}/sbin/veritysetup dump /dev/vdc)
      data_blocks=$(printf '%s\n' "$verity_profile" | ${pkgs.gawk}/bin/awk \
        '$1 == "Data" && $2 == "blocks:" { print $3 }')
      salt=$(printf '%s\n' "$verity_profile" | ${pkgs.gawk}/bin/awk \
        '$1 == "Salt:" { print $2 }')
      [[ "$data_blocks" =~ ^[1-9][0-9]*$ ]]
      [[ "$salt" =~ ^[0-9a-f]{64}$ ]]

      # The minimal rootfs has no device manager to populate mapper/control.
      ${pkgs.grep}/bin/grep -E '^[[:space:]]*252[[:space:]]+device-mapper$' /proc/devices
      ${pkgs.grep}/bin/grep -E '^[[:space:]]*236[[:space:]]+device-mapper$' /proc/misc
      mkdir -p /dev/mapper
      if [ ! -e /dev/mapper/control ]; then
        mknod -m 0600 /dev/mapper/control c 10 236
      fi
      test "$(stat -c '%t:%T' /dev/mapper/control)" = a:ec

      table="0 $((data_blocks * 8)) verity 1 /dev/vdb /dev/vdc 4096 4096 $data_blocks 1 sha256 $root_hash $salt"
      ${pkgs.device-mapper}/sbin/dmsetup \
        --noudevrules --noudevsync -r create aos-mount-carrier \
        --major 252 --minor 21 --table "$table"
      if [ ! -e /dev/mapper/aos-mount-carrier ]; then
        mknod -m 0600 /dev/mapper/aos-mount-carrier b 252 21
      fi
      test "$(stat -c '%t:%T' /dev/mapper/aos-mount-carrier)" = fc:15

      mkdir -p /mnt/carrier-stage1 /mnt/carrier-stage2
      mount -t ext4 -o ro,nosuid,nodev \
        /dev/mapper/aos-mount-carrier /mnt/carrier-stage1
      test "$(${pkgs.attr}/bin/getfattr --only-values \
        -n security.selinux /mnt/carrier-stage1)" = \
        system_u:object_r:root_t
      gcc -std=c17 -Wall -Wextra -Werror \
        -isystem ${pkgs.linux-headers}/include ${probeSource} -o /tmp/carrier-probe
      unset LD_LIBRARY_PATH
      launcher_digest=$(/tmp/carrier-probe measure-verity /mnt/carrier-stage1/launcher)
      daemon_digest=$(/tmp/carrier-probe measure-verity /mnt/carrier-stage1/daemon)
      [[ "$launcher_digest" =~ ^[0-9a-f]{64}$ ]]
      [[ "$daemon_digest" =~ ^[0-9a-f]{64}$ ]]

      launcher_identity=$(stat -c '%D:%i:%s:%a' /mnt/carrier-stage1/launcher)
      daemon_identity=$(stat -c '%D:%i:%s:%a' /mnt/carrier-stage1/daemon)
      test "''${launcher_identity%%:*}" = fc15
      test "''${daemon_identity%%:*}" = fc15
      test "$launcher_identity" != "$daemon_identity"

      mount --move /mnt/carrier-stage1 /mnt/carrier-stage2
      test "$(${pkgs.attr}/bin/getfattr --only-values \
        -n security.selinux /mnt/carrier-stage2)" = \
        system_u:object_r:root_t
      test "$(stat -c '%D:%i:%s:%a' /mnt/carrier-stage2/launcher)" = \
        "$launcher_identity"
      test "$(stat -c '%D:%i:%s:%a' /mnt/carrier-stage2/daemon)" = \
        "$daemon_identity"
      test "$(/tmp/carrier-probe measure-verity /mnt/carrier-stage2/launcher)" = \
        "$launcher_digest"
      test "$(/tmp/carrier-probe measure-verity /mnt/carrier-stage2/daemon)" = \
        "$daemon_digest"
      printf 'AOS_CARRIER_IDENTITY=%s:%s:%s:%s\n' \
        "$launcher_identity" "$daemon_identity" "$launcher_digest" "$daemon_digest"
      umount /mnt/carrier-stage2
      ${pkgs.device-mapper}/sbin/dmsetup \
        --noudevrules --noudevsync remove aos-mount-carrier
    '';
  };
in
  pkgs.mkDerivation {
    pname = "aos-vm-test-sandbox-mount-carrier-reboot";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.firecracker pkgs.grep];
    requiredSystemFeatures = ["kvm"];

    phases = [
      {
        name = "test";
        script = ''
          set -eu

          report_failure() {
            status=$?
            if [ "$status" -ne 0 ]; then
              for log in serial-clean-*.log firecracker-*.log; do
                if [ -f "$log" ]; then
                  tail -n 80 "$log" >&2
                fi
              done
            fi
          }
          trap report_failure EXIT
          root_hash=$(cat ${carrier}/carrier.root-hash)
          printf '%s\n' "$root_hash" | grep -Eq '^[0-9a-f]{64}$'

          run_boot() {
            round=$1
            cp ${rootfs} "rootfs-$round.img"
            chmod u+w "rootfs-$round.img"
            kernel_image=$(find ${pkgs.linux.vmlinux}/boot \
              -maxdepth 1 -name 'vmlinux-*' -print)
            test -n "$kernel_image"

            cat > "firecracker-$round.json" << EOF
          {
            "boot-source": {
              "kernel_image_path": "$kernel_image",
              "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet dm_mod.major=252 aos.carrier.roothash=$root_hash"
            },
            "drives": [
              {
                "drive_id": "rootfs",
                "path_on_host": "$PWD/rootfs-$round.img",
                "is_root_device": true,
                "is_read_only": false,
                "cache_type": "Unsafe",
                "io_engine": "Sync"
              },
              {
                "drive_id": "carrier-data",
                "path_on_host": "${carrier}/carrier.ext4",
                "is_root_device": false,
                "is_read_only": true,
                "cache_type": "Unsafe",
                "io_engine": "Sync"
              },
              {
                "drive_id": "carrier-hash",
                "path_on_host": "${carrier}/carrier.hash",
                "is_root_device": false,
                "is_read_only": true,
                "cache_type": "Unsafe",
                "io_engine": "Sync"
              }
            ],
            "machine-config": {
              "vcpu_count": 1,
              "mem_size_mib": 512,
              "smt": false,
              "track_dirty_pages": false,
              "huge_pages": "None"
            }
          }
          EOF

            unset LD_LIBRARY_PATH
            firecracker --no-api --config-file "firecracker-$round.json" \
              > "serial-$round.log" 2> "firecracker-$round.log"
            tr -d '\r' < "serial-$round.log" > "serial-clean-$round.log"
            grep -Fq 'TEST_RESULT:PASS' "serial-clean-$round.log"
            test "$(grep -c '^AOS_CARRIER_IDENTITY=' "serial-clean-$round.log")" -eq 1
            grep '^AOS_CARRIER_IDENTITY=' "serial-clean-$round.log" \
              > "identity-$round"
          }

          run_boot first
          run_boot second
          cmp identity-first identity-second
          mkdir -p "$out"
          cp identity-first serial-clean-first.log serial-clean-second.log "$out/"
        '';
      }
    ];

    meta = {
      description = "Two-boot fixed device and inode Mount carrier proof";
      license = "Apache-2.0";
      platforms = ["x86_64-linux"];
    };
  }
