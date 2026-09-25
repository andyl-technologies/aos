##! Build exact systemd and Mount executable inodes with kernel fs-verity.
{
  mkDerivation,
  lib,
  hostPackages,
  buildPackages,
  linux,
  systemd,
  aos-sandbox-mountd,
}: let
  sealTool = mkDerivation {
    pname = "aos-mount-carrier-seal";
    version = "1";
    src = ./_aos-mount-carrier-seal.c;
    buildDeps = [buildPackages.linux-headers];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Os -Wall -Wextra -Werror -static \
            -isystem ${buildPackages.linux-headers}/include \
            -Wl,-z,noexecstack "$src" -o aos-mount-carrier-seal
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 0555 aos-mount-carrier-seal "$out/bin/"
        '';
      }
    ];
    meta = {
      description = "Kernel fs-verity sealer for the immutable Mount carrier";
      license = "Apache-2.0";
    };
  };

  firecrackerRootfs =
    (import ../../lib/testing/firecracker.nix {
      pkgs = hostPackages;
      inherit lib;
    })
    .mkFirecrackerRootfs {
      pname = "mount-executable-carrier-build";
      rootfsDeps = [sealTool];
      testScript = ''
        mkdir -p /mnt/carrier
        mount -t ext4 -o rw,nosuid,nodev /dev/vdb /mnt/carrier

        launcher_digest=$(${sealTool}/bin/aos-mount-carrier-seal \
          seal /mnt/carrier/launcher system_u:object_r:init_exec_t)
        daemon_digest=$(${sealTool}/bin/aos-mount-carrier-seal \
          seal /mnt/carrier/daemon system_u:object_r:bin_t)
        test "$(stat -c %i /mnt/carrier/launcher)" != \
          "$(stat -c %i /mnt/carrier/daemon)"

        sync
        umount /mnt/carrier
        mount -t ext4 -o ro,nosuid,nodev /dev/vdb /mnt/carrier
        test "$launcher_digest" = "$(${sealTool}/bin/aos-mount-carrier-seal \
          measure /mnt/carrier/launcher system_u:object_r:init_exec_t)"
        test "$daemon_digest" = "$(${sealTool}/bin/aos-mount-carrier-seal \
          measure /mnt/carrier/daemon system_u:object_r:bin_t)"
        printf 'AOS_CARRIER_LAUNCHER_SHA256=%s\n' "$launcher_digest"
        printf 'AOS_CARRIER_DAEMON_SHA256=%s\n' "$daemon_digest"
        umount /mnt/carrier
      '';
    };
in
  mkDerivation {
    pname = "aos-mount-executable-carrier";
    version = "1";
    src = null;
    buildDeps = [
      buildPackages.coreutils
      buildPackages.cryptsetup
      buildPackages.e2fsprogs
      buildPackages.firecracker
      buildPackages.gawk
      buildPackages.grep
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    requiredSystemFeatures = ["kvm"];

    phases = [
      {
        name = "build";
        script = ''
          set -eu

          mkdir carrier-tree
          install -m 0555 ${systemd}/lib/systemd/systemd carrier-tree/launcher
          install -m 0555 ${aos-sandbox-mountd}/bin/aos-sandbox-mountd carrier-tree/daemon
          mkfs.ext4 -F -q -b 4096 -O verity -d carrier-tree carrier.ext4 128M

          # debugfs edits the offline ext4 metadata; the guest checks these
          # exact fields before fs-verity seals either executable.
          for name in launcher daemon; do
            debugfs -w -R "set_inode_field /$name uid 0" carrier.ext4
            debugfs -w -R "set_inode_field /$name gid 0" carrier.ext4
          done
          debugfs -w -R \
            'ea_set /launcher security.selinux system_u:object_r:init_exec_t' \
            carrier.ext4
          debugfs -w -R \
            'ea_set /daemon security.selinux system_u:object_r:bin_t' \
            carrier.ext4

          cp ${firecrackerRootfs} rootfs.img
          chmod u+w rootfs.img
          kernel_image=$(find ${linux.vmlinux}/boot -maxdepth 1 -name 'vmlinux-*' -print)
          test -n "$kernel_image"
          test "$(printf '%s\n' "$kernel_image" | wc -l)" -eq 1

          cat > firecracker.json << EOF
          {
            "boot-source": {
              "kernel_image_path": "$kernel_image",
              "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet"
            },
            "drives": [
              {
                "drive_id": "rootfs",
                "path_on_host": "$PWD/rootfs.img",
                "is_root_device": true,
                "is_read_only": false,
                "cache_type": "Unsafe",
                "io_engine": "Sync"
              },
              {
                "drive_id": "carrier",
                "path_on_host": "$PWD/carrier.ext4",
                "is_root_device": false,
                "is_read_only": false,
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
          vm_result=0
          firecracker --no-api --config-file firecracker.json \
            > serial.log 2> firecracker.log || vm_result=$?
          tr -d '\r' < serial.log > serial-clean.log
          if [ "$vm_result" -ne 0 ] || \
             ! grep -Fq 'TEST_RESULT:PASS' serial-clean.log; then
            tail -n 60 serial-clean.log >&2
            tail -n 60 firecracker.log >&2
            echo 'Mount carrier sealing guest failed' >&2
            exit 1
          fi
          test "$(grep -c '^AOS_CARRIER_LAUNCHER_SHA256=[0-9a-f]\{64\}$' serial-clean.log)" -eq 1
          test "$(grep -c '^AOS_CARRIER_DAEMON_SHA256=[0-9a-f]\{64\}$' serial-clean.log)" -eq 1
          e2fsck -fn carrier.ext4

          veritysetup format \
            --hash sha256 --data-block-size 4096 --hash-block-size 4096 \
            --salt 0000000000000000000000000000000000000000000000000000000000000021 \
            --uuid bdfb6fc9-0000-4000-8000-000000000021 \
            carrier.ext4 carrier.hash > carrier-verity-profile
          root_hash=$(awk '$1 == "Root" && $2 == "hash:" { print $3 }' \
            carrier-verity-profile)
          printf '%s\n' "$root_hash" | grep -Eq '^[0-9a-f]{64}$'
          veritysetup verify carrier.ext4 carrier.hash "$root_hash"

          mkdir -p "$out"
          install -m 0444 carrier.ext4 carrier.hash "$out/"
          printf '%s\n' "$root_hash" > "$out/carrier.root-hash"
          chmod 0444 "$out/carrier.root-hash"
          install -m 0444 serial-clean.log carrier-verity-profile "$out/"
        '';
      }
    ];

    passthru = {
      kernel = linux;
      launcher = systemd;
      daemon = aos-sandbox-mountd;
    };

    meta = {
      description = "KVM-sealed systemd and Mount executable ext4 carrier";
      license = "Apache-2.0";
      platforms = ["x86_64-linux"];
    };
  }
