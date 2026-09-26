# Qualify the immutable executable carrier substrate on the exact AOS kernel.
{
  lib,
  testing,
  pkgs,
}: let
  probeSource = builtins.path {
    path = ../sandbox/filesystem-capability-probe.c;
    name = "aos-sandbox-filesystem-capability-probe.c";
  };
in
  testing.mkVMTest {
    name = "sandbox-mount-executable-carrier";
    rootfsDeps = [
      probeSource
      pkgs.cryptsetup
      pkgs.e2fsprogs
      pkgs.gawk
      pkgs.jq
      pkgs.linux-headers
      pkgs.util-linux
    ];
    memory = 256;
    testScript = ''
      cd /tmp
      gcc -std=c17 -Wall -Wextra -Werror \
        -isystem ${pkgs.linux-headers}/include ${probeSource} -o carrier-probe
      unset LD_LIBRARY_PATH
      if ./carrier-probe measure-verity carrier-probe; then
        echo 'unsealed executable passed fs-verity measurement' >&2
        exit 1
      fi

      truncate -s 128M carrier.ext4
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q -b 4096 -O verity carrier.ext4
      mkdir carrier-build carrier-stage1 carrier-stage2
      mount -o loop,nosuid,nodev carrier.ext4 carrier-build

      # Two names with the same bytes still require distinct sealed inodes.
      cp carrier-probe carrier-build/launcher
      cp carrier-probe carrier-build/daemon
      chmod 0555 carrier-build/launcher carrier-build/daemon
      sync carrier-build/launcher carrier-build/daemon
      ./carrier-probe fs-verity carrier-build/launcher > launcher.json
      ./carrier-probe fs-verity carrier-build/daemon > daemon.json
      launcher_digest=$(${pkgs.jq}/bin/jq -r .digest launcher.json)
      daemon_digest=$(${pkgs.jq}/bin/jq -r .digest daemon.json)
      test "$launcher_digest" = "$daemon_digest"
      test "$(stat -c %i carrier-build/launcher)" != \
        "$(stat -c %i carrier-build/daemon)"
      sync
      umount carrier-build

      ${pkgs.cryptsetup}/sbin/veritysetup format \
        --hash sha256 --data-block-size 4096 --hash-block-size 4096 \
        --salt 0000000000000000000000000000000000000000000000000000000000000021 \
        --uuid bdfb6fc9-0000-4000-8000-000000000021 \
        carrier.ext4 carrier.hash > carrier-verity.txt
      root_hash=$(${pkgs.gawk}/bin/awk \
        '$1 == "Root" && $2 == "hash:" { print $3 }' carrier-verity.txt)
      [[ "$root_hash" =~ ^[0-9a-f]{64}$ ]]
      ${pkgs.cryptsetup}/sbin/veritysetup verify \
        carrier.ext4 carrier.hash "$root_hash"

      data_loop=$(${pkgs.util-linux}/sbin/losetup -f --show carrier.ext4)
      hash_loop=$(${pkgs.util-linux}/sbin/losetup -f --show carrier.hash)
      ${pkgs.cryptsetup}/sbin/veritysetup open \
        "$data_loop" aos-mount-carrier "$hash_loop" "$root_hash"
      mount -t ext4 -o ro,nosuid,nodev \
        /dev/mapper/aos-mount-carrier carrier-stage1

      for name in launcher daemon; do
        expected=$(${pkgs.jq}/bin/jq -r .digest "$name.json")
        observed=$(./carrier-probe measure-verity "carrier-stage1/$name")
        test "$observed" = "$expected"
        test "$(stat -c '%u:%g' "carrier-stage1/$name")" = 0:0
        test "$(stat -c %a "carrier-stage1/$name")" = 555
        test "$(stat -c %h "carrier-stage1/$name")" = 1
      done
      launcher_identity=$(stat -c '%D:%i:%s:%a' carrier-stage1/launcher)
      daemon_identity=$(stat -c '%D:%i:%s:%a' carrier-stage1/daemon)
      test "$launcher_identity" != "$daemon_identity"
      carrier-stage1/launcher measure-verity carrier-stage1/daemon \
        > executed-measurement
      test "$(< executed-measurement)" = "$daemon_digest"

      # Moving the retained mount across the root handoff must retain raw
      # st_dev and inode identity, not merely equal file contents.
      mount --move carrier-stage1 carrier-stage2
      test "$(stat -c '%D:%i:%s:%a' carrier-stage2/launcher)" = \
        "$launcher_identity"
      test "$(stat -c '%D:%i:%s:%a' carrier-stage2/daemon)" = \
        "$daemon_identity"
      test "$(./carrier-probe measure-verity carrier-stage2/launcher)" = \
        "$launcher_digest"
      test "$(./carrier-probe measure-verity carrier-stage2/daemon)" = \
        "$daemon_digest"
      carrier-stage2/daemon measure-verity carrier-stage2/launcher \
        > executed-after-move
      test "$(< executed-after-move)" = "$launcher_digest"

      umount carrier-stage2
      ${pkgs.cryptsetup}/sbin/veritysetup close aos-mount-carrier
      ${pkgs.util-linux}/sbin/losetup -d "$data_loop" "$hash_loop"

      # The backing image must be authenticated as a whole because per-file
      # fs-verity does not protect ext4 names or unrelated metadata.
      printf X | dd of=carrier.ext4 bs=1 seek=65536 conv=notrunc status=none
      if ${pkgs.cryptsetup}/sbin/veritysetup verify \
        carrier.ext4 carrier.hash "$root_hash"; then
        echo 'tampered carrier image passed dm-verity verification' >&2
        exit 1
      fi
    '';
  }
