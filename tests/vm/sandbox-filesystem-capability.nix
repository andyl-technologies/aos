# Exact-kernel capability qualification, independent of full-system services.
{
  testing,
  pkgs,
}: let
  probeSource = builtins.path {
    path = ../sandbox/filesystem-capability-probe.c;
    name = "aos-sandbox-filesystem-capability-probe.c";
  };
in
  testing.mkVMTest {
    name = "sandbox-filesystem-kernel-capabilities";
    rootfsDeps = [probeSource pkgs.linux-headers pkgs.e2fsprogs pkgs.jq];
    memory = 256;
    testScript = ''
      test -c /dev/fuse
      echo 'Compiling the filesystem capability probe'
      cd /tmp
      gcc -std=c17 -Wall -Wextra -Werror \
        -isystem ${pkgs.linux-headers}/include ${probeSource} -o filesystem-probe
      unset LD_LIBRARY_PATH

      mkdir ext4 fuse
      echo 'Preparing an ext4 verity backing filesystem'
      truncate -s 128M ext4.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q -b 4096 -O verity ext4.img
      mount -o loop,nosuid,nodev ext4.img ext4
      trap 'umount /tmp/ext4' EXIT
      printf 'aos-fuse-passthrough-proof\n' > ext4/payload
      sync ext4/payload

      echo 'Qualifying fs-verity'
      ./filesystem-probe fs-verity /tmp/ext4/payload > verity.json
      ${pkgs.jq}/bin/jq -e '
        .schema_version == "aos.sandbox.fs-verity-proof/v1" and
        (.architecture == "x86_64" or .architecture == "aarch64") and
        .hash_algorithm == 1 and
        (.digest | test("^[0-9a-f]{64}$")) and
        .verity_flag == true and .write_open_denied == true and
        .write_open_errno != 0
      ' verity.json

      echo 'Qualifying FUSE backing-file passthrough'
      ./filesystem-probe fuse-passthrough /tmp/fuse /tmp/ext4/payload > passthrough.json
      ${pkgs.jq}/bin/jq -e --slurpfile verity verity.json '
        . == {
          schema_version: "aos.sandbox.fuse-passthrough-proof/v1",
          architecture: $verity[0].architecture,
          fuse_protocol: "7.45",
          passthrough_offered: true,
          backing_registered: true,
          passthrough_read: true,
          userspace_read_requests: 0
        }
      ' passthrough.json
      cat verity.json passthrough.json
      umount /tmp/ext4
      trap - EXIT
    '';
  }
