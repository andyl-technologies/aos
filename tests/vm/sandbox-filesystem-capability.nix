# Exact-kernel capability qualification, independent of full-system services.
{
  lib,
  testing,
  pkgs,
}: let
  probeSource = builtins.path {
    path = ../sandbox/filesystem-capability-probe.c;
    name = "aos-sandbox-filesystem-capability-probe.c";
  };
  rustBackingProbe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-verity-backing-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-verity-backing-probe --bin aos-sandbox-verity-backing-probe";
    # The executable needs the real ext4/fs-verity fixture below, not build-time
    # mount privilege. It links only its Linux boundary and ordinary runtime.
    doCheck = false;
    buildDeps = [];
    runtimeDeps = [];
  };
in
  testing.mkVMTest {
    name = "sandbox-filesystem-kernel-capabilities";
    rootfsDeps = [probeSource rustBackingProbe pkgs.linux-headers pkgs.e2fsprogs pkgs.jq];
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

      # This measured expectation is supplied by the trusted test coordinator;
      # it does not demonstrate a production publication-authorization catalog.
      # Run last because the owned-descriptor lifetime check unlinks payload.
      measurement=$(${pkgs.jq}/bin/jq -r .digest verity.json)
      ${rustBackingProbe}/bin/aos-sandbox-verity-backing-probe \
        /tmp/ext4 "$measurement" > backing.json
      ${pkgs.jq}/bin/jq -e '
        . == {
          schema_version: "aos.sandbox.verity-backing-proof/v1",
          read_verified: true,
          identity_verified: true,
          mapping_verified: true,
          wrong_size_rejected: true,
          over_limit_rejected: true,
          wrong_digest_rejected: true,
          unsealed_rejected: true,
          symlink_rejected: true,
          unlinked_pin_verified: true
        }
      ' backing.json
      cat backing.json
      umount /tmp/ext4
      trap - EXIT
    '';
  }
