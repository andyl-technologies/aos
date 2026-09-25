# KVM qualification of the local four-journal and physical Cache cut.
{
  lib,
  testing,
  pkgs,
}: let
  probeSource = builtins.path {
    path = ../sandbox/filesystem-capability-probe.c;
    name = "aos-sandbox-filesystem-capability-probe.c";
  };
  verityProbe = pkgs.mkDerivation {
    pname = "aos-sandbox-cache-physical-join-verity-probe";
    version = "1";
    src = null;
    runtimeDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            -I${pkgs.linux-headers}/include ${probeSource} -o verity-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp verity-probe $out/bin/
        '';
      }
    ];
  };
  physicalJoinProbe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-cache-physical-join-vm-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-cache-physical-join-vm-probe";
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
  };
in
  # The daemon artifact must never carry the fixture-only Cache preparation API.
  assert !(builtins.elem "cache-physical-join-vm-fixture" pkgs."aos-sandboxd".passthru.cargoArtifactContract.buildFeatures);
  assert !(lib.hasInfix "cache-physical-join-vm-fixture" (builtins.readFile ../../pkgs/tools/aos-sandboxd.nix));
  testing.mkVMTest {
    name = "sandbox-cache-physical-join";
    rootfsDeps = [
      physicalJoinProbe
      verityProbe
      pkgs.coreutils
      pkgs.e2fsprogs
      pkgs.jq
      pkgs.util-linux
    ];
    memory = 512;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH

      mkdir -p /var/lib/aos/sandbox /var/lib/aos/sandboxd/cache-residency-authority
      chmod 0755 /var /var/lib /var/lib/aos /var/lib/aos/sandbox /var/lib/aos/sandboxd
      chmod 0700 /var/lib/aos/sandboxd/cache-residency-authority
      chown 811:811 /var/lib/aos/sandboxd/cache-residency-authority

      truncate -s 128M /tmp/cache-physical-join.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q -b 4096 -O verity /tmp/cache-physical-join.img
      mount -o loop,nosuid,nodev /tmp/cache-physical-join.img /var/lib/aos/sandbox
      trap 'umount /var/lib/aos/sandbox' EXIT

      mkdir -p \
        /var/lib/aos/sandbox/cache-residency-journals \
        /var/lib/aos/sandbox/cache-residency-objects
      chmod 0755 /var/lib/aos/sandbox
      chmod 0700 \
        /var/lib/aos/sandbox/cache-residency-journals \
        /var/lib/aos/sandbox/cache-residency-objects
      chown 811:811 \
        /var/lib/aos/sandbox/cache-residency-journals \
        /var/lib/aos/sandbox/cache-residency-objects

      printf 'cache-physical-join-verity-proof\n' \
        > /var/lib/aos/sandbox/cache-residency-objects/verity-witness
      sync /var/lib/aos/sandbox/cache-residency-objects/verity-witness
      ${verityProbe}/bin/verity-probe fs-verity \
        /var/lib/aos/sandbox/cache-residency-objects/verity-witness \
        > /tmp/cache-physical-join-verity.json
      ${pkgs.jq}/bin/jq -e '
        .schema_version == "aos.sandbox.fs-verity-proof/v1" and
        .hash_algorithm == 1 and
        (.digest | test("^[0-9a-f]{64}$")) and
        .verity_flag == true and .write_open_denied == true
      ' /tmp/cache-physical-join-verity.json
      cat /tmp/cache-physical-join-verity.json
      rm /var/lib/aos/sandbox/cache-residency-objects/verity-witness

      ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        ${physicalJoinProbe}/bin/aos-sandbox-cache-physical-join-vm-probe

      physical_device="$(stat -c %d /var/lib/aos/sandbox/cache-residency-objects)"
      test "$physical_device" = "$(stat -c %d /var/lib/aos/sandbox/cache-residency-journals)"
      test "$physical_device" = "$(stat -c %d /var/lib/aos/sandbox)"
      test "$(findmnt -n -o FSTYPE -T /var/lib/aos/sandbox)" = ext4
      test -s /var/lib/aos/sandbox/cache-residency-objects/owner-state
      test -f /var/lib/aos/sandbox/cache-residency-journals/state.journal
      for name in clock authority policy-hold; do
        test -s "/var/lib/aos/sandbox/cache-residency-journals/$name.journal"
      done
      umount /var/lib/aos/sandbox
      trap - EXIT
    '';
  }
