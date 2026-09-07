# Executable fs-verity and FUSE passthrough proof for the exact AOS kernel.
{
  mkSystem,
  pkgs,
  ...
}: let
  probe = pkgs.mkDerivation {
    pname = "aos-sandbox-filesystem-capability-probe";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            ${../sandbox/filesystem-capability-probe.c} \
            -o aos-sandbox-filesystem-capability-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-sandbox-filesystem-capability-probe $out/bin/
        '';
      }
    ];
    meta = {
      description = "Runtime proof for AOS fs-verity and FUSE passthrough";
      license = "Apache-2.0";
    };
  };

  system = mkSystem [
    ../../systems/server-test.nix
    {
      aos.image.budgets = {
        maxRootMiB = 768;
        maxDownloadMiB = 896;
      };
      environment.systemPackages = [
        pkgs.coreutils
        pkgs.e2fsprogs
        pkgs.util-linux
        probe
      ];
    }
  ];
in {
  name = "sandbox-filesystem-capability-proof";
  timeout = 300;
  bootTimeout = 180;

  machines.vm = {inherit system;};

  testScript = ''
    import json

    PROBE = "${probe}/bin/aos-sandbox-filesystem-capability-probe"
    TRUNCATE = "${pkgs.coreutils}/bin/truncate"
    SYNC = "${pkgs.coreutils}/bin/sync"
    MKFS_EXT4 = "${pkgs.e2fsprogs}/sbin/mkfs.ext4"
    MOUNT = "${pkgs.util-linux}/bin/mount"
    UMOUNT = "${pkgs.util-linux}/bin/umount"

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.succeed("test -c /dev/fuse")
    vm.succeed("mkdir -p /var/tmp/aos-fs-proof/ext4 /var/tmp/aos-fs-proof/fuse")
    vm.succeed(f"{TRUNCATE} -s 128M /var/tmp/aos-fs-proof/ext4.img")
    vm.succeed(f"{MKFS_EXT4} -F -q -b 4096 -O verity /var/tmp/aos-fs-proof/ext4.img")
    vm.succeed(
        f"{MOUNT} -o loop,nosuid,nodev /var/tmp/aos-fs-proof/ext4.img "
        "/var/tmp/aos-fs-proof/ext4"
    )
    vm.succeed(
        "printf 'aos-fuse-passthrough-proof\\n' > "
        "/var/tmp/aos-fs-proof/ext4/payload"
    )
    vm.succeed(f"{SYNC} /var/tmp/aos-fs-proof/ext4/payload")

    verity = json.loads(
        vm.succeed(
            f"{PROBE} fs-verity /var/tmp/aos-fs-proof/ext4/payload"
        )
    )
    assert verity["schema_version"] == "aos.sandbox.fs-verity-proof/v1", verity
    assert verity["architecture"] in ("x86_64", "aarch64"), verity
    assert verity["hash_algorithm"] == 1, verity
    assert len(verity["digest"]) == 64, verity
    assert verity["verity_flag"] is True, verity
    assert verity["write_open_denied"] is True, verity
    assert verity["write_open_errno"] != 0, verity

    passthrough = json.loads(
        vm.succeed(
            f"{PROBE} fuse-passthrough /var/tmp/aos-fs-proof/fuse "
            "/var/tmp/aos-fs-proof/ext4/payload"
        )
    )
    assert passthrough == {
        "schema_version": "aos.sandbox.fuse-passthrough-proof/v1",
        "architecture": verity["architecture"],
        "fuse_protocol": "7.45",
        "passthrough_offered": True,
        "backing_registered": True,
        "passthrough_read": True,
        "userspace_read_requests": 0,
    }, passthrough

    vm.succeed(f"{UMOUNT} /var/tmp/aos-fs-proof/ext4")
  '';
}
