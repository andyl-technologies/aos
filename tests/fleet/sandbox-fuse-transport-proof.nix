# Real-kernel metadata, DAC, and teardown proof for the installed FUSE bridge.
{
  mkSystem,
  pkgs,
  ...
}: let
  probe = pkgs.mkDerivation {
    pname = "aos-fuse-transport-probe";
    version = "1";
    src = null;
    runtimeDeps = [pkgs.aos-fuse-transport];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -I${pkgs.aos-fuse-transport}/include \
            ${../sandbox/fuse-transport-probe.c} \
            -L${pkgs.aos-fuse-transport}/lib -laos-fuse-transport \
            -o aos-fuse-transport-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-fuse-transport-probe $out/bin/
        '';
      }
    ];
    meta = {
      description = "Real-kernel qualification for the AOS FUSE metadata bridge";
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
      environment.systemPackages = [probe];
    }
  ];
in {
  name = "sandbox-fuse-transport-proof";
  timeout = 300;
  bootTimeout = 180;
  machines.vm = {inherit system;};
  testScript = ''
    import json

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.succeed("test -c /dev/fuse")
    proof = json.loads(vm.succeed("${probe}/bin/aos-fuse-transport-probe"))
    assert proof.pop("architecture") in ("x86_64", "aarch64"), proof
    assert proof == {
        "schema_version": "aos.sandbox.fuse-transport-proof/v1",
        "metadata": True,
        "mount_flags": True,
        "cross_uid_dac": True,
        "read_only": True,
        "idle_survives": True,
        "cancelled": True,
        "borrowed_fds_retained": True,
        "destroyed_once": True,
        "disconnected": True,
        "unmounted": True,
    }, proof
  '';
}
