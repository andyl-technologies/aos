# VM probe for initializer-owned detached mounts crossing a process boundary.
{
  mkSystem,
  pkgs,
  ...
}: let
  probe = pkgs.mkDerivation {
    pname = "aos-root-initializer-mount-transfer-probe";
    version = "0.1.0";
    src = null;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          $CC -std=c11 -Wall -Wextra -Werror -O2 \
            ${../sandbox/root-initializer-mount-transfer-probe.c} \
            -o "$out/bin/aos-root-initializer-mount-transfer-probe"
        '';
      }
    ];
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [probe];
    }
  ];
in {
  name = "sandbox-root-initializer-mount-transfer";
  timeout = 300;

  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    result = vm.succeed("${probe}/bin/aos-root-initializer-mount-transfer-probe")
    print(result)
    assert "cross-userns=0 detached transfer attached:" in result, result
    assert "cross-userns=1 detached transfer attached:" in result, result
  '';
}
