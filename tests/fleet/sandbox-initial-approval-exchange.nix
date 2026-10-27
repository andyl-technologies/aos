# Native transport proof; no installed producer, policy or TPM authority.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  ...
} @ args: let
  installedSystem = (import ./sandbox-host-phase0-readiness.nix args).machines.vm.system;
  installedKernel = installedSystem.config.system.build.kernel;

  probe = pkgs.mkCargoPackage {
    pname = "aos-initial-approval-exchange-test";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-linux --test initial-approval-exchange --features kernel-tests"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.jq];
    runtimeDeps = [];
    postBuild = import ./_cargo-libtest-artifact.nix {
      inherit lib pkgs;
      crate = "aos-sandbox-linux";
      target = "initial-approval-exchange";
      kind = "test";
      destination = "native-tests/initial-approval-exchange";
    };
    postInstall = ''
      install -D -m 0755 native-tests/initial-approval-exchange "$out/bin/initial-approval-exchange"
    '';
  };

  fixtureSystem = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [probe];
      aos.kernel._extraConfigFragments = lib.mkForce installedSystem.config.aos.kernel._extraConfigFragments;
    }
  ];
  system =
    if toString fixtureSystem.config.system.build.kernel == toString installedKernel
    then fixtureSystem
    else throw "initial approval transport must use the installed Host kernel";
in {
  name = "sandbox-initial-approval-exchange";
  timeout = 300;
  bootTimeout = 180;
  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    result = vm.succeed("${probe}/bin/initial-approval-exchange", timeout=90)
    assert "finite initial approval transport: five native cases PASS" in result, result
  '';
}
