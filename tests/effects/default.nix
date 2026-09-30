##! Focused infrastructure checks independent of unmigrated system consumers.
{pkgs}: let
  lib = import ../../lib {system = pkgs.bash.system;};
  fixture = import ./deployment-fixture.nix {inherit pkgs lib;};
  checks = {
    modules = import ./modules.nix;
    packages = (import ./packages.nix).checks;
    stages = import ./stages.nix;
    frozenHandler = import ./frozen-handler.nix;
  };
in
  builtins.deepSeq checks (pkgs.mkDerivation {
    pname = "aos-effect-module-checks";
    version = "0";
    src = null;
    runtimeDeps = [fixture];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          echo PASS > "$out/result"
          ln -s ${fixture}/fixture.json "$out/deployment.json"
        '';
      }
    ];
  })
