##! Focused infrastructure checks independent of unmigrated system consumers.
{pkgs}: let
  checks = {
    modules = import ./modules.nix;
    stages = import ./stages.nix;
    frozenHandler = import ./frozen-handler.nix;
  };
in
  builtins.deepSeq checks (pkgs.mkDerivation {
    pname = "aos-effect-module-checks";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  })
