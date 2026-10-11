##! Preserves the configuration contract target using native typed lower inputs.
{
  pkgs,
  lib,
  system,
}: let
  checks = import ../../tests/effects/configuration-lower.nix {inherit pkgs lib;};
in
  assert builtins.all (value: value == true) (builtins.attrValues checks);
    pkgs.mkDerivation {
      pname = "aos-native-configuration-contract-check";
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
    }
