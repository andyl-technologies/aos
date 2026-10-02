##! Checks the selected native Hub package against shared service policy fixtures.
{
  pkgs,
  lib,
  mkSystem,
  serverModule,
}: let
  checks = import ../effects/hub-consumer.nix;
  contract = builtins.all (value: value) (builtins.attrValues checks);
in
  assert contract;
    pkgs.mkDerivation {
      pname = "registry-hub-module-check";
      version = "0";
      src = null;
      inherit contract;
      phases = [
        {
          name = "check";
          script = ''
            : "$contract"
            mkdir -p "$out"
            printf '%s\n' ok > "$out/result"
          '';
        }
      ];
    }
