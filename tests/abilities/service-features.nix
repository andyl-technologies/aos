##! Checks the native manager-neutral feature schema and portable validation.
{lib, pkgs}: let
  checks = import ../effects/service-management.nix;
  sources = builtins.map builtins.readFile [
    ../../pkgs/system/_service-management/input.nix
    ../../pkgs/system/_service-management/types.nix
    ../../pkgs/system/_service-management/policy.nix
  ];
  platformNeutral = builtins.all (source:
    !lib.hasInfix "systemctl" source && !lib.hasInfix "systemd" source) sources;
in
  assert platformNeutral;
  assert builtins.all (value: value) (builtins.attrValues checks); true
