##! Checks native BIND listener ownership and package service composition.
{
  lib,
  pkgs,
}:
builtins.all (value: value) (builtins.attrValues (import ../../pkgs/networking/_bind/native-tests.nix {
  inherit lib pkgs;
  self = pkgs.bind;
}))
