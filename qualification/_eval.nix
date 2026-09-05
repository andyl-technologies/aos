##! Exposes typed options and evaluated policy for inspection and composition.
{
  lib,
  packageNames,
  modules ? [],
}:
lib.evalModules {
  inherit lib;
  specialArgs = {inherit packageNames;};
  modules = (import ./modules) ++ modules;
}
