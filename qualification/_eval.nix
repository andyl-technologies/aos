##! Exposes typed options and evaluated policy for inspection and composition.
{
  lib,
  packageNames,
  nativeAdapterMatrix,
  modules ? [],
}:
lib.evalModules {
  inherit lib;
  specialArgs = {inherit nativeAdapterMatrix packageNames;};
  modules = (import ./modules) ++ modules;
}
