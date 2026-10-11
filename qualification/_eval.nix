##! Exposes typed options and evaluated policy for inspection and composition.
{
  lib,
  packageNames,
  nativeAdapterMatrix,
  nativeOperationSpec,
  modules ? [],
}:
lib.evalModules {
  inherit lib;
  specialArgs = {inherit nativeAdapterMatrix nativeOperationSpec packageNames;};
  modules = (import ./modules) ++ modules;
}
