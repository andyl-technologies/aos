##! Resolves the declarative qualification policy into its offline contract.
{
  lib,
  packageNames,
  nativeAdapterMatrix,
  nativeOperationSpec,
  # Inventory and qualification use the same reviewed platform deferral list.
  deferredPlatforms ? import ./deferred-platforms.nix,
  modules ? [],
}:
(import ./_eval.nix {
  inherit lib nativeAdapterMatrix nativeOperationSpec packageNames;
  modules = [{qualification.deferredPlatforms = deferredPlatforms;}] ++ modules;
})
.config
.qualification
.export
