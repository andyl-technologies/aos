##! Evaluates the shared qualification policy with the AOS module fixed point.
{
  lib,
  packageNames,
  nativeAdapterMatrix,
  nativeOperationSpec,
  modules ? [],
}:
(import ./_eval.nix {inherit lib nativeAdapterMatrix nativeOperationSpec packageNames modules;}).config.qualification.export
