##! Evaluates the shared qualification policy with the AOS module fixed point.
{
  lib,
  packageNames,
  nativeAdapterMatrix,
  modules ? [],
}:
(import ./_eval.nix {inherit lib nativeAdapterMatrix packageNames modules;}).config.qualification.export
