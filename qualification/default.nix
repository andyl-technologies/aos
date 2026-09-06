##! Evaluates the shared qualification policy with the AOS module fixed point.
{
  lib,
  packageNames,
  modules ? [],
}:
(import ./_eval.nix {inherit lib packageNames modules;}).config.qualification.export
