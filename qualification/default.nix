##! Evaluates the shared qualification policy with the AOS module fixed point.
{
  lib,
  packageNames,
  # Callers that also build the package inventory pass the same list they
  # gave `pkgs/_platform-support.nix`, so both halves of the release contract
  # always defer the same platforms.
  deferredPlatforms ? import ./deferred-platforms.nix,
  modules ? [],
}:
(import ./_eval.nix {
  inherit lib packageNames;
  modules = [{qualification.deferredPlatforms = deferredPlatforms;}] ++ modules;
})
.config
.qualification
.export
