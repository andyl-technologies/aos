##! Authored immutable-root policy shared by both replayable boot scopes.
{
  config,
  lib,
  options,
  ...
}: {
  config = lib.mkMerge [
    (lib.optionalAttrs (options.aos.packageRuntime or {} ? configurationEvaluation) {
      aos.packageRuntime.configurationEvaluation = {
        enable = lib.mkDefault true;
        measuredBoot = lib.mkDefault config.aos.boot.secureBoot.measuredBoot.enable;
        pcrPublicKey = lib.mkDefault (config.aos.boot.secureBoot.measuredBoot._effectivePcrPublicKey or null);
      };
    })
    (lib.optionalAttrs (options.aos.config or {} ? unitGraph) {
      aos.config.unitGraph.enable = lib.mkDefault true;
    })
    (lib.optionalAttrs (options.aos.security ? verity) {
      aos.security.verity.enable = lib.mkDefault true;
    })
    (lib.optionalAttrs (options.aos.boot.initrd or {} ? abilityHandoff) {
      aos.boot.initrd.abilityHandoff.enable = lib.mkDefault true;
    })
  ];
}
