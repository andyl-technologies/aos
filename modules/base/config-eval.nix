##! Projects image trust and measurement policy into native boot deployment.
{
  config,
  lib,
  pkgs,
  initrdAbilityEvaluation ? null,
  packageModulesAvailable ? false,
  ...
}: let
  preparation =
    if initrdAbilityEvaluation == null
    then null
    else initrdAbilityEvaluation.config.aos.abilities.storageProvisioning.operations.prepare.effects.system or null;
  metadataSourceRequired = preparation != null && preparation.enable;
  binding = pkgs.writeTextFile {
    name = "aos-boot-metadata-binding";
    destination = "/binding.json";
    text = builtins.toJSON ({
        schema = "aos.boot.metadata-binding";
        version = 1;
        inherit metadataSourceRequired;
      }
      // lib.optionalAttrs metadataSourceRequired {
        scope = initrdAbilityEvaluation.config.aos.activation.scope;
        effect = builtins.hashString "sha256" (builtins.toJSON preparation.contract.identity);
      });
  };
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/tools/_aos-metadata-provider/policy.nix];
  options.system.build.bootMetadataBinding = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    readOnly = true;
    internal = true;
    description = "Image-authenticated binding to the exact native initrd metadata authorization result.";
  };
  config = {
    system.build.bootMetadataBinding = binding;
  };
}
