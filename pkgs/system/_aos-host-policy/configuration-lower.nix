##! Derives the OS lower from canonical native file declarations.
{
  config,
  lib,
  ...
}: let
  literalText = import ./literal-text.nix;
  effects = config.aos.abilities.configuration.operations.file.effects;
  declarations = lib.filterAttrs (_: effect:
    effect.enable
    && builtins.isString effect.input.path
    && lib.hasPrefix "/etc/" effect.input.path)
  effects;
  eligible = lib.filterAttrs (_: effect: literalText effect.input != null) declarations;
  fileEffect = effect: {
    id = builtins.hashString "sha256" (builtins.toJSON effect.contract.identity);
    inherit (effect) lifetime;
  };
  entries =
    lib.mapAttrsToList (name: effect: {
      path = lib.removePrefix "/etc/" effect.input.path;
      owner = effect.contract.owner;
      value = {
        kind = "text";
        text = literalText effect.input;
        inherit (effect.input) mode;
      };
    })
    eligible;
  paths = lib.mapAttrsToList (_: effect: lib.removePrefix "/etc/" effect.input.path) declarations;
  uniqueEntries =
    if builtins.length paths != builtins.length (lib.unique paths)
    then throw "native configuration file effects must own distinct /etc paths"
    else entries;
in {
  # Only literal inputs enter the baseline. References to secrets or other
  # effect results remain live file operations after the overlay is mounted.
  config = lib.mkIf ((config.aos.boot.stage or "host") == "host") {
    aos.configurationLower = {
      files = builtins.listToAttrs (map (entry: lib.nameValuePair entry.path entry.value) uniqueEntries);
      ownership.files = builtins.listToAttrs (map (entry: lib.nameValuePair entry.path entry.owner) uniqueEntries);
      # The retained lower must preserve the declaring effect's lifetime when
      # its package disappears, including after the volatile upper is lost.
      fileEffects = builtins.listToAttrs (lib.mapAttrsToList (_: effect:
        lib.nameValuePair (lib.removePrefix "/etc/" effect.input.path) (fileEffect effect))
      declarations);
      retiredEffects = config.aos.activation.retire;
    };
  };
}
