##! Derives the OS lower from canonical native file declarations.
{
  config,
  lib,
  ...
}: let
  effects = config.aos.abilities.configuration.operations.file.effects;
  eligible = lib.filterAttrs (_: effect:
    effect.enable
    && builtins.isString effect.input.path
    && lib.hasPrefix "/etc/" effect.input.path
    && builtins.isString effect.input.content)
  effects;
  entries =
    lib.mapAttrsToList (name: effect: {
      path = lib.removePrefix "/etc/" effect.input.path;
      owner = effect.contract.owner;
      value = {
        kind = "text";
        text = effect.input.content;
        inherit (effect.input) mode;
      };
    })
    eligible;
  paths = map (entry: entry.path) entries;
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
    };
  };
}
