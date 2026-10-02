##! Projects early services' consumed configuration from canonical file inputs.
{
  config,
  lib,
  ...
}: let
  services = import ./bootstrap-services.nix {
    inherit config lib;
    pkgs = {};
  };
  references = builtins.concatMap (service: service.dependencyValues) (builtins.attrValues services);
  effects = lib.filterAttrs (_: effect:
    effect.enable
    && (builtins.elem effect.outputs.resource references || builtins.elem effect.outputs.path references))
  config.aos.abilities.configuration.operations.file.effects;
  project = name: effect: let
    input = effect.input;
    relativePath = lib.removePrefix "/etc/" input.path;
    normalized = builtins.all (part: !(builtins.elem part ["" "." ".."])) (lib.splitString "/" relativePath);
    content =
      if builtins.isString input.content
      then input.content
      else if builtins.all builtins.isString input.fragments
      then lib.concatStringsSep "" input.fragments
      else throw "Early service configuration '${name}' requires runtime values and cannot enter the image.";
  in
    if input.format != "text" || !builtins.isString input.path || !lib.hasPrefix "/etc/" input.path || !normalized
    then throw "Early service configuration '${name}' must declare literal text beneath /etc."
    else if !(builtins.elem input.owner [null "root"]) || !(builtins.elem input.group [null "root"])
    then throw "Early service configuration '${name}' requires an identity unavailable to the image file projection."
    else {
      path = relativePath;
      owner = effect.contract.owner;
      value = {
        kind = "text";
        text = content;
        inherit (input) mode;
      };
    };
  entries = lib.mapAttrsToList project effects;
  paths = map (entry: entry.path) entries;
  checked =
    if builtins.length paths == builtins.length (lib.unique paths)
    then entries
    else throw "Early service configuration effects must own distinct image paths.";
in {
  filesystemEntries = builtins.listToAttrs (map (entry: lib.nameValuePair entry.path entry.value) checked);
  ownership.filesystemEntries = builtins.listToAttrs (map (entry: lib.nameValuePair entry.path entry.owner) checked);
}
