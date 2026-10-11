##! Authors real marker edges before binding the original domain target graph.
{
  config,
  lib,
  ...
}: let
  operations = ["directory" "allocate" "persistentAllocate" "entry" "file" "ruleset"];
  cfg = config.aos.nativeDomainQualification;
  markers = config.aos.abilities.nativeDependencyBarrier.operations.ensure.effects;
  abilityFor = name:
    if name == "ruleset"
    then "networkPolicy"
    else if name == "file"
    then "configuration"
    else "filesystem";
  effectFor = name:
    if name == "ruleset"
    then "host"
    else "native-qualification";
  selected = name: config.aos.abilities.${abilityFor name}.operations.${name}.effects.${effectFor name};
  enabled = name:
    if name == "ruleset"
    then config.aos.networkPolicy.enable
    else cfg.enabled.${name};
  requests = name:
    lib.mkMerge [
      (lib.mkIf cfg.dependencyParents.${name} {
        "parent-${name}".name = "parent-${name}";
      })
      (lib.mkIf (enabled name) {
        "child-${name}" = {
          name = "child-${name}";
          parent = (selected name).outputs.resource;
        };
      })
    ];
  ordering = name: {
    ${abilityFor name}.operations.${name}.effects = lib.mkIf (enabled name) {
      ${effectFor name}.after = [markers."parent-${name}".outputs.resource];
    };
  };
in {
  options.aos.nativeDomainQualification.dependencyParents = lib.mkOption {
    type = lib.types.submodule {
      options = lib.genAttrs operations (_:
        lib.mkOption {
          type = lib.types.bool;
          default = true;
        });
    };
    default = {};
    description = "Qualification marker declarations retained until their controlled retirement.";
  };
  config.aos = {
    nativeDependencyBarrier.requests = lib.mkMerge (map requests operations);
    abilities = lib.mkMerge (map ordering operations);
  };
}
