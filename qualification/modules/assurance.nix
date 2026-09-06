##! Composes target assurance obligations and validates their admission phases.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification;
  types = import ./_types.nix {inherit lib;};
  functions = target:
    if target.kind == "image"
    then ["image-installation" "image-lifecycle" "image-update-recovery"]
    else ["container-lifecycle"];
  observation = target:
    if target.kind == "image"
    then "image-observation"
    else "container-observation";
  obligations = name: target:
    lib.mkIf target.required {
      "${name}-functional" = {
        target = name;
        requirements = functions target;
        minimum_assurance = "A2";
        phase = "staging";
        blocks_release = true;
      };
      "${name}-qualified" = {
        target = name;
        requirements = functions target ++ [(observation target)];
        minimum_assurance = "A3";
        phase = "complete";
        blocks_release = true;
      };
    };
  requiredCoverage = name: target: phase: assurance:
    builtins.any (claim:
      claim.target
      == name
      && claim.phase == phase
      && claim.minimum_assurance == assurance
      && claim.blocks_release
      && builtins.all (id: builtins.elem id claim.requirements)
      (functions target ++ lib.optional (phase == "complete") (observation target)))
    (builtins.attrValues cfg.claims);
in {
  options.qualification.claims = lib.mkOption {
    type = lib.types.attrsOf types.claim;
    default = {};
    description = "Scoped assurance obligations composed from targets and functional requirements.";
  };
  config.qualification = {
    claims = lib.mkMerge (lib.mapAttrsToList obligations cfg.targets);
    assertions = [
      {
        assertion = builtins.all (claim:
          builtins.hasAttr claim.target cfg.targets
          && claim.requirements != []
          && builtins.all (id: builtins.hasAttr id cfg.requirements) claim.requirements
          && (claim.minimum_assurance != "A3" || claim.phase == "complete"))
        (builtins.attrValues cfg.claims);
        message = "Claims require known targets/functions and A3 may only be admitted at completion.";
      }
      {
        assertion = builtins.all (name: let
          target = cfg.targets.${name};
        in
          !target.required || (requiredCoverage name target "staging" "A2" && requiredCoverage name target "complete" "A3"))
        (builtins.attrNames cfg.targets);
        message = "Required targets retain release-blocking functional and complete observation claims.";
      }
    ];
  };
}
