##! Checks set semantics at ordinary service module merges and strict wire bounds.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "service-set-fixture";
    outPath = toString (import ./_fixture-payload.nix "service-set-fixture");
    meta.mainProgram = "service-set-fixture";
  };
  command = argument: {
    executable = {
      path = "${package}/bin/command";
      arguments = [argument];
    };
    ignore_failure = false;
  };
  base = {config, ...}: {
    aos.abilities.ready.operations.ensure = {
      input.options = {};
      result.options.resource = lib.mkOption {type = lib.types.str;};
      handler.program = package;
      effects = {
        alpha.input = {};
        omega.input = {};
      };
    };
    aos.abilities.serviceManagement.operations.realize.handler.program = package;
    aos.services.example = {
      enable = true;
      dependencies.prerequisites = [
        config.aos.abilities.ready.operations.ensure.effects.omega.outputs.resource
        config.aos.abilities.ready.operations.ensure.effects.alpha.outputs.resource
      ];
      dependencies.after = ["omega.target" "alpha.target"];
      lifecycle = {
        description = "Set merge fixture";
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command "middle")];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 1000;
        remain_after_exit = false;
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
    };
  };
  contribution = {config, ...}: {
    aos.services.example.dependencies.prerequisites = [
      config.aos.abilities.ready.operations.ensure.effects.alpha.outputs.resource
      config.aos.abilities.ready.operations.ensure.effects.omega.outputs.resource
    ];
    aos.services.example.dependencies.after = ["alpha.target"];
    aos.services.example.lifecycle.start = lib.mkBefore [(command "before")];
  };
  evaluate = additions:
    lib.evalModules {
      inherit lib;
      modules = [../../lib/effects/module.nix ../../pkgs/system/_service-management/module.nix base contribution] ++ additions;
    };
  evaluated = evaluate [{aos.services.example.lifecycle.start = lib.mkAfter [(command "after")];}];
  effect = evaluated.config.aos.abilities.serviceManagement.operations.realize.effects.example;
  prerequisites = effect.input.dependencies.prerequisites;
  projected = evaluated.config.aos.abilities.serviceManagement.operations.realize.documentation.inputType;
  constraint = projected.fields.dependencies.value.fields.prerequisites;
  oversized = evaluate [{aos.services.example.dependencies.prerequisites = lib.mkForce (builtins.genList (index: "dependency-${toString index}") 257);}];
  contextual = evaluate [{aos.services.example.dependencies.prerequisites = lib.mkForce ["${package}/b" "${package}/a" "${package}/a"];}];
  contextualValues = contextual.config.aos.services.example.dependencies.prerequisites;
in {
  oppositeContributionsMergeOnce = builtins.length prerequisites == 2;
  canonicalReferenceOrdering = map builtins.toJSON prerequisites == builtins.sort builtins.lessThan (map builtins.toJSON prerequisites);
  orderedDependenciesStayOrdered = effect.input.dependencies.after == ["omega.target" "alpha.target" "alpha.target"];
  commandOrderMarkersStayOrdered = map (value: value.executable.arguments) effect.input.lifecycle.start == [["before"] ["middle"] ["after"]];
  boundsRemainEnforced = !(builtins.tryEval (builtins.deepSeq oversized.config.aos.services.example.dependencies.prerequisites true)).success;
  strictWireSchemaRemainsCanonical = constraint.unique && constraint.canonical_order && constraint.max_items == 256;
  contextSurvivesOnlyLookupNormalization = contextualValues == ["${package}/a" "${package}/b"] && builtins.getContext (builtins.head contextualValues) != {};
}
