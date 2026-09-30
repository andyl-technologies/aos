##! Normalizes the native scenario registry and its complete operation cells.
{
  lib,
  policy ? builtins.fromJSON (builtins.readFile ../native-adapter-scenarios.json),
}: let
  postconditionsFor = scenario:
    lib.concatMap (group: policy.postcondition_groups.${group}) scenario.postcondition_groups
    ++ scenario.additional_postconditions;
  scenarios = map (scenario:
    builtins.removeAttrs scenario ["additional_postconditions" "postcondition_groups"]
    // {
      postconditions = map (name: {
        evidence_kind = policy.postcondition_kinds.${name};
        inherit name;
      }) (postconditionsFor scenario);
    })
  policy.scenarios;
  families = builtins.sort builtins.lessThan (lib.unique (map (scenario: scenario.family) scenarios));
  cellFor = surface: adapter: action: scenario: {
    id = "${adapter.adapter}/${adapter.operation.ability}/${adapter.operation.name}/${action}/${scenario.family}/${scenario.id}";
    matrix_schema = surface.matrix_schema;
    adapter = adapter.adapter;
    operation = {inherit (adapter.operation) ability name;};
    inherit action;
    scenario = {inherit (scenario) family id;};
    scope = adapter.scope;
    inherit (scenario) boundary failure predecessor candidate disposition applicability;
    postconditions = map (postcondition: postcondition.name) scenario.postconditions;
    postcondition_kinds = builtins.listToAttrs (map (postcondition: {
        name = postcondition.name;
        value = postcondition.evidence_kind;
      })
      scenario.postconditions);
    invalidated_by = surface.invalidation_dimensions;
  };
  cellsFor = surface:
    builtins.sort (left: right: builtins.lessThan left.id right.id) (
      lib.concatMap (
        adapter:
          lib.concatMap (
            action:
              map (cellFor surface adapter action)
              (builtins.filter (scenario: builtins.elem scenario.family adapter.conformance_families) surface.scenarios)
          )
          adapter.actions
      )
      surface.adapters
    );
in {
  inherit policy postconditionsFor scenarios families cellsFor;
}
