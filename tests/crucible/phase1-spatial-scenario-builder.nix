{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialScenarioBuilder",
  taskIds ? ["T-SPAT-15"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  workloadTest = builtins.readFile ../../crates/crucible/crucible-engine/tests/workload_parameterization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-15 completion names ScenarioBuilder";
        needle = "`ScenarioBuilder` now exposes";
      }
      {
        label = "T-SPAT-15 completion names gate";
        needle = "`checks.crucible.phase1.spatialScenarioBuilder`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/model.rs" model [
      {
        label = "node template type";
        needle = "pub struct NodeTemplate";
      }
      {
        label = "scenario builder type";
        needle = "pub struct ScenarioBuilder";
      }
      {
        label = "world template entry point";
        needle = "pub fn world(mut self, world: &World) -> Self";
      }
      {
        label = "node entry point";
        needle = "pub fn node(mut self, name: impl Into<String>, template: NodeTemplate) -> Self";
      }
      {
        label = "node-like template entry point";
        needle = "pub fn node_like(";
      }
      {
        label = "link entry point";
        needle = "pub fn link(mut self, left: impl Into<String>, right: impl Into<String>) -> Self";
      }
      {
        label = "plan layer entry point";
        needle = "pub fn plan(mut self, plan: Plan) -> Self";
      }
      {
        label = "properties layer entry point";
        needle = "pub fn properties(mut self, properties: Properties) -> Self";
      }
      {
        label = "property assertion entry point";
        needle = "pub fn property(mut self, assertion: AssertionDef) -> Self";
      }
      {
        label = "seed layer entry point";
        needle = "pub fn seed(mut self, seed: Seed) -> Self";
      }
      {
        label = "validated build entry point";
        needle = "pub fn build(self) -> Result<ScenarioDef, EngineError>";
      }
      {
        label = "builder composes through validated seed helper";
        needle = "world.scenario_def_with_plan_properties_and_seed(&plan, &properties, self.seed)";
      }
      {
        label = "unknown node template error";
        needle = "ScenarioBuilderUnknownNodeTemplate";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/src/model.rs" model [
      {
        label = "boot event authoring entry point";
        needle = "boot_event";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/tests/workload_parameterization.rs" workloadTest [
      {
        label = "builder produces validated concrete scenario values";
        needle = "fn scenario_def_with_template(";
      }
      {
        label = "test uses node template";
        needle = "NodeTemplate::fixed_icount";
      }
      {
        label = "test builds through ScenarioBuilder";
        needle = "crucible_engine::ScenarioBuilder::new()";
      }
      {
        label = "builder output changes with template material";
        needle = "assert_eq!(template_rootfs.id(), manual_rootfs.id())";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial scenario builder check";
        needle = "spatialScenarioBuilder = import ./phase1-spatial-scenario-builder.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial scenario builder check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-spatial-scenario-builder";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-spatial-scenario-builder";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible-engine \
              --test workload_parameterization \
              config_tree_change_changes_scenario_id_and_reproduces \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            component=scenario-builder
            builder_layers=world,plan,properties,seed
            node_templating=true
            world_templating=true
            boot_event_folding=false
            RESULT
          '';
        }
      ];
    }
