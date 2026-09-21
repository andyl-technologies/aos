{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialScenarioBuilder",
  taskIds ? ["T-SPAT-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  workloadTest = builtins.readFile ../../crates/crucible/tests/workload_parameterization.rs;
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
    ++ failuresFor "crates/crucible/src/model.rs" model [
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
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "boot event authoring entry point";
        needle = "boot_event";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_parameterization.rs" workloadTest [
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
        needle = "crucible::ScenarioBuilder::new()";
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
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-scenario-builder";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-spatial-scenario-builder";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-scenario-builder-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
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
