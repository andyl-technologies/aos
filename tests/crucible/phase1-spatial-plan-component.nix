{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPlanComponent",
  taskIds ? ["T-SPAT-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-12 completion names independent plan hash";
        needle = "`Plan` carries one event";
      }
      {
        label = "T-SPAT-12 completion names scenario composition";
        needle = "`World::scenario_def_with_plan`";
      }
      {
        label = "T-SPAT-12 completion names gate";
        needle = "`checks.crucible.phase7.gates.signalFaultSystem`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "private plan identity field";
        needle = "pub(super) id: ContentHash,";
      }
      {
        label = "plan content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "plan hash domain";
        needle = "\"crucible.model.plan.v5\"";
      }
      {
        label = "plan canonical entry helper";
        needle = "fn from_canonical_parts(graph: EventGraph, fault_signals: FaultSignalPlan)";
      }
      {
        label = "world-validated event graph";
        needle = "validate_event_graph_plan";
      }
      {
        label = "plan material helper";
        needle = "fn plan_material(plan: &Plan) -> String";
      }
      {
        label = "signal plan identity enters canonical material";
        needle = "fault_signals.id().to_hex()";
      }
      {
        label = "world-plan scenario helper";
        needle = "pub fn scenario_def_with_plan(&self, plan: &Plan) -> Result<ScenarioDef, EngineError>";
      }
      {
        label = "scenario world-plan domain";
        needle = "\"crucible.model.world-plan-properties-seed-scenario.v1\"";
      }
      {
        label = "scenario component material";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "scenario includes world component hash";
        needle = "content_hash_hex(canonical_world_identity(world))";
      }
      {
        label = "scenario includes plan component hash";
        needle = "content_hash_hex(plan.content_hash())";
      }
      {
        label = "scenario includes empty properties compatibility";
        needle = "Ok(self.scenario_def_from_components(plan, &Properties::empty(), Seed::default()))";
      }
      {
        label = "world validates plan before scenario composition";
        needle = "plan.validate_for_world(self)?;";
      }
    ]
    ++ lib.optionals (hasInfix ''
        pub struct Plan {
            /// The independently content-addressed plan identity.
        pub id: ContentHash,
      ''
      model) [
      "crates/crucible/src/model.rs: plan identity field must not be public"
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "plan content-address regression";
        needle = "fn plan_content_address_preserves_declared_event_order()";
      }
      {
        label = "declared event order affects canonical bytes";
        needle = "assert_ne!(plan.canonical_bytes(), reordered_plan.canonical_bytes());";
      }
      {
        label = "declared event order affects plan identity";
        needle = "assert_ne!(plan.content_hash(), reordered_plan.content_hash());";
      }
      {
        label = "reuse and scenario sensitivity regression";
        needle = "spatial_components_have_independent_content_addresses_and_cross_reuse";
      }
      {
        label = "incompatible world rejection";
        needle = "incompatible_world.scenario_def_with_plan(&plan)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial plan component check";
        needle = "spatialPlanComponent = import ./phase1-spatial-plan-component.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial plan component check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-plan-component";
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
          name = "run-spatial-plan-component";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-plan-component-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              plan_content_address \
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
            related_gates=gate:content-address,gate:e2e-determinism
            spatial_graph_task=orthogonal-plan-component
            component=plan
            canonical_order=declared-event-order-and-signal-binding-identity
            scenario_identity=world-ref-plus-plan-ref
            RESULT
          '';
        }
      ];
    }
