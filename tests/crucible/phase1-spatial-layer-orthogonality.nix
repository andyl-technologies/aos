{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialLayerOrthogonality",
  taskIds ? ["T-SPAT-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-2 completion names test";
        needle = "`scenario_layers_stay_structurally_orthogonal`";
      }
      {
        label = "T-SPAT-2 completion names gate";
        needle = "`checks.crucible.phase1.spatialLayerOrthogonality`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "scenario builder type";
        needle = "pub struct ScenarioBuilder";
      }
      {
        label = "builder stores world nodes separately";
        needle = "nodes: Vec<PendingScenarioNode>";
      }
      {
        label = "builder stores world links separately";
        needle = "links: Vec<PendingScenarioLink>";
      }
      {
        label = "builder stores complete plan separately";
        needle = "plan: Option<Plan>";
      }
      {
        label = "builder stores plan entries separately";
        needle = "plan_entries: Vec<PlanEntry>";
      }
      {
        label = "builder stores properties separately";
        needle = "properties: Option<Properties>";
      }
      {
        label = "builder stores assertions separately";
        needle = "assertions: Vec<AssertionDef>";
      }
      {
        label = "builder stores seed separately";
        needle = "seed: Seed";
      }
      {
        label = "world node entry point";
        needle = "pub fn node(mut self, name: impl Into<String>, template: NodeTemplate) -> Self";
      }
      {
        label = "world link entry point";
        needle = "pub fn link(mut self, left: impl Into<String>, right: impl Into<String>) -> Self";
      }
      {
        label = "transport link entry point";
        needle = "pub fn link_with_transport(";
      }
      {
        label = "plan layer entry point";
        needle = "pub fn plan(mut self, plan: Plan) -> Self";
      }
      {
        label = "plan-entry layer entry point";
        needle = "pub fn plan_entry(mut self, entry: PlanEntry) -> Self";
      }
      {
        label = "properties layer entry point";
        needle = "pub fn properties(mut self, properties: Properties) -> Self";
      }
      {
        label = "assertion layer entry point";
        needle = "pub fn property(mut self, assertion: AssertionDef) -> Self";
      }
      {
        label = "seed layer entry point";
        needle = "pub fn seed(mut self, seed: Seed) -> Self";
      }
      {
        label = "build composes world first";
        needle = "let world = World::from_nodes_and_links(self.build_nodes()?, self.build_links()?)?;";
      }
      {
        label = "build validates plan against world";
        needle = "let plan = self.build_plan(&world)?;";
      }
      {
        label = "build validates properties against world";
        needle = "let properties = self.build_properties(&world)?;";
      }
      {
        label = "build composes seed separately";
        needle = "world.scenario_def_with_plan_properties_and_seed(&plan, &properties, self.seed)";
      }
      {
        label = "plan validation uses world";
        needle = "Plan::from_entries_for_world(world, self.plan_entries.clone())";
      }
      {
        label = "properties validation uses world";
        needle = "Properties::from_assertions_for_world(world, self.assertions.clone())";
      }
      {
        label = "scenario tuple material keeps world ref";
        needle = "world_ref={}";
      }
      {
        label = "scenario tuple material keeps plan ref";
        needle = "plan_ref={}";
      }
      {
        label = "scenario tuple material keeps properties ref";
        needle = "properties_ref={}";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "boot event folding API";
        needle = "boot_event";
      }
      {
        # Scoped to the call form `entrypoint(`. The bare substring `entrypoint`
        # also matched the canonical-material string literal `"trigger=entrypoint"`
        # in event_material (a serialization label for a triggerless/entrypoint
        # event, NOT a layer-folding API); the open-paren anchor still bans a real
        # entrypoint-folding API while allowing that string. Rescoped 2026-07-09.
        label = "entrypoint folding API";
        needle = "entrypoint(";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "focused orthogonality test";
        needle = "fn scenario_layers_stay_structurally_orthogonal()";
      }
      {
        label = "test builds through builder";
        needle = "ScenarioBuilder::new()";
      }
      {
        label = "test checks serialized world layer";
        needle = "toml.contains(\"[[world.link]]\")";
      }
      {
        label = "test checks serialized plan layer";
        needle = "toml.contains(\"[[plan.entry]]\")";
      }
      {
        label = "test checks serialized properties layer";
        needle = "toml.contains(\"[[properties.assertion]]\")";
      }
      {
        label = "test checks serialized seed layer";
        needle = "toml.contains(\"seed = \\\"0x\")";
      }
      {
        label = "test rejects missing-link fault";
        needle = "Err(EngineError::PlanFaultUnknownLink";
      }
      {
        label = "test rejects assertion-declared topology";
        needle = "Err(EngineError::PropertyPredicateUnknownNode";
      }
      {
        label = "test rejects link-declared missing node";
        needle = "Err(EngineError::WorldLinkUnknownNode";
      }
      {
        label = "test forbids boot events";
        needle = "!toml.contains(\"boot_event\")";
      }
      {
        label = "test forbids entrypoint folding";
        needle = "!toml.contains(\"entrypoint\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial layer orthogonality check";
        needle = "spatialLayerOrthogonality = import ./phase1-spatial-layer-orthogonality.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial layer orthogonality check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-layer-orthogonality";
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
          name = "run-spatial-layer-orthogonality";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-layer-orthogonality-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              scenario_layers_stay_structurally_orthogonal \
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
            component=spatial-layer-orthogonality
            layers=world,plan,properties,seed
            boot_event_folding=false
            entrypoint_folding=false
            RESULT
          '';
        }
      ];
    }
