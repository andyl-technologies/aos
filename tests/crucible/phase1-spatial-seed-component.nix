{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialSeedComponent",
  taskIds ? ["T-SPAT-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  canonicalRust = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  decisionRust = builtins.readFile ../../crates/crucible/src/decision.rs;
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-14 completion names seed root entropy";
        needle = "`Seed` now carries the 256-bit";
      }
      {
        label = "T-SPAT-14 completion names scenario composition";
        needle = "`World::scenario_def_with_plan_properties_and_seed`";
      }
      {
        label = "T-SPAT-14 completion names gate";
        needle = "`checks.crucible.phase1.spatialSeedComponent`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "seed type";
        needle = "pub struct Seed";
      }
      {
        label = "seed is 256-bit";
        needle = "bytes: [u8; 32]";
      }
      {
        label = "seed byte constructor";
        needle = "pub fn from_bytes(bytes: [u8; 32]) -> Self";
      }
      {
        label = "seed integer constructor";
        needle = "pub fn from_u64(value: u64) -> Self";
      }
      {
        label = "seed decision RNG";
        needle = "pub fn decision_rng(self) -> DecisionRng";
      }
      {
        label = "seed stream seed API";
        needle = "pub fn stream_seed(self, stream: &RngStreamId) -> u64";
      }
      {
        label = "seed stream fork API";
        needle = "pub fn fork_stream(self, stream: &RngStreamId) -> DecisionStream";
      }
      {
        label = "all seed bytes hashed into RNG root";
        needle = "\"crucible.model.seed-decision-rng-root.v1\"";
      }
      {
        label = "seed material helper";
        needle = "fn seed_material(seed: Seed) -> String";
      }
      {
        label = "world seeded stream projection";
        needle = "pub fn seeded_rng_streams(&self, seed: Seed) -> Vec<SeededRngStream>";
      }
      {
        label = "seeded stream type";
        needle = "pub struct SeededRngStream";
      }
      {
        label = "explicit seed scenario helper";
        needle = "pub fn scenario_def_with_seed(&self, seed: Seed) -> ScenarioDef";
      }
      {
        label = "full seed scenario helper";
        needle = "pub fn scenario_def_with_plan_properties_and_seed";
      }
      {
        label = "scenario seed domain";
        needle = "\"crucible.model.world-plan-properties-seed-scenario.v1\"";
      }
      {
        label = "scenario component material";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "scenario includes seed material";
        needle = "seed_material(seed)";
      }
      {
        label = "stored scenario definition carries seed material";
        needle = "seed_material(def.seed)";
      }
    ]
    ++ lib.optionals (hasInfix "pub id: ContentHash,\n    /// The root entropy carried by this scenario definition." model) [
      "crates/crucible/src/model.rs: ScenarioDef id field must stay private"
    ]
    # Scoped to the ScenarioDef seed field via its unique doc comment. The bare
    # `pub seed: Seed,\n}` form matched four OTHER structs that legitimately carry a
    # public seed as their last field; the doc-comment anchor pins the check to
    # ScenarioDef's own field. Rescoped 2026-07-09.
    ++ lib.optionals (hasInfix "/// The root entropy carried by this scenario definition.\n    pub seed: Seed," model) [
      "crates/crucible/src/model.rs: ScenarioDef seed field must stay private"
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" canonicalRust [
      {
        label = "configuration identity includes scenario seed";
        needle = "write_seed(&mut hasher, configuration.def.seed());";
      }
      {
        label = "reduced state identity includes scenario seed";
        needle = "write_seed(&mut hasher, def.seed());";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" decisionRust [
      {
        label = "decision recorder roots RNG in scenario seed";
        needle = "let rng = configuration.def.seed().decision_rng();";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "seed content-address test";
        needle = "seed_is_scenario_identity_and_name_hashed_stream_root";
      }
      {
        label = "test checks explicit default seed compatibility";
        needle = "scenario_def_with_seed(Seed::default())";
      }
      {
        label = "test checks seed affects scenario identity";
        needle = "world.scenario_def_with_seed(other_seed)";
      }
      {
        label = "test checks generic seeded scenario identity";
        needle = "generic_seeded.id(), generic_other_seed.id()";
      }
      {
        label = "test checks seed changes configuration identity";
        needle = "Configuration::genesis(generic_other_seed.clone()).id()";
      }
      {
        label = "test checks seed changes reduced state identity";
        needle = "reduce(&generic_other_seed, &Schedule::empty())";
      }
      {
        label = "test checks all seed bytes perturb streams";
        needle = "tail_changed_seed.stream_seed(&node_stream)";
      }
      {
        label = "test checks stream domain separation";
        needle = "seed.stream_seed(&link_stream)";
      }
      {
        label = "test checks unrelated world edit stream stability";
        needle = "expanded_world.seeded_rng_streams(seed)";
      }
      {
        label = "test checks stream draws stay stable";
        needle = "expanded_node_draws.next_u64()";
      }
      {
        label = "test checks recorder uses scenario seed";
        needle = "DecisionRecorder::new(Configuration::genesis(world.scenario_def_with_seed(seed)))";
      }
      {
        label = "test checks every seed byte contributes";
        needle = "for index in 0..32";
      }
      {
        label = "test checks added node gets its own stream";
        needle = "RngStreamId::for_node(\"c\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial seed component check";
        needle = "spatialSeedComponent = import ./phase1-spatial-seed-component.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial seed component check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-seed-component";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-spatial-seed-component";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-seed-component-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              seed_is_scenario_identity \
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
            related_gates=gate:e2e-determinism
            spatial_graph_task=seed-root-entropy
            component=seed
            scenario_identity=world-ref-plus-plan-ref-plus-properties-ref-plus-seed
            stream_forking=name-hash
            unrelated_world_edits_perturb_existing_streams=false
            RESULT
          '';
        }
      ];
    }
