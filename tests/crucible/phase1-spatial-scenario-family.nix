{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialScenarioFamily",
  taskIds ? ["T-SPAT-17"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  familyTest = builtins.readFile ../../crates/crucible/tests/gate_coverage_guided_fuzzing.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-17 completion names ScenarioFamily";
        needle = "`ScenarioFamily`";
      }
      {
        label = "T-SPAT-17 completion names gate";
        needle = "`checks.crucible.phase1.spatialScenarioFamily`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "scenario family type";
        needle = "pub struct ScenarioFamily";
      }
      {
        label = "family parameter space type";
        needle = "pub struct FamilySpace";
      }
      {
        label = "family params type";
        needle = "pub struct FamilyParams";
      }
      {
        label = "pinned scenario type";
        needle = "pub struct PinnedScenario";
      }
      {
        label = "pinned configuration type";
        needle = "pub struct PinnedConfiguration";
      }
      {
        label = "topology shape axis";
        needle = "pub enum TopologyShape";
      }
      {
        label = "seed space axis";
        needle = "pub struct SeedSpace";
      }
      {
        label = "family instantiate validates params";
        needle = "self.space.validate_params(params)?";
      }
      {
        label = "finite family cardinality";
        needle = "pub fn cardinality(&self) -> Result<u64, EngineError>";
      }
      {
        label = "family returns pinned scenario";
        needle = "pub fn instantiate(&self, params: FamilyParams) -> Result<PinnedScenario, EngineError>";
      }
      {
        label = "finite sampling rejects exhausted index";
        needle = "parameter: \"sample_index\"";
      }
      {
        label = "pinned scenario reconstructs scenario def";
        needle = "pub fn scenario_def(&self) -> ScenarioDef";
      }
      {
        label = "pinned scenario retains concrete form with config";
        needle = "pub fn genesis_configuration(&self) -> PinnedConfiguration";
      }
      {
        label = "family space canonicalizes topology shapes";
        needle = "topology_shapes.sort();";
      }
      {
        label = "family contains only declared finite axes";
        needle = "self.seeds.contains(params.seed)";
      }
      {
        label = "random topology is deterministic from seed";
        needle = "crucible.model.scenario-family.random-topology.v1";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "ScenarioFamily re-export";
        needle = "ScenarioFamily";
      }
      {
        label = "PinnedScenario re-export";
        needle = "PinnedScenario";
      }
      {
        label = "PinnedConfiguration re-export";
        needle = "PinnedConfiguration";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_coverage_guided_fuzzing.rs" familyTest [
      {
        label = "focused scenario family reproducibility test";
        needle = "fn gate_coverage_guided_fuzzing_is_seeded_and_reproducible()";
      }
      {
        label = "test instantiates concrete family parameters";
        needle = "assert!(family.space().contains(iteration.params));";
      }
      {
        label = "test covers bounded finite sampling";
        needle = "SeedSpace::explicit(vec![Seed::from_u64(0x11)])?";
      }
      {
        label = "test uses topology size and shape axes";
        needle = "TopologySizeRange::new(2, 2)?";
      }
      {
        label = "test reduces each concrete configuration";
        needle = "reduce(&iteration.configuration.def, iteration.schedule()).is_ok()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial scenario family check";
        needle = "spatialScenarioFamily = import ./phase1-spatial-scenario-family.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial scenario family check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-scenario-family";
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
          name = "run-spatial-scenario-family";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-scenario-family-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_coverage_guided_fuzzing \
              gate_coverage_guided_fuzzing_is_seeded_and_reproducible \
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
            component=scenario-family
            deterministic_sampling=true
            pinned_instance_only=true
            finite_axes=seed,topology-size,topology-shape
            RESULT
          '';
        }
      ];
    }
