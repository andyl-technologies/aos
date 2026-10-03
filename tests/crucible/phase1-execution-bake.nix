{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionBake",
  taskIds ? ["T-EXEC-8" "T-PAT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  bakedGenesis = builtins.readFile ../../crates/crucible-daemon/src/qemu_baked_genesis.rs;
  freshLifecycle = builtins.readFile ../../crates/crucible-daemon/src/qemu_campaign_lifecycle.rs;
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-8 completion note";
        needle = "Completed by `crates/crucible/src/model.rs`: `bake`";
      }
      {
        label = "T-EXEC-8 cold boot lint note";
        needle = "production cold-boot lint";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world scenario bridge";
        needle = "pub fn scenario_def(&self) -> ScenarioDef";
      }
      {
        label = "implemented bake signature";
        needle = "pub fn bake(world: &World) -> Result<GenesisCheckpoint, EngineError>";
      }
      {
        label = "world-derived genesis";
        needle = "let def = world.scenario_def();";
      }
      {
        label = "genesis configuration identity";
        needle = "let genesis = Configuration::genesis(def);";
      }
      {
        label = "content-addressed checkpoint node domain";
        needle = "crucible.dag-store.checkpoint-node.v1";
      }
      {
        label = "fat genesis checkpoint";
        needle = "CheckpointKind::Fat";
      }
      {
        label = "bake passes genesis configuration to checkpoint constructor";
        needle = "        &genesis,";
      }
      {
        label = "baked genesis carries node blob refs";
        needle = "baked_node_blobs(world)";
      }
      {
        label = "scenario component material helper";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "stable hash hex helper";
        needle = "fn content_hash_hex(hash: ContentHash) -> String";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "bake placeholder";
        needle = "operation: \"bake\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "bake deterministic sharing test";
        needle = "bake_content_addresses_world_as_shared_fat_genesis_checkpoint";
      }
      {
        label = "bake instantiate test";
        needle = "baked_world_genesis_instantiates_as_first_resume";
      }
      {
        label = "generated world fixture";
        needle = "fn generated_world(seed: u64) -> World";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_baked_genesis.rs" bakedGenesis [
      {
        label = "production baked-genesis capture entry point";
        needle = "pub(crate) fn capture_production_baked_genesis<F>(";
      }
      {
        label = "production baked-genesis capture uses fresh lifecycle";
        needle = "capture_fresh_genesis_checkpoint_candidate(factory, source, context)?;";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_campaign_lifecycle.rs" freshLifecycle [
      {
        label = "fresh genesis capture lifecycle entry point";
        needle = "pub(crate) fn capture_fresh_genesis_checkpoint_candidate<F>(";
      }
      {
        label = "fresh capture starts from the exact genesis configuration";
        needle = "let genesis = Configuration::genesis(scenario.clone());";
      }
      {
        label = "fresh capture requires exact checkpoint readiness";
        needle = "lifecycle.exact_checkpoint_ready()";
      }
      {
        label = "fresh capture obtains the authenticated attempt checkpoint";
        needle = ".capture_attempt_checkpoint(context)";
      }
      {
        label = "fresh capture always shuts down the lifecycle";
        needle = "let cleanup = lifecycle.shutdown();";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes bake execution check";
        needle = "executionBake = import ./phase1-execution-bake.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-9 confines cold boot to baked capture";
        needle = "cold boot remains inside baked";
      }
      {
        label = "T-PAT-9 completion names execution bake gate";
        needle = "`checks.crucible.phase1.executionBake`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution bake check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-bake";
      version = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      runtimeDeps = [pkgs.sqlite];
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed

        pkgs.pkg-config
        pkgs.sqlite
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
          name = "run-execution-bake";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-bake-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              bake \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-bake-daemon-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-daemon \
              --lib \
              baked_catalog_routes_by_the_complete_world_scenario_basis \
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
            related_gates=gate:content-address,gate:replay-oracle
            model_bake=world-derived-fat-genesis-checkpoint
            production_bake=authenticated-fresh-lifecycle-v9-descriptor-capture
            pattern_PAT_12=cold-boot-confined-to-bake
            production_cold_boot_lint=bake-only
            first_run_realization=v9-descriptor-baked-genesis
            baked_catalog_basis=world-plus-scenario
            RESULT
          '';
        }
      ];
    }
