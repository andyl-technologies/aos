{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionBake",
  taskIds ? ["T-EXEC-8" "T-PAT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  realization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
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
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" realization [
      {
        label = "QEMU bake executor";
        needle = "pub trait QemuVmBakeExecutor";
      }
      {
        label = "QEMU bake API";
        needle = "pub fn bake_qemu_genesis_vm";
      }
      {
        label = "only QEMU bake invokes cold boot executor";
        needle = "executor.cold_boot_to_ready_and_savevm(world)";
      }
      {
        label = "QEMU bake entrypoint test";
        needle = "qemu_bake_is_the_only_cold_boot_entry_point";
      }
      {
        label = "hot genesis load avoids cold boot test";
        needle = "qemu_instantiate_loads_baked_genesis_for_genesis_without_cold_boot";
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
        label = "T-PAT-9 completion names model bake";
        needle = "`crucible::bake`";
      }
      {
        label = "T-PAT-9 completion names QEMU bake";
        needle = "`bake_qemu_genesis_vm`";
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
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
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
              --target-dir "$TMPDIR/crucible-execution-bake-qemu-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              qemu_bake_is_the_only_cold_boot_entry_point \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-bake-qemu-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              qemu_instantiate_loads_baked_genesis_for_genesis_without_cold_boot \
              -- --test-threads=1

            if grep -R -n -E 'cold[_ -]?boot|ColdBoot|cold_boot_to_ready|boot_to_ready' crates/*/src \
              | grep -v '^crates/crucible-qemu/src/realization.rs:' \
              | grep -v '^crates/crucible-harness/' \
              | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//' \
              > "$TMPDIR/production-cold-boot-markers.txt"; then
              cat "$TMPDIR/production-cold-boot-markers.txt" >&2
              echo "unexpected production cold-boot marker outside the QEMU bake coordinator" >&2
              exit 1
            fi

            sed -n '1,/^#\[cfg(test)\]/p' crates/crucible-qemu/src/realization.rs \
              > "$TMPDIR/qemu-realization-production.rs"
            cold_boot_symbol_count="$(
              grep -n 'cold_boot_to_ready_and_savevm' "$TMPDIR/qemu-realization-production.rs" \
                | wc -l \
                | tr -d ' '
            )"
            if [ "$cold_boot_symbol_count" != "2" ]; then
              grep -n 'cold_boot_to_ready_and_savevm' "$TMPDIR/qemu-realization-production.rs" >&2 || true
              echo "expected exactly one QEMU bake executor declaration and one bake call" >&2
              exit 1
            fi
            cold_boot_call_count="$(
              grep -n 'executor.cold_boot_to_ready_and_savevm(world)' "$TMPDIR/qemu-realization-production.rs" \
                | wc -l \
                | tr -d ' '
            )"
            if [ "$cold_boot_call_count" != "1" ]; then
              grep -n 'executor.cold_boot_to_ready_and_savevm(world)' "$TMPDIR/qemu-realization-production.rs" >&2 || true
              echo "expected exactly one production cold-boot executor call" >&2
              exit 1
            fi
            sed -n '/^pub fn bake_qemu_genesis_vm/,/^}/p' "$TMPDIR/qemu-realization-production.rs" \
              | grep -q 'executor.cold_boot_to_ready_and_savevm(world)' || {
                echo "the single production cold-boot executor call must be inside bake_qemu_genesis_vm" >&2
                exit 1
              }
            grep -n -E 'cold_boot|fn [A-Za-z0-9_]*boot|pub fn [A-Za-z0-9_]*boot' \
              "$TMPDIR/qemu-realization-production.rs" \
              | grep -v 'fn cold_boot_to_ready_and_savevm' \
              | grep -v 'pub fn bake_qemu_genesis_vm' \
              | grep -v 'executor.cold_boot_to_ready_and_savevm(world)' \
              > "$TMPDIR/qemu-realization-cold-boot-markers.txt" || true
            if grep -q . "$TMPDIR/qemu-realization-cold-boot-markers.txt"; then
              cat "$TMPDIR/qemu-realization-cold-boot-markers.txt" >&2
              echo "unexpected production cold-boot entry point in QEMU realization" >&2
              exit 1
            fi
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
            qemu_bake=cold-boot-to-ready-savevm
            pattern_PAT_12=cold-boot-confined-to-bake
            production_cold_boot_lint=bake-only
            first_run_realization=loadvm-baked-genesis
            qemu_hot_genesis_test=no-cold-boot
            RESULT
          '';
        }
      ];
    }
