{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.memoryConditionLeaf",
  taskIds ? ["T-TRIG-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  memoryTest = builtins.readFile ../../crates/crucible/tests/memory_condition_leaf.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-6 completion note";
        needle = "Completed by `checks.crucible.phase4.memoryConditionLeaf`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "MemoryPredicate predicate";
        needle = "MemoryPredicate {\n        /// Node whose memory or register is sampled.";
      }
      {
        label = "MemPlace type";
        needle = "pub enum MemPlace";
      }
      {
        label = "MemoryWidth type";
        needle = "pub enum MemoryWidth";
      }
      {
        label = "MemoryCmp type";
        needle = "pub enum MemoryCmp";
      }
      {
        label = "memory constructor";
        needle = "pub fn memory_predicate(node: NodeId, place: MemPlace, cmp: MemoryCmp, value: u64) -> Self";
      }
      {
        label = "memory TOML";
        needle = "PredicateTomlKind::MemoryPredicate";
      }
      {
        label = "memory place TOML";
        needle = "enum MemPlaceToml";
      }
      {
        label = "memory binary tag";
        needle = "writer.write_u8(14);";
      }
      {
        label = "memory place binary";
        needle = "fn write_mem_place_binary";
      }
      {
        label = "memory material";
        needle = "mem_place_material(place)";
      }
      {
        label = "memory validates nodes";
        needle = "Predicate::MemoryPredicate { node, .. }";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "resolved memory place";
        needle = "pub enum ResolvedMemPlace";
      }
      {
        label = "memory observable constructor";
        needle = "pub fn memory_sample";
      }
      {
        label = "memory sample explicit evaluation time";
        needle = "at: VirtualTime";
      }
      {
        label = "memory observable payload";
        needle = "ObservableEventPayload::MemorySample";
      }
      {
        label = "memory carries sample icount";
        needle = "sample_icount: Icount";
      }
      {
        label = "memory place resolution hook";
        needle = "fn resolve_mem_place";
      }
      {
        label = "test evaluator memory resolution injection";
        needle = "pub fn with_resolved_mem_places";
      }
      {
        label = "MemoryPredicate evaluation";
        needle = "Condition::MemoryPredicate";
      }
      {
        label = "memory matcher";
        needle = "fn memory_predicate_matches";
      }
      {
        label = "memory comparison function";
        needle = "fn memory_cmp_matches";
      }
      {
        label = "physical conservative default";
        needle = "ResolvedMemPlace::physical_address(*address, width.bytes())";
      }
      {
        label = "virtual requires host resolution";
        needle = "MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. }";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "MemPlace export";
        needle = "MemPlace";
      }
      {
        label = "MemoryCmp export";
        needle = "MemoryCmp";
      }
      {
        label = "ResolvedMemPlace export";
        needle = "ResolvedMemPlace";
      }
    ]
    ++ failuresFor "crates/crucible/tests/memory_condition_leaf.rs" memoryTest [
      {
        label = "physical sample test";
        needle = "memory_predicate_observes_current_physical_sample";
      }
      {
        label = "comparison test";
        needle = "memory_predicate_comparisons_are_unsigned_and_deterministic";
      }
      {
        label = "host-side symbol resolution test";
        needle = "memory_predicate_resolves_symbols_host_side";
      }
      {
        label = "virtual address resolution test";
        needle = "memory_predicate_virtual_address_requires_host_resolution";
      }
      {
        label = "sample icount plus explicit evaluation time test";
        needle = "memory_sample_event_keeps_sample_icount_and_explicit_evaluation_time";
      }
      {
        label = "event graph memory firing test";
        needle = "event_graph_fires_from_memory_predicate_without_guest_marker_support";
      }
      {
        label = "node validation test";
        needle = "memory_predicate_properties_validate_referenced_nodes";
      }
      {
        label = "serialization roundtrip";
        needle = "memory_predicate_round_trips_through_properties_serialization";
      }
      {
        label = "content material distinction";
        needle = "memory_predicate_material_distinguishes_place_cmp_and_value";
      }
      {
        label = "no guest marker fallback";
        needle = "memory predicates must not require named or guest-marker leaf resolution";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes memory condition leaf check";
        needle = "memoryConditionLeaf = import ./phase4-memory-condition-leaf.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/memory_condition_leaf.rs" memoryTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 memory-condition-leaf check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-memory-condition-leaf";
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
          name = "run-memory-condition-leaf";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-memory-condition-leaf-target" \
              -p crucible \
              --test memory_condition_leaf \
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
            tasks=${taskList}
            component=crucible-trigger
            memory_leaf=memory-predicate
            sample_source=deterministic-memory-sample-observable-event
            symbol_resolution=host-side
            RESULT
          '';
        }
      ];
    }
