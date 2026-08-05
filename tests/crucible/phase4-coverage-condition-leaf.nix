{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.coverageConditionLeaf",
  taskIds ? ["T-TRIG-5"],
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
  coverageTest = builtins.readFile ../../crates/crucible/tests/coverage_condition_leaf.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-5 completion note";
        needle = "Completed by `checks.crucible.phase4.coverageConditionLeaf`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "CoveragePoint predicate";
        needle = "CoveragePoint {\n        /// Node whose execution is observed.";
      }
      {
        label = "CodePoint type";
        needle = "pub enum CodePoint";
      }
      {
        label = "guest address constructor";
        needle = "pub const fn guest_address(address: u64) -> Self";
      }
      {
        label = "symbol constructor";
        needle = "pub fn symbol(name: impl Into<String>) -> Self";
      }
      {
        label = "coverage constructor";
        needle = "pub fn coverage_point(node: NodeId, point: CodePoint) -> Self";
      }
      {
        label = "coverage TOML";
        needle = "PredicateTomlKind::CoveragePoint";
      }
      {
        label = "code point TOML";
        needle = "enum CodePointToml";
      }
      {
        label = "coverage binary tag";
        needle = "writer.write_u8(13);";
      }
      {
        label = "code point binary";
        needle = "fn write_code_point_binary";
      }
      {
        label = "coverage material";
        needle = "code_point_material(point)";
      }
      {
        label = "coverage validates nodes";
        needle = "Predicate::CoveragePoint { node, .. }";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "resolved code point";
        needle = "pub struct ResolvedCodePoint";
      }
      {
        label = "coverage observable constructor";
        needle = "pub fn coverage_block";
      }
      {
        label = "coverage observable payload";
        needle = "ObservableEventPayload::CoverageBlock";
      }
      {
        label = "coverage carries execution icount";
        needle = "execution_icount: Icount";
      }
      {
        label = "code point resolution hook";
        needle = "fn resolve_code_point";
      }
      {
        label = "raw address resolves to itself";
        needle = "CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address))";
      }
      {
        label = "test evaluator resolution injection";
        needle = "pub fn with_resolved_code_points";
      }
      {
        label = "CoveragePoint evaluation";
        needle = "Condition::CoveragePoint { node, point }";
      }
      {
        label = "coverage matcher";
        needle = "fn coverage_point_matches";
      }
      {
        label = "block execution sample";
        needle = "fn coverage_event_matches";
      }
      {
        label = "prior block suppresses rematch";
        needle = "event.at() < at && coverage_event_matches(event.payload(), expected_node, resolved)";
      }
      {
        label = "block range address match";
        needle = "fn block_contains_address";
      }
      {
        label = "graph evaluator delegates symbol resolution";
        needle = "self.inner.resolve_code_point(node, point)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "CodePoint export";
        needle = "CodePoint";
      }
      {
        label = "ResolvedCodePoint export";
        needle = "ResolvedCodePoint";
      }
    ]
    ++ failuresFor "crates/crucible/tests/coverage_condition_leaf.rs" coverageTest [
      {
        label = "current block execution test";
        needle = "coverage_point_observes_current_basic_block_execution_event";
      }
      {
        label = "first execution test";
        needle = "coverage_point_does_not_rematch_after_prior_block_execution";
      }
      {
        label = "host-side symbol resolution test";
        needle = "coverage_point_resolves_symbols_host_side_without_guest_marker_support";
      }
      {
        label = "raw address ignores resolution table test";
        needle = "coverage_point_raw_guest_address_ignores_symbol_resolution_table";
      }
      {
        label = "execution icount derives event point test";
        needle = "coverage_block_event_point_is_derived_from_execution_icount";
      }
      {
        label = "event graph coverage firing test";
        needle = "event_graph_fires_from_coverage_point_without_named_leaf_fallback";
      }
      {
        label = "node validation test";
        needle = "coverage_point_properties_validate_referenced_nodes";
      }
      {
        label = "serialization roundtrip";
        needle = "coverage_point_round_trips_through_properties_serialization";
      }
      {
        label = "content material distinction";
        needle = "coverage_point_material_distinguishes_addresses_and_symbols";
      }
      {
        label = "observable event prefix construction";
        needle = "support::evaluation_with_observables";
      }
      {
        label = "no guest marker fallback";
        needle = "coverage leaves must not require named or guest-marker leaf resolution";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes coverage condition leaf check";
        needle = "coverageConditionLeaf = import ./phase4-coverage-condition-leaf.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/coverage_condition_leaf.rs" coverageTest [
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
  then throw "crucible phase4 coverage-condition-leaf check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-coverage-condition-leaf";
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
          name = "run-coverage-condition-leaf";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-coverage-condition-leaf-target" \
              -p crucible \
              --test coverage_condition_leaf \
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
            coverage_leaf=coverage-point
            event_source=tcg-exec-basic-block-observable-event
            symbol_resolution=host-side
            RESULT
          '';
        }
      ];
    }
