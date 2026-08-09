{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gateCatalog",
  taskIds ? ["T-HARN-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  phasePlan = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  gateCatalogRust = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  rfcConsistency = builtins.readFile ../../crates/crucible-harness/tests/rfc_consistency.rs;
  rfcConsistencyMisc = builtins.readFile ../../crates/crucible-harness/tests/support/rfc_consistency_misc.rs;
  phaseGateWiring = builtins.readFile ./phase1-phase-gate-wiring.nix;
  defaultChecks = builtins.readFile ./default.nix;
  phaseGateWiringCheck = import ./phase1-phase-gate-wiring.nix {inherit pkgs lib;};
  rfcConsistencyCheck = import ./phase1-rfc-consistency.nix {inherit pkgs lib;};

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  gateNameFromCatalogLine = line: let
    matched = builtins.match ".*`(gate:[a-z0-9-]+)`.*" line;
  in
    if matched == null
    then []
    else matched;

  gateNameFromPhaseTargetLine = line: let
    matched = builtins.match ".*gate = \"(gate:[a-z0-9-]+)\";.*" line;
  in
    if matched == null
    then []
    else matched;

  catalogGateLines =
    builtins.filter (line: lib.hasPrefix "| `gate:" line) (lib.splitString "\n" harnessTesting);
  catalogGates =
    builtins.sort builtins.lessThan
    (lib.unique (lib.concatMap gateNameFromCatalogLine catalogGateLines));

  phaseGateTargets =
    builtins.sort builtins.lessThan
    (lib.unique (lib.concatMap gateNameFromPhaseTargetLine (lib.splitString "\n" phaseGateWiring)));

  missingTargets =
    builtins.filter (gate: !(builtins.elem gate phaseGateTargets)) catalogGates;
  unknownTargets =
    builtins.filter (gate: !(builtins.elem gate catalogGates)) phaseGateTargets;

  failures =
    map (gate: "${gate}: canonical gate lacks a phase-gate CI target") missingTargets
    ++ map (gate: "${gate}: phase-gate CI target is not canonical") unknownTargets
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalogRust [
      {
        label = "canonical gate catalog";
        needle = "pub const CANONICAL_GATES: &[GateSpec]";
      }
      {
        label = "canonical gate lookup";
        needle = "pub fn find_gate(name: &str) -> Option<&'static GateSpec>";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "catalog table/reference equality test";
        needle = "canonical_gate_catalog_matches_rfc_table_and_references";
      }
      {
        label = "implemented table matches catalog";
        needle = "assert_eq!(implemented, table);";
      }
      {
        label = "implemented table matches references";
        needle = "assert_eq!(implemented, referenced);";
      }
      {
        label = "phase-gate CI target coverage";
        needle = "canonical_gates_have_phase_gate_ci_targets";
      }
      {
        label = "doc-lint failure mode coverage";
        needle = "gate_catalog_doc_lint_failure_modes_remain_wired";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/rfc_consistency.rs" rfcConsistency [
      {
        label = "referenced/undefined gate failure hook";
        needle = "failures.extend(gate_reference_failures(&gate_catalog, &referenced_gates));";
      }
      {
        label = "referenced/undefined gate behavioral regression";
        needle = "rfc_consistency_rules_reject_undefined_and_unreferenced_gates";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/rfc_consistency_misc.rs" rfcConsistencyMisc [
      {
        label = "catalog table parser";
        needle = "pub(super) fn gate_catalog";
      }
      {
        label = "RFC gate reference scanner";
        needle = "pub(super) fn referenced_gate_names";
      }
      {
        label = "referenced-but-undefined gate failure";
        needle = "referenced gate is absent from file 24 catalog";
      }
      {
        label = "defined-but-unreferenced gate failure";
        needle = "catalog gate is not referenced outside the catalog table";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-phase-gate-wiring.nix" phaseGateWiring [
      {
        label = "missing catalog wiring detection";
        needle = "missingCatalogWiring";
      }
      {
        label = "unknown phase gate detection";
        needle = "unknownPhaseGates";
      }
      {
        label = "phase target count output";
        needle = "phase_gate_targets=";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "gate-catalog check import";
        needle = "gateCatalog = import ./phase1-gate-catalog.nix";
      }
      {
        label = "phase-gate wiring import";
        needle = "phaseGateWiring = import ./phase1-phase-gate-wiring.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" phasePlan [
      {
        label = "Phase 1 lists gate catalog work";
        needle = "the gate catalog";
      }
      {
        label = "Phase 1 lists harness task range";
        needle = "T-HARN-1";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 gate-catalog check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-gate-catalog";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
        phaseGateWiringCheck
        rfcConsistencyCheck
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
          name = "run-gate-catalog";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-gate-catalog-target" \
              -p crucible-harness \
              --test gate_catalog \
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
            canonical_gates=${toString (builtins.length catalogGates)}
            phase_gate_targets=${toString (builtins.length phaseGateTargets)}
            rust_test=crucible-harness::gate_catalog
            RESULT
          '';
        }
      ];
    }
