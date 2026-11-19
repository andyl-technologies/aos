{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gateCatalog",
  taskIds ? ["T-HARN-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  testingAndGatesDoc = builtins.readFile ../../docs/engineering/crucible/testing-and-gates.md;
  gateCatalogRust = builtins.readFile ../../crates/crucible/crucible-test-support/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible/crucible-test-support/tests/gate_catalog.rs;
  phaseGateWiring = builtins.readFile ./phase1-phase-gate-wiring.nix;
  defaultChecks = builtins.readFile ./default.nix;
  phaseGateWiringCheck = import ./phase1-phase-gate-wiring.nix {inherit pkgs lib;};

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
    builtins.filter (line: lib.hasPrefix "| `gate:" line) (lib.splitString "\n" testingAndGatesDoc);
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
    ++ failuresFor "crates/crucible/crucible-test-support/src/lib.rs" gateCatalogRust [
      {
        label = "canonical gate catalog";
        needle = "pub const CANONICAL_GATES: &[GateSpec]";
      }
      {
        label = "canonical gate lookup";
        needle = "pub fn find_gate(name: &str) -> Option<&'static GateSpec>";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "catalog table/reference equality test";
        needle = "canonical_gate_catalog_matches_documented_table_and_references";
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
              -p crucible-test-support \
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
            rust_test=crucible_test_support::gate_catalog
            RESULT
          '';
        }
      ];
    }
