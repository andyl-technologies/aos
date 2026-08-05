{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.restoreStrategies",
  taskIds ? ["T-ADV-5"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  restoreGateTest = builtins.readFile ../../crates/crucible/tests/gate_restore_strategies.rs;
  replayOracleHarness = builtins.readFile ../../crates/crucible-harness/src/replay_oracle.rs;
  divergenceGateTest = builtins.readFile ../../crates/crucible-harness/tests/gate_divergence_bisect.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  indexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches =
      builtins.filter (
        index: builtins.substring index needleLen haystack == needle
      )
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceFromUntil = content: startNeedle: endNeedle: let
    start = indexOf startNeedle content;
    tailStart = start + builtins.stringLength startNeedle;
    tail = builtins.substring tailStart (builtins.stringLength content - tailStart) content;
    end = indexOf endNeedle tail;
  in
    if start == null
    then ""
    else if end == null
    then startNeedle + tail
    else startNeedle + builtins.substring 0 end tail;

  defaultRestoreStrategiesBlock =
    sliceFromUntil
    defaultChecks
    "    restoreStrategies = greenBeforeAdvance {"
    "    gates = {";

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "T-ADV-5 completion note";
        needle = "Completed by `checks.crucible.phase6.restoreStrategies`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "fat materialization entry point";
        needle = "pub fn materialize_checkpoint(";
      }
      {
        label = "materialization replay oracle validation";
        needle = "self.replay_checkpoint(configuration, &checkpoint)?;";
      }
      {
        label = "snapshot cache after validation";
        needle = "self.cache_snapshot(configuration, checkpoint.clone())?;";
      }
      {
        label = "on-demand snapshot restore replay check";
        needle = "pub fn replay_oracle_admit_cached_snapshot(";
      }
      {
        label = "corrupt snapshot eviction";
        needle = "self.evict_fat_checkpoint_to_thin(configuration)?;";
      }
      {
        label = "thin replay source of truth";
        needle = "instantiate_thin_replay(self, configuration)?;";
      }
      {
        label = "explicit replay API";
        needle = "pub fn replay(&self, configuration: &Configuration)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_restore_strategies.rs" restoreGateTest [
      {
        label = "thin and snapshot convergence test";
        needle = "gate_restore_strategies_converge_on_thin_source_of_truth";
      }
      {
        label = "corrupt snapshot rejection test";
        needle = "gate_restore_strategies_reject_corrupt_snapshot_restore_and_evict_cache";
      }
      {
        label = "thin source of truth assertion";
        needle = "the fat snapshot cache must not replace the thin source-of-truth DAG node";
      }
      {
        label = "snapshot bug visible as oracle mismatch";
        needle = "EngineError::ReplayOracleMismatch";
      }
      {
        label = "restore path validation before load";
        needle = "snapshot restore should validate before loading corrupt cache";
      }
      {
        label = "restore mismatch localization helper";
        needle = "assert_restore_mismatch_localizes";
      }
      {
        label = "restore mismatch bisection";
        needle = "check_sampled_search_replay_oracle_with_bisection";
      }
      {
        label = "localized restore decision";
        needle = "restore mismatch must localize the first differing decision";
      }
      {
        label = "corrupt cache eviction assertion";
        needle = "corrupt cached snapshot should be evicted back to thin replay";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_restore_strategies.rs" restoreGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/replay_oracle.rs" replayOracleHarness [
      {
        label = "oracle mismatch localization API";
        needle = "pub fn localize_replay_oracle_mismatch";
      }
      {
        label = "oracle bisection request";
        needle = "pub struct ReplayOracleBisectionRequest";
      }
      {
        label = "localized oracle mismatch";
        needle = "pub struct ReplayOracleLocalizedMismatch";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_divergence_bisect.rs" divergenceGateTest [
      {
        label = "oracle mismatch divergence localization test";
        needle = "gate_divergence_bisect_localizes_replay_oracle_mismatch";
      }
      {
        label = "first differing decision assertion";
        needle = "oracle mismatch must localize the first differing decision";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix restoreStrategies block" defaultRestoreStrategiesBlock [
      {
        label = "phase6 restore strategies green wrapper";
        needle = "restoreStrategies = greenBeforeAdvance";
      }
      {
        label = "phase6 restore strategies import";
        needle = "gate = import ./phase6-restore-strategies.nix";
      }
      {
        label = "phase6 restore strategies attr path";
        needle = "checks.crucible.phase6.restoreStrategies";
      }
      {
        label = "phase6 restore strategies task id";
        needle = ''taskIds = ["T-ADV-5"]'';
      }
      {
        label = "phase4 replay oracle raw dependency";
        needle = "\n          phase4.gates.replayOracle.rawGate\n";
      }
      {
        label = "phase4 e2e determinism raw dependency";
        needle = "\n          phase4.gates.e2eDeterminism.rawGate\n";
      }
      {
        label = "phase6 advanced ladder raw dependency";
        needle = "\n          phase6.advancedDependencyLadder.rawGate\n";
      }
      {
        label = "phase4 replay oracle green dependency";
        needle = "\n        phase4.gates.replayOracle\n";
      }
      {
        label = "phase4 e2e determinism green dependency";
        needle = "\n        phase4.gates.e2eDeterminism\n";
      }
      {
        label = "phase6 advanced ladder green dependency";
        needle = "\n        phase6.advancedDependencyLadder\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 restore strategies check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-restore-strategies";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            set -eu
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-restore-strategies";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-restore-strategies-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_restore_strategies \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
                        set -eu
                        mkdir -p "$out"
                        cat > "$out/result" <<RESULT
                        PASS
            check=${attrPath}
            tasks=${taskList}
            restore=replay-from-seed,snapshot-restore
            rust_test=crucible::gate_restore_strategies
            RESULT
          '';
        }
      ];
    }
