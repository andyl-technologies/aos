{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.gates.replayOracle",
  taskIds ? ["T-ADV-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  forkReplayGateTest = builtins.readFile ../../crates/crucible/tests/gate_fork_replay_oracle.rs;
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

  defaultReplayOracleBlock =
    sliceFromUntil
    (sliceFromUntil defaultChecks "  phase6 = {" "\n  phase7 = {")
    "      replayOracle = greenBeforeAdvance {"
    "\n    };";

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
        label = "T-ADV-4 completion note";
        needle = "Completed by `checks.crucible.phase6.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "fork API";
        needle = "pub fn fork<I>";
      }
      {
        label = "fork base instantiate path";
        needle = "let base_runtime = self.resume(base)?;";
      }
      {
        label = "fork branch thin checkpoint";
        needle = "let branch_checkpoint = self.record_thin_checkpoint(&branch)?;";
      }
      {
        label = "shared replay oracle API";
        needle = "pub fn replay_checkpoint";
      }
      {
        label = "cached snapshot replay validation";
        needle = "graph.replay_checkpoint(config, snapshot)?;";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_fork_replay_oracle.rs" forkReplayGateTest [
      {
        label = "base and branch validation test";
        needle = "gate_fork_replay_oracle_validates_base_and_materialized_branch";
      }
      {
        label = "corrupt base rejection test";
        needle = "gate_fork_replay_oracle_rejects_corrupt_base_before_branching";
      }
      {
        label = "corrupt branch localization test";
        needle = "gate_fork_replay_oracle_rejects_corrupt_branch_cache_and_localizes";
      }
      {
        label = "fork operation under test";
        needle = "graph.fork(&base";
      }
      {
        label = "branch materialization uses restore oracle";
        needle = "graph.materialize_checkpoint(&fork.branch)?";
      }
      {
        label = "branch explicit replay check";
        needle = "graph.replay(&fork.branch)?";
      }
      {
        label = "base failure prevents branch recording";
        needle = "a base replay-oracle failure must not record the fork branch";
      }
      {
        label = "oracle mismatch surfaced";
        needle = "EngineError::ReplayOracleMismatch";
      }
      {
        label = "bisection handoff";
        needle = "check_sampled_search_replay_oracle_with_bisection";
      }
      {
        label = "localized fork decision";
        needle = "fork mismatch must localize the first differing decision";
      }
      {
        label = "corrupt cache eviction";
        needle = "corrupt fork branch cache should be evicted back to thin replay";
      }
      {
        label = "post-eviction thin replay";
        needle = "thin replay after cache eviction should realize the fork branch";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_fork_replay_oracle.rs" forkReplayGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix phase6 replayOracle block" defaultReplayOracleBlock [
      {
        label = "phase6 replay oracle green wrapper";
        needle = "replayOracle = greenBeforeAdvance";
      }
      {
        label = "phase6 replay oracle import";
        needle = "gate = import ./phase6-fork-replay-oracle.nix";
      }
      {
        label = "phase6 replay oracle attr path";
        needle = "checks.crucible.phase6.gates.replayOracle";
      }
      {
        label = "phase6 replay oracle task id";
        needle = ''taskIds = ["T-ADV-4"]'';
      }
      {
        label = "phase4 replay oracle raw dependency";
        needle = "\n            phase4.gates.replayOracle.rawGate\n";
      }
      {
        label = "phase4 e2e determinism raw dependency";
        needle = "\n            phase4.gates.e2eDeterminism.rawGate\n";
      }
      {
        label = "phase6 exploration fork raw dependency";
        needle = "\n            phase6.explorationFork.rawGate\n";
      }
      {
        label = "phase6 restore strategies raw dependency";
        needle = "\n            phase6.restoreStrategies.rawGate\n";
      }
      {
        label = "phase4 replay oracle green dependency";
        needle = "\n          phase4.gates.replayOracle\n";
      }
      {
        label = "phase4 e2e determinism green dependency";
        needle = "\n          phase4.gates.e2eDeterminism\n";
      }
      {
        label = "phase6 exploration fork green dependency";
        needle = "\n          phase6.explorationFork\n";
      }
      {
        label = "phase6 restore strategies green dependency";
        needle = "\n          phase6.restoreStrategies\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 fork replay-oracle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-fork-replay-oracle";
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
          name = "run-fork-replay-oracle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fork-replay-oracle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_fork_replay_oracle \
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
            gate=gate:replay-oracle
            fork=base-validated,branch-materialized,divergence-localized
            rust_test=crucible::gate_fork_replay_oracle
            RESULT
          '';
        }
      ];
    }
