{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionResumeFingerprint",
  taskIds ? ["T-EXEC-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  decision = builtins.readFile ../../crates/crucible/src/decision.rs;
  model = import ./_crucible-model-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "resume+continue fingerprint test";
        needle = "resume_continue_matches_uninterrupted_run_by_fingerprint";
      }
      {
        label = "uninterrupted recorder binding";
        needle = "let mut uninterrupted";
      }
      {
        label = "uninterrupted recorder constructor";
        needle = "DecisionRecorder::new(Configuration::genesis(scenario.clone()))";
      }
      {
        label = "resume from prefix configuration";
        needle = "let mut resumed = DecisionRecorder::new(prefix.clone());";
      }
      {
        label = "continuation starts after prefix";
        needle = "for index in 4..8";
      }
      {
        label = "prefix equivalence assertion";
        needle = "uninterrupted.schedule.prefix(prefix_len)";
      }
      {
        label = "prefix fingerprint differs from final";
        needle = "configuration_execution_fingerprint(&prefix)";
      }
      {
        label = "final configuration equality";
        needle = "assert_eq!(uninterrupted, resumed);";
      }
      {
        label = "final fingerprint equality";
        needle = "configuration_execution_fingerprint(&resumed)";
      }
      {
        label = "representative decision driver";
        needle = "fn record_representative_decision(recorder: &mut DecisionRecorder, index: u64)";
      }
      {
        label = "pure fingerprint helper";
        needle = "pub(super) fn configuration_execution_fingerprint(";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" decision [
      {
        label = "schedule hydration for resume";
        needle = "hydrate_streams(&rng, configuration.schedule.decisions())";
      }
      {
        label = "hydrate only recorded RNG draws";
        needle = "if let Decision::RngDraw(RngDecision { stream, .. }) = decision";
      }
      {
        label = "stream position advance";
        needle = "let _ = decision_stream.next_u64();";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "pure reducer";
        needle = "pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError>";
      }
      {
        label = "reducer hashes schedule";
        needle = "id: canonical::reduced_state_hash(def, schedule)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes resume fingerprint check";
        needle = "executionResumeFingerprint = import ./phase1-execution-resume-fingerprint.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution resume fingerprint check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-resume-fingerprint";
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
          name = "run-execution-resume-fingerprint";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-resume-fingerprint-target" \
              -p crucible \
              --lib \
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
            proof=resume-plus-continue-equals-uninterrupted
            witness=reduced-state-execution-fingerprint
            rng_state=schedule-hydrated-decision-recorder
            RESULT
          '';
        }
      ];
    }
