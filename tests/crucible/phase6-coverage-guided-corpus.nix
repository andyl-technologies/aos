{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.coverageGuidedCorpus",
  taskIds ? ["T-ADV-13"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  corpusTest = builtins.readFile ../../crates/crucible/tests/gate_coverage_guided_corpus.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

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
        label = "T-ADV-13 completion note";
        needle = "Completed by `checks.crucible.phase6.coverageGuidedCorpus`";
      }
      {
        label = "ADV-26 corpus requirement";
        needle = "The fuzzer MUST manage a content-addressed corpus stored in the\n  `DagStore`";
      }
      {
        label = "ADV-27 throughput requirement";
        needle = "Throughput MUST be measured in deterministic work\n  units";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "corpus config";
        needle = "pub struct CoverageGuidedCorpusConfig";
      }
      {
        label = "corpus run";
        needle = "pub struct CoverageGuidedCorpusRun";
      }
      {
        label = "corpus entry";
        needle = "pub struct CoverageGuidedCorpusEntry";
      }
      {
        label = "admission decision";
        needle = "pub enum CoverageGuidedCorpusAdmissionDecision";
      }
      {
        label = "throughput report";
        needle = "pub struct CoverageGuidedFuzzThroughputReport";
      }
      {
        label = "scenario family corpus API";
        needle = "pub fn fuzz_coverage_guided_corpus";
      }
      {
        label = "artifact capture";
        needle = "ReproductionArtifact::capture";
      }
      {
        label = "artifact store put";
        needle = "store.put(&artifact.to_compact_binary())";
      }
      {
        label = "descriptor store put";
        needle = "put-corpus-entry-descriptor";
      }
      {
        label = "coverage pruning";
        needle = "PrunedSubsumedCoverage";
      }
      {
        label = "weighted parent selection";
        needle = "coverage_guided_corpus_select_parent";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "corpus config export";
        needle = "CoverageGuidedCorpusConfig";
      }
      {
        label = "corpus run export";
        needle = "CoverageGuidedCorpusRun";
      }
      {
        label = "throughput report export";
        needle = "CoverageGuidedFuzzThroughputReport";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_coverage_guided_corpus.rs" corpusTest [
      {
        label = "persistence gate";
        needle = "gate_coverage_guided_corpus_persists_replay_artifacts";
      }
      {
        label = "determinism gate";
        needle = "gate_coverage_guided_corpus_is_seeded_and_deduplicated";
      }
      {
        label = "corpus API used";
        needle = "fuzz_coverage_guided_corpus";
      }
      {
        label = "memory store used";
        needle = "MemoryDagStore::new";
      }
      {
        label = "artifact decode assertion";
        needle = "ReproductionArtifact::from_compact_binary";
      }
      {
        label = "descriptor lookup assertion";
        needle = "entry.descriptor_key";
      }
      {
        label = "throughput assertion";
        needle = "run.throughput.meets_target()";
      }
      {
        label = "pruning assertion";
        needle = "PrunedSubsumedCoverage";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green coverage corpus gate";
        needle = "coverageGuidedCorpus = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-ADV-13\"]";
      }
      {
        label = "fuzzing raw dependency";
        needle = "phase6.coverageGuidedFuzzing.rawGate";
      }
      {
        label = "fuzzing green dependency";
        needle = "phase6.coverageGuidedFuzzing";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_coverage_guided_corpus.rs" corpusTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 coverage-guided corpus check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-coverage-guided-corpus";
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
          name = "run-coverage-guided-corpus";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-coverage-guided-corpus-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_coverage_guided_corpus \
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
            gate=gate:coverage-guided-corpus
            corpus=dag-store-reproduction-artifacts
            admission=first-seen-coverage
            pruning=deterministic-subsumed-coverage
            throughput=deterministic-work-units
            RESULT
          '';
        }
      ];
    }
