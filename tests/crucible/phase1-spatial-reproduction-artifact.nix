{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialReproductionArtifact",
  taskIds ? ["T-SPAT-18"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  artifactTest = builtins.readFile ../../crates/crucible/tests/event_log_reproduction_artifact.rs;
  workloadTest = builtins.readFile ../../crates/crucible/tests/workload_parameterization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-18 completion names reproduction artifact";
        needle = "`ReproductionArtifact`";
      }
      {
        label = "T-SPAT-18 completion names gate";
        needle = "`checks.crucible.phase1.spatialReproductionArtifact`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "reproduction artifact type";
        needle = "pub struct ReproductionArtifact";
      }
      {
        label = "reproduction replay result";
        needle = "pub struct ReproductionReplay";
      }
      {
        label = "capture constructor";
        needle = "pub fn capture(scenario: &ScenarioDefForm, schedule: &Schedule) -> Result<Self, EngineError>";
      }
      {
        label = "recorded parts constructor";
        needle = "pub fn from_recorded_parts(scenario: ScenarioDefForm, schedule: Schedule) -> Self";
      }
      {
        label = "artifact binary decoder";
        needle = "pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError>";
      }
      {
        label = "schedule binary encoder";
        needle = "pub fn to_compact_binary(&self) -> Vec<u8>";
      }
      {
        label = "schedule binary decoder";
        needle = "let schedule = read_schedule_binary(&mut reader)?;";
      }
      {
        label = "derived scenario seed";
        needle = "pub fn seed(&self) -> Seed";
      }
      {
        label = "canonical artifact bytes";
        needle = "pub fn canonical_bytes(&self) -> Vec<u8>";
      }
      {
        label = "BLAKE3 content address over canonical bytes";
        needle = "ContentHash::from_bytes(&reproduction_artifact_canonical_bytes";
      }
      {
        label = "schedule embedded in canonical bytes";
        needle = "writer.write_binary_blob(&schedule.to_compact_binary())";
      }
      {
        label = "artifact embeds scenario binary";
        needle = "writer.write_binary_blob(&scenario.to_compact_binary())";
      }
      {
        label = "artifact replay API";
        needle = "pub fn replay(&self) -> Result<ReproductionReplay, EngineError>";
      }
      {
        label = "artifact replay verification API";
        needle = "pub fn verify_replay(&self, expected: ContentHash) -> Result<ReproductionReplay, EngineError>";
      }
      {
        label = "artifact replay reduces embedded tuple";
        needle = "reduce(&self.scenario_def(), &self.schedule)?";
      }
      {
        label = "artifact replay mismatch error";
        needle = "ReproductionArtifactReplayMismatch";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "crate exports reproduction artifact";
        needle = "ReproductionArtifact";
      }
      {
        label = "crate exports reproduction replay";
        needle = "ReproductionReplay";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_reproduction_artifact.rs" artifactTest [
      {
        label = "focused artifact replay test";
        needle = "fn reproduction_artifact_replay_reconstructs_byte_identical_causal_log_from_metadata()";
      }
      {
        label = "test captures scenario and schedule";
        needle = "ReproductionArtifact::capture(&scenario, &schedule)";
      }
      {
        label = "test verifies replay";
        needle = ".verify_event_log_replay_with(&debug_artifact, replay_log_from_artifact)";
      }
      {
        label = "test rejects causal log drift";
        needle = "fn reproduction_artifact_replay_rejects_causal_log_drift_without_original_full_log()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_parameterization.rs" workloadTest [
      {
        label = "scenario form TOML round trip precedes capture";
        needle = "ScenarioDefForm::from_canonical_toml(&form.to_canonical_toml()?)?";
      }
      {
        label = "scenario form binary round trip precedes capture";
        needle = "ScenarioDefForm::from_compact_binary(&form.to_compact_binary())?";
      }
      {
        label = "captured artifact replays offline";
        needle = "let replay = artifact.replay()?;";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial reproduction artifact check";
        needle = "spatialReproductionArtifact = import ./phase1-spatial-reproduction-artifact.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial reproduction artifact check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-reproduction-artifact";
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
          name = "run-spatial-reproduction-artifact";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-reproduction-artifact-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test event_log_reproduction_artifact \
              reproduction_artifact_replay \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-reproduction-artifact-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_parameterization \
              reproduces \
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
            component=reproduction-artifact
            self_contained_tuple=true
            replay_oracle_verified=true
            content_addressed=true
            RESULT
          '';
        }
      ];
    }
