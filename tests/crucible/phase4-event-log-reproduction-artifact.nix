{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogReproductionArtifact",
  taskIds ? ["T-OBS-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  reproductionTest = builtins.readFile ../../crates/crucible/tests/event_log_reproduction_artifact.rs;
  contentAddressTest = builtins.readFile ../../crates/crucible/tests/event_log_content_address.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-10 checked off";
        needle = "- [x] **T-OBS-10**";
      }
      {
        label = "T-OBS-10 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogReproductionArtifact`";
      }
      {
        label = "byte-identical causal replay completion note";
        needle = "event-log metadata records the fork-point index and causal-subsequence digest";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "event-log artifact type";
        needle = "pub struct ReproductionEventLogArtifact";
      }
      {
        label = "event-log replay report type";
        needle = "pub struct ReproductionEventLogReplay";
      }
      {
        label = "debug artifact capture API";
        needle = "pub fn event_log_debug_artifact(";
      }
      {
        label = "debug artifact shared-store API";
        needle = "pub fn event_log_debug_artifact_with_segments";
      }
      {
        label = "event-log replay verification API";
        needle = "pub fn verify_event_log_replay_with";
      }
      {
        label = "verification invokes replay-log reconstructor";
        needle = "let reproduced_entries = replay_log(self, &reduction)?;";
      }
      {
        label = "causal projection used as compact metadata";
        needle = "crate::scheduler::event_log_causal_projection(entries)";
      }
      {
        label = "full log not embedded in artifact identity";
        needle = "reproduction_artifact_canonical_bytes(&self.scenario, &self.schedule)";
      }
      {
        label = "store-key artifact carries event-log segment refs";
        needle = "pub event_log_segments: Vec<ContentHash>";
      }
      {
        label = "materialized state carries event-log segment refs";
        needle = "pub event_log_segments: Vec<ContentHash>";
      }
      {
        label = "explicit event-log segment constructor";
        needle = "pub fn from_components_with_event_log_segments";
      }
      {
        label = "store-key artifact includes segment keys";
        needle = "keys.extend(self.event_log_segments.iter().copied())";
      }
      {
        label = "event-log segment refs are collected";
        needle = "event_log_segments.push(cow_ref.content)";
      }
      {
        label = "closure artifact receives segment keys";
        needle = ".with_event_log_segment_keys(event_log_segments)";
      }
      {
        label = "replay pass condition checks causal digest";
        needle = "self.expected_causal_subsequence == self.reproduced_causal_subsequence";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "event-log artifact export";
        needle = "ReproductionEventLogArtifact";
      }
      {
        label = "event-log replay export";
        needle = "ReproductionEventLogReplay";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_reproduction_artifact.rs" reproductionTest [
      {
        label = "byte-identical causal replay test";
        needle = "reproduction_artifact_replay_reconstructs_byte_identical_causal_log_from_metadata";
      }
      {
        label = "drift rejection test";
        needle = "reproduction_artifact_replay_rejects_causal_log_drift_without_original_full_log";
      }
      {
        label = "shared-store segment key test";
        needle = "dag_reproduction_artifact_references_shared_event_log_segments_by_content_key";
      }
      {
        label = "metadata verification path exercised";
        needle = "verify_event_log_replay_with(&debug_artifact, replay_log_from_artifact)";
      }
      {
        label = "replay log is reconstructed from artifact";
        needle = "fn replay_log_from_artifact(";
      }
      {
        label = "shared-store capture path exercised";
        needle = "event_log_debug_artifact_with_segments";
      }
      {
        label = "shared-store DAG artifact assertion";
        needle = ".event_log_segments";
      }
      {
        label = "shared-store chain constructor exercised";
        needle = "from_components_with_event_log_segments";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_content_address.rs" contentAddressTest [
      {
        label = "shared event-log segment store baseline";
        needle = "scheduler_writes_event_log_segments_to_shared_store";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event log reproduction-artifact import";
        needle = "eventLogReproductionArtifact = import ./phase4-event-log-reproduction-artifact.nix";
      }
      {
        label = "phase4 event log reproduction-artifact attr path";
        needle = "checks.crucible.phase4.eventLogReproductionArtifact";
      }
      {
        label = "phase4 event log reproduction-artifact task id";
        needle = "taskIds = [\"T-OBS-10\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log reproduction artifact check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-reproduction-artifact";
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
            set -eu
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
          name = "run-event-log-reproduction-artifact";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-reproduction-artifact-target" \
              -p crucible \
              --test event_log_reproduction_artifact \
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
            event_log_debug_artifact=fork-point-index
            causal_subsequence_replay=byte-identical
            shared_store_segments=content-key
            RESULT
          '';
        }
      ];
    }
