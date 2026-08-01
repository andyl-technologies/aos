{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionViolationRecords",
  taskIds ? ["T-ASRT-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  violationTest = builtins.readFile ../../crates/crucible/tests/assertion_violation_records.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-14 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionViolationRecords`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "violation record type";
        needle = "pub struct HostAssertionViolation";
      }
      {
        label = "quantifier type";
        needle = "pub enum AssertionQuantifierKind";
      }
      {
        label = "violation accessor";
        needle = "pub fn violations(&self) -> &[HostAssertionViolation]";
      }
      {
        label = "violation records from outcomes";
        needle = "host_assertion_violations_from_outcomes";
      }
      {
        label = "icount from retained log";
        needle = "ObservableEventPayload::GuestMarker";
      }
      {
        label = "content-addressed retained log artifact";
        needle = "assertion_reproduction_artifact_from_prefix";
      }
      {
        label = "canonical retained log bytes";
        needle = "external_formal_trace_bytes(&prefix.scheduler_entries)";
      }
      {
        label = "recorded evidence on outcomes";
        needle = "evidence: Option<HostAssertionViolationEvidence>";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_violation_records.rs" violationTest [
      {
        label = "violation record test";
        needle = "violation_records_are_derived_from_retained_log_and_reproduction_artifact";
      }
      {
        label = "online offline equality";
        needle = "assert_eq!(online, offline)";
      }
      {
        label = "recorded log equality";
        needle = "assert_eq!(offline, offline_recorded)";
      }
      {
        label = "artifact derived from retained log export";
        needle = "ExternalFormalTraceExporter::export_event_log(&event_log)";
      }
      {
        label = "artifact assertion";
        needle = "assert_eq!(violation.reproduction_artifact, reproduction_artifact)";
      }
      {
        label = "same-time decoy marker";
        needle = "ObservableEvent::guest_marker(icount(7), node(\"decoy\"), marker_id(\"decoy\"))";
      }
      {
        label = "icount assertion";
        needle = "assert_eq!(violation.at_icount, Some(icount(7)))";
      }
      {
        label = "node assertion";
        needle = "assert_eq!(violation.node, Some(node(\"guest\")))";
      }
      {
        label = "detail assertion";
        needle = "guest marker marker=forbidden matched";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion violation import";
        needle = "assertionViolationRecords = import ./phase4-assertion-violation-records.nix";
      }
      {
        label = "phase4 assertion violation attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionViolationRecords\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_violation_records.rs" violationTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
      {
        label = "caller-supplied artifact hash";
        needle = "crucible.test.reproduction-artifact";
      }
      {
        label = "artifact override helper";
        needle = ".with_reproduction_artifact(";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "artifact override helper";
        needle = ".with_reproduction_artifact(";
      }
      {
        label = "synthetic fallback artifact";
        needle = "fallback_assertion_reproduction_artifact";
      }
      {
        label = "timestamp-only violation attribution";
        needle = "violation_site_from_log";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 assertion-violation-records check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-violation-records";
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
          name = "run-assertion-violation-records";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-violation-records-target" \
              -p crucible \
              --test assertion_violation_records \
              --test offline_assertion_checker \
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
            assertion_violation_records=true
            RESULT
          '';
        }
      ];
    }
