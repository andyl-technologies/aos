{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.failureSignature",
  taskIds ? ["T-TRI-1"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  triageDoc = builtins.readFile ../../docs/rfcs/0010-crucible/34-failure-triage.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  triggers = import ./_crucible-trigger-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  signatureTest = builtins.readFile ../../crates/crucible/tests/gate_failure_signature.rs;
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
    failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "T-TRI-1 completion note";
        needle = "Completed by `checks.crucible.phase6.failureSignature`";
      }
      {
        label = "recorded run alone invariant";
        needle = "recorded run alone";
      }
      {
        label = "read not re-derived invariant";
        needle = "signature is read, not re-derived";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-1 plan summary";
        needle = "`T-TRI-1` is green through `checks.crucible.phase6.failureSignature`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "failure signature tuple";
        needle = "pub struct FailureSignature";
      }
      {
        label = "failure kind discriminant";
        needle = "pub enum FailureKind";
      }
      {
        label = "property key";
        needle = "pub struct FailurePropertyKey";
      }
      {
        label = "first failing point";
        needle = "pub struct FailureFirstFailingPoint";
      }
      {
        label = "coverage class";
        needle = "pub struct FailureCoverageClass";
      }
      {
        label = "checked event-log wrapper";
        needle = "pub struct FailureRecordedEventLog";
      }
      {
        label = "violation source record";
        needle = "pub struct FailurePropertyViolationRecord";
      }
      {
        label = "property constructor";
        needle = "from_recorded_property_violation";
      }
      {
        label = "divergence constructor";
        needle = "from_recorded_divergence";
      }
      {
        label = "content-addressed signature";
        needle = "FAILURE_SIGNATURE_DOMAIN";
      }
      {
        label = "event-log artifact binding";
        needle = "event_log_artifact.reproduction_artifact";
      }
      {
        label = "causal subsequence binding";
        needle = "event_log_artifact.causal_subsequence";
      }
      {
        label = "coverage fingerprint bucket";
        needle = "coverage_fingerprint_from_event_log(event_log)";
      }
      {
        label = "recorded coverage fingerprint binding";
        needle = "event_log_artifact.coverage_fingerprint";
      }
      {
        label = "coverage fingerprint in event-log metadata id";
        needle = "content_hash_hex(coverage_fingerprint)";
      }
      {
        label = "event kind read from violation record";
        needle = "event_kind: self.violation.event_kind.clone()";
      }
      {
        label = "static artifact identity";
        needle = "validate_finding_static_identity";
      }
      {
        label = "violation artifact binding";
        needle = "validate_violation_for_finding";
      }
      {
        label = "divergence projection binding";
        needle = "validate_divergence_point";
      }
      {
        label = "causal slice field";
        needle = "causal_slice_hash: Option<ContentHash>";
      }
      {
        label = "no discovery path in signature docs";
        needle = "omits discovery path";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" triggers [
      {
        label = "host assertion violation record";
        needle = "pub struct HostAssertionViolation";
      }
      {
        label = "host assertion violation event kind";
        needle = "pub event_kind: String";
      }
      {
        label = "assertion violation event kind derived";
        needle = "event_kind: String::from(\"assertion_state_changed\")";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "failure signature export";
        needle = "FailureSignature";
      }
      {
        label = "failure kind export";
        needle = "FailureKind";
      }
      {
        label = "failure property key export";
        needle = "FailurePropertyKey";
      }
      {
        label = "failure violation record export";
        needle = "FailurePropertyViolationRecord";
      }
      {
        label = "failure recorded event log export";
        needle = "FailureRecordedEventLog";
      }
      {
        label = "failure coverage class export";
        needle = "FailureCoverageClass";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "recorded tuple test";
        needle = "failure_signature_uses_recorded_tuple_not_discovery_campaign";
      }
      {
        label = "divergence bisection test";
        needle = "failure_signature_reads_divergence_bisection_point";
      }
      {
        label = "static identity mismatch test";
        needle = "failure_signature_rejects_static_artifact_identity_mismatch";
      }
      {
        label = "unbound record input test";
        needle = "failure_signature_rejects_unbound_record_inputs";
      }
      {
        label = "discovery path ignored";
        needle = "assert_ne!(first.discovery_path, second.discovery_path)";
      }
      {
        label = "finding fingerprint ignored";
        needle = "assert_ne!(first.finding_fingerprint, second.finding_fingerprint)";
      }
      {
        label = "observational noise ignored by causal slice";
        needle = "operator-visible noise";
      }
      {
        label = "checked event log constructor exercised";
        needle = "FailureRecordedEventLog::from_recorded_artifact";
      }
      {
        label = "mismatched violation rejected";
        needle = "wrong-artifact";
      }
      {
        label = "coverage tampering rejected";
        needle = "coverage-added-after-recording";
      }
      {
        label = "missing divergence rejected";
        needle = "divergence point must exist in the recorded causal projection";
      }
      {
        label = "causal slice computed test";
        needle = "causal_slice_hash.is_some()";
      }
      {
        label = "recorded property constructor exercised";
        needle = "FailureSignature::from_recorded_property_violation";
      }
      {
        label = "recorded divergence constructor exercised";
        needle = "FailureSignature::from_recorded_divergence";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green failure signature gate";
        needle = "failureSignature = greenBeforeAdvance";
      }
      {
        label = "phase6 failure signature import";
        needle = "gate = import ./phase6-failure-signature.nix";
      }
      {
        label = "phase6 failure signature attr path";
        needle = "checks.crucible.phase6.failureSignature";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-TRI-1\"]";
      }
      {
        label = "phase6 minimization raw dependency";
        needle = "phase6.minimization.rawGate";
      }
      {
        label = "phase4 assertion violation records dependency";
        needle = "phase4.assertionViolationRecords";
      }
      {
        label = "phase4 event log dependency";
        needle = "phase4.eventLogUnified";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "ignored test";
        needle = "#[ignore]";
      }
      {
        label = "todo marker";
        needle = "todo!";
      }
      {
        label = "unimplemented marker";
        needle = "unimplemented!";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "stubbed failure signature";
        needle = "NotImplemented { operation: \"failure-signature";
      }
      {
        label = "caller-supplied violation event kind";
        needle = "event_kind: event_kind.into()";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 failure-signature check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-failure-signature";
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
          name = "run-failure-signature";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-failure-signature-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_failure_signature \
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
            gate=gate:failure-signature
            source=recorded-run-only
            key=failure-kind-property-point-coverage
            RESULT
          '';
        }
      ];
    }
