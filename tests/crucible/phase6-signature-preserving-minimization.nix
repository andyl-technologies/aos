{
  attrPath ? "checks.crucible.phase6.signaturePreservingMinimization",
  dependencies ? [],
  lib,
  pkgs,
  taskIds ? ["T-TRI-5"],
}: let
  # Substring scan by index. The regex form (builtins.match ".*needle.*")
  # overflows the Nix regex engine's stack on large haystacks such as the CLI
  # main.rs, so use a linear index walk instead.
  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index: builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (! hasInfix requirement.needle content) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  triageDoc = builtins.readFile ../../docs/rfcs/0010-crucible/34-failure-triage.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  modelSource = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  signatureTest = builtins.readFile ../../crates/crucible/tests/gate_failure_signature.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  failures =
    failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "T-TRI-5 checked off";
        needle = "- [x] **T-TRI-5**";
      }
      {
        label = "T-TRI-5 completion note";
        needle = "Completed by `checks.crucible.phase6.signaturePreservingMinimization`";
      }
      {
        label = "signature-preserving minimization invariant";
        needle = "accepts only candidates whose active-policy `FailureSignatureKey` equals the";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-5 plan summary";
        needle = "checks.crucible.phase6.signaturePreservingMinimization";
      }
      {
        label = "downstream triage report gate";
        needle = "checks.crucible.phase6.perClusterReports";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "signature minimization result domain";
        needle = "FAILURE_SIGNATURE_MINIMIZATION_RESULT_DOMAIN";
      }
      {
        label = "per-cluster minimization API";
        needle = "pub fn minimize_representatives";
      }
      {
        label = "base minimization composition";
        needle = "FindingReproductionArtifact::minimize";
      }
      {
        label = "representative selection";
        needle = "representative_member()";
      }
      {
        label = "signature candidate recomputation";
        needle = "candidate_signature.signature_key(policy)?";
      }
      {
        label = "strengthened accept predicate";
        needle = "candidate_key == target_key_for_oracle";
      }
      {
        label = "target fingerprint returned only after signature match";
        needle = "then_some(target_fingerprint)";
      }
      {
        label = "minimal signature assertion";
        needle = "minimal representative signature changed";
      }
      {
        label = "minimization run struct";
        needle = "pub struct FailureSignaturePreservingMinimizationRun";
      }
      {
        label = "minimization result struct";
        needle = "pub struct FailureSignaturePreservingMinimizationResult";
      }
      {
        label = "target signature key field";
        needle = "target_signature_key";
      }
      {
        label = "minimized signature key field";
        needle = "minimized_signature_key";
      }
      {
        label = "canonical minimization material";
        needle = "failure_signature_preserving_minimization_result_material";
      }
      {
        label = "signature preserved material";
        needle = "minimization.signature_preserved";
      }
      {
        label = "attempt sequence material";
        needle = ".attempt.";
      }
      {
        label = "attempt candidate artifact material";
        needle = ".candidate_artifact";
      }
      {
        label = "attempt replayed state material";
        needle = ".replayed_state";
      }
      {
        label = "attempt observed fingerprint material";
        needle = ".observed_fingerprint";
      }
      {
        label = "attempt accepted material";
        needle = ".accepted";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "minimization run export";
        needle = "FailureSignaturePreservingMinimizationRun";
      }
      {
        label = "minimization result export";
        needle = "FailureSignaturePreservingMinimizationResult";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "signature minimization regression";
        needle = "signature_preserving_minimization_extends_base_pass_per_cluster";
      }
      {
        label = "seeded base config";
        needle = "MinimizationConfig::new";
      }
      {
        label = "signature oracle helper";
        needle = "signature_for_minimization_candidate";
      }
      {
        label = "one representative per cluster";
        needle = "loaded_representatives.len()";
      }
      {
        label = "O clusters not findings assertion";
        needle = "clustered.member_count()";
      }
      {
        label = "preserved signature assertion";
        needle = "run.preserves_signature()";
      }
      {
        label = "drift candidate rejected";
        needle = "attempt.sequence == 0";
      }
      {
        label = "signature mismatch reported as non-failure";
        needle = "attempt.observed_fingerprint.is_none()";
      }
      {
        label = "base minimization evidence retained";
        needle = "run.minimization.accepted_attempts() == 1";
      }
      {
        label = "canonical target key material";
        needle = "minimization.target_signature_key_BEGIN";
      }
      {
        label = "canonical attempt material";
        needle = "minimization.0.attempt.0.replayed_state=";
      }
      {
        label = "attempt evidence hash regression";
        needle = "forged_attempt_evidence.content_hash()";
      }
      {
        label = "attempt evidence mutation message";
        needle = "canonical result hash must include per-attempt replay evidence";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green signature minimization gate";
        needle = "signaturePreservingMinimization = greenBeforeAdvance";
      }
      {
        label = "phase6 signature minimization import";
        needle = "gate = import ./phase6-signature-preserving-minimization.nix";
      }
      {
        label = "phase6 signature minimization attr path";
        needle = "checks.crucible.phase6.signaturePreservingMinimization";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-TRI-5\"]";
      }
      {
        label = "failure clustering raw dependency";
        needle = "phase6.failureClustering.rawGate";
      }
      {
        label = "base minimization raw dependency";
        needle = "phase6.minimization.rawGate";
      }
      {
        label = "failure clustering green dependency";
        needle = "phase6.failureClustering";
      }
      {
        label = "base minimization green dependency";
        needle = "phase6.minimization";
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
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "unordered cluster map";
        needle = "HashMap<";
      }
      {
        label = "wall clock";
        needle = "SystemTime";
      }
      {
        label = "thread rng";
        needle = "thread_rng";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 signature-preserving-minimization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-signature-preserving-minimization";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
          name = "run-signature-preserving-minimization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-signature-preserving-minimization-target" \
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
            gate=gate:signature-preserving-minimization
            source=existing-minimization-pass
            accept_predicate=signature-key-equality
            cost=one-representative-per-cluster
            RESULT
          '';
        }
      ];
    }
