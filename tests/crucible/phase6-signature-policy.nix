{
  attrPath ? "checks.crucible.phase6.signaturePolicy",
  dependencies ? [],
  lib,
  pkgs,
  taskIds ? ["T-TRI-3"],
}: let
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
    builtins.any (index: builtins.substring index needleLen haystack == needle) indexes;

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
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
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
        label = "T-TRI-3 completion note";
        needle = "Completed by `checks.crucible.phase6.signaturePolicy`";
      }
      {
        label = "policy levels note";
        needle = "coarse/default/fine/exact";
      }
      {
        label = "result identity note";
        needle = "triage result identity";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-3 plan summary";
        needle = "checks.crucible.phase6.signaturePolicy";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "policy level enum";
        needle = "pub enum SignaturePolicyLevel";
      }
      {
        label = "coarse level";
        needle = "Coarse";
      }
      {
        label = "default level";
        needle = "Default";
      }
      {
        label = "fine level";
        needle = "Fine";
      }
      {
        label = "exact level";
        needle = "Exact";
      }
      {
        label = "policy struct";
        needle = "pub struct SignaturePolicy";
      }
      {
        label = "policy schema version";
        needle = "SIGNATURE_POLICY_SCHEMA_VERSION";
      }
      {
        label = "policy schema in material";
        needle = "signature_policy_schema_version";
      }
      {
        label = "fixed coverage algorithm";
        needle = "coverage_class_algorithm";
      }
      {
        label = "exact no minimize merge";
        needle = "allows_minimize_merge";
      }
      {
        label = "absolute icount key selector";
        needle = "keys_absolute_icount";
      }
      {
        label = "causal slice key selector";
        needle = "keys_causal_slice_hash";
      }
      {
        label = "signature key projection";
        needle = "signature_key";
      }
      {
        label = "signature key type";
        needle = "pub struct FailureSignatureKey";
      }
      {
        label = "signature key domain";
        needle = "FAILURE_SIGNATURE_KEY_DOMAIN";
      }
      {
        label = "triage result identity";
        needle = "pub struct FailureTriageResultIdentity";
      }
      {
        label = "triage identity domain";
        needle = "FAILURE_TRIAGE_RESULT_IDENTITY_DOMAIN";
      }
      {
        label = "full causal cone type";
        needle = "pub struct FailureCausalCone";
      }
      {
        label = "signature retains causal cone";
        needle = "pub causal_cone: Option<FailureCausalCone>";
      }
      {
        label = "exact causal cone material";
        needle = "exact_causal_cone_material_BEGIN";
      }
      {
        label = "exact icount key material";
        needle = "at_icount_key";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "policy export";
        needle = "SignaturePolicy";
      }
      {
        label = "policy level export";
        needle = "SignaturePolicyLevel";
      }
      {
        label = "signature key export";
        needle = "FailureSignatureKey";
      }
      {
        label = "triage result identity export";
        needle = "FailureTriageResultIdentity";
      }
      {
        label = "causal cone export";
        needle = "FailureCausalCone";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "policy projection regression";
        needle = "failure_signature_policy_projects_versioned_keys_and_result_identity";
      }
      {
        label = "quantifier coarse/default regression";
        needle = "changed_quantifier";
      }
      {
        label = "coverage default regression";
        needle = "changed_coverage";
      }
      {
        label = "fine causal slice regression";
        needle = "changed_slice";
      }
      {
        label = "exact full cone regression";
        needle = "changed_cone_signature";
      }
      {
        label = "exact icount regression";
        needle = "shifted_icount";
      }
      {
        label = "default identity regression";
        needle = "default_identity";
      }
      {
        label = "policy identity regression";
        needle = "fine_identity";
      }
      {
        label = "exact no minimize merge regression";
        needle = "!exact.allows_minimize_merge()";
      }
      {
        label = "exact cone key assertion";
        needle = "exact_causal_cone_material_BEGIN";
      }
      {
        label = "result identity policy assertion";
        needle = "signature_policy_level=default";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green signature policy gate";
        needle = "signaturePolicy = greenBeforeAdvance";
      }
      {
        label = "phase6 signature policy import";
        needle = "gate = import ./phase6-signature-policy.nix";
      }
      {
        label = "phase6 signature policy attr path";
        needle = "checks.crucible.phase6.signaturePolicy";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-TRI-3\"]";
      }
      {
        label = "failure normalization raw dependency";
        needle = "phase6.failureNormalization.rawGate";
      }
      {
        label = "failure normalization green dependency";
        needle = "phase6.failureNormalization";
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
        label = "stringly policy level";
        needle = "level: String";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 signature-policy check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-signature-policy";
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
          name = "run-signature-policy";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-signature-policy-target" \
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
            gate=gate:signature-policy
            source=recorded-run-only
            key=closed-versioned-policy
            RESULT
          '';
        }
      ];
    }
