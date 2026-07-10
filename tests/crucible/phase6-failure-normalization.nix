{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.failureNormalization",
  taskIds ? ["T-TRI-2"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  triageDoc = builtins.readFile ../../docs/rfcs/0010-crucible/34-failure-triage.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  signatureTest = builtins.readFile ../../crates/crucible/tests/gate_failure_signature.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
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

  failures =
    failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "T-TRI-2 checked off";
        needle = "- [x] **T-TRI-2**";
      }
      {
        label = "T-TRI-2 completion note";
        needle = "Completed by `checks.crucible.phase6.failureNormalization`";
      }
      {
        label = "absolute icount report-only invariant";
        needle = "at_icount_report_only";
      }
      {
        label = "symmetry canonical invariant";
        needle = "symmetry-canonical";
      }
      {
        label = "causal cone invariant";
        needle = "causal cone";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-2 plan summary";
        needle = "checks.crucible.phase6.failureNormalization";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "normalization input";
        needle = "pub struct FailureSignatureNormalization";
      }
      {
        label = "symmetry canonicalizer";
        needle = "pub struct FailureSymmetryCanonicalizer";
      }
      {
        label = "normalizing property constructor";
        needle = "from_recorded_property_violation_with_normalization";
      }
      {
        label = "normalizing divergence constructor";
        needle = "from_recorded_divergence_with_normalization";
      }
      {
        label = "report-only icount field";
        needle = "pub at_icount_report_only: Option<Icount>";
      }
      {
        label = "report-only icount excluded from key";
        needle = "failure_signature_report_material";
      }
      {
        label = "canonical node relabel";
        needle = "canonical_node(&self, node: &NodeId)";
      }
      {
        label = "symmetry class label";
        needle = "symmetry-class";
      }
      {
        label = "cone hash domain";
        needle = "FAILURE_CAUSAL_SLICE_DOMAIN";
      }
      {
        label = "cone material function";
        needle = "failure_causal_cone_through_index";
      }
      {
        label = "typed dependency cone";
        needle = "failure_causal_dependency_keys";
      }
      {
        label = "dependency cone selector";
        needle = "failure_causal_cone_entries";
      }
      {
        label = "property violation point validation";
        needle = "validate_violation_point";
      }
      {
        label = "divergence point returns causal index";
        needle = "Result<usize, EngineError>";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "normalization export";
        needle = "FailureSignatureNormalization";
      }
      {
        label = "canonicalizer export";
        needle = "FailureSymmetryCanonicalizer";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "normalization regression test";
        needle = "failure_signature_applies_t_tri_2_normalizations";
      }
      {
        label = "report-only icount regression";
        needle = "at_icount_report_only=8";
      }
      {
        label = "icount not in key regression";
        needle = "!replica_a_signature";
      }
      {
        label = "symmetry class regression";
        needle = "symmetry-class:8:replicas";
      }
      {
        label = "out-of-cone causal stability regression";
        needle = "trailing_causal_entries";
      }
      {
        label = "pre-failure out-of-cone regression";
        needle = "prefailure_out_of_cone_entries";
      }
      {
        label = "shifted recorded icount regression";
        needle = "shifted_log_signature";
      }
      {
        label = "cone hash equality regression";
        needle = "trailing_signature.causal_slice_hash";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green failure normalization gate";
        needle = "failureNormalization = greenBeforeAdvance";
      }
      {
        label = "phase6 failure normalization import";
        needle = "gate = import ./phase6-failure-normalization.nix";
      }
      {
        label = "phase6 failure normalization attr path";
        needle = "checks.crucible.phase6.failureNormalization";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-TRI-2\"]";
      }
      {
        label = "failure signature raw dependency";
        needle = "phase6.failureSignature.rawGate";
      }
      {
        label = "failure signature green dependency";
        needle = "phase6.failureSignature";
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
        label = "deferred causal slice";
        needle = "until the T-TRI-2 cone normalization";
      }
      {
        label = "whole causal projection as cone hash";
        needle = "causal_slice_hash: Some(event_log.causal_subsequence";
      }
      {
        label = "sequence in causal slice key";
        needle = "entry.sequence=";
      }
      {
        label = "virtual time in causal slice key";
        needle = "entry.virtual_time=";
      }
      {
        label = "absolute icount in causal slice key";
        needle = "entry.icount=";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 failure-normalization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-failure-normalization";
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
          name = "run-failure-normalization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-failure-normalization-target" \
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
            gate=gate:failure-normalization
            source=recorded-run-only
            key=report-only-icount-symmetry-cone
            RESULT
          '';
        }
      ];
    }
