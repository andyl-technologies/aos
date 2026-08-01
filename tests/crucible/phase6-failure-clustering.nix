{
  attrPath ? "checks.crucible.phase6.failureClustering",
  dependencies ? [],
  lib,
  pkgs,
  taskIds ? ["T-TRI-4"],
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
        label = "T-TRI-4 completion note";
        needle = "Completed by `checks.crucible.phase6.failureClustering`";
      }
      {
        label = "equivalence class note";
        needle = "equivalence-class partition";
      }
      {
        label = "content-address ordering note";
        needle = "content-address ordered";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-4 plan summary";
        needle = "checks.crucible.phase6.failureClustering";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "cluster finding input";
        needle = "pub struct FailureClusterFinding";
      }
      {
        label = "cluster member";
        needle = "pub struct FailureClusterMember";
      }
      {
        label = "cluster";
        needle = "pub struct FailureCluster";
      }
      {
        label = "clustering result";
        needle = "pub struct FailureClusteringResult";
      }
      {
        label = "deterministic clustering constructor";
        needle = "pub fn from_findings";
      }
      {
        label = "BTreeMap cluster ordering";
        needle = "let mut clusters = BTreeMap::new();";
      }
      {
        label = "BTreeMap member ordering";
        needle = "members: BTreeMap<ContentHash, FailureClusterMember>";
      }
      {
        label = "cluster id from key";
        needle = "let cluster_id = signature_key.content_hash();";
      }
      {
        label = "distinct key collision guard";
        needle = "distinct signature keys collided to one cluster id";
      }
      {
        label = "duplicate artifact guard";
        needle = "same reproduction artifact has conflicting failure signatures";
      }
      {
        label = "report material duplicate guard";
        needle = "signature_report";
      }
      {
        label = "previous report comparison";
        needle = "previous_report";
      }
      {
        label = "representative member";
        needle = "representative_member";
      }
      {
        label = "member hashes";
        needle = "member_hashes";
      }
      {
        label = "canonical clustering material";
        needle = "failure_clustering_result_material";
      }
      {
        label = "clustering result domain";
        needle = "FAILURE_CLUSTERING_RESULT_DOMAIN";
      }
      {
        label = "member content material";
        needle = "cluster.member.reproduction_artifact";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "cluster finding export";
        needle = "FailureClusterFinding";
      }
      {
        label = "cluster member export";
        needle = "FailureClusterMember";
      }
      {
        label = "cluster export";
        needle = "FailureCluster";
      }
      {
        label = "clustering result export";
        needle = "FailureClusteringResult";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "clustering regression";
        needle = "failure_clustering_partitions_and_orders_by_signature_key";
      }
      {
        label = "input order regression";
        needle = "reversed_inputs";
      }
      {
        label = "cluster count regression";
        needle = "clustered.cluster_count()";
      }
      {
        label = "member count regression";
        needle = "clustered.member_count()";
      }
      {
        label = "cluster id ordering regression";
        needle = "sorted_cluster_ids";
      }
      {
        label = "member ordering regression";
        needle = "sorted_member_hashes";
      }
      {
        label = "key equivalence regression";
        needle = "key.content_hash() == base_cluster.id";
      }
      {
        label = "coarse partition regression";
        needle = "coarse clusters by failure kind and property id only";
      }
      {
        label = "fine partition regression";
        needle = "fine separates the causal slice hash";
      }
      {
        label = "conflict regression";
        needle = "same reproduction artifact cannot carry conflicting signatures";
      }
      {
        label = "same key report drift regression";
        needle = "report_only_conflict";
      }
      {
        label = "report material drift assertion";
        needle = "same-key duplicate artifact with different report material must be rejected";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green failure clustering gate";
        needle = "failureClustering = greenBeforeAdvance";
      }
      {
        label = "phase6 failure clustering import";
        needle = "gate = import ./phase6-failure-clustering.nix";
      }
      {
        label = "phase6 failure clustering attr path";
        needle = "checks.crucible.phase6.failureClustering";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-TRI-4\"]";
      }
      {
        label = "signature policy raw dependency";
        needle = "phase6.signaturePolicy.rawGate";
      }
      {
        label = "signature policy green dependency";
        needle = "phase6.signaturePolicy";
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
  then throw "crucible phase6 failure-clustering check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-failure-clustering";
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
          name = "run-failure-clustering";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-failure-clustering-target" \
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
            gate=gate:failure-clustering
            source=recorded-signatures-only
            key=content-address-ordered-partition
            RESULT
          '';
        }
      ];
    }
