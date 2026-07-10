{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionEvaluationOrder",
  taskIds ? ["T-ASRT-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  orderTest = builtins.readFile ../../crates/crucible/tests/assertion_evaluation_order.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-11 checked off";
        needle = "- [x] **T-ASRT-11**";
      }
      {
        label = "T-ASRT-11 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionEvaluationOrder`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "canonical assertion ordering helper";
        needle = "fn canonical_assertions";
      }
      {
        label = "assertion id primary sort key";
        needle = "left.id";
      }
      {
        label = "assertion id comparison";
        needle = ".cmp(&right.id)";
      }
      {
        label = "canonical property accessor";
        needle = "Returns property assertions in their canonical order.";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "evaluator state vector";
        needle = "states: Vec<HostAssertionState>";
      }
      {
        label = "canonical evaluator constructor";
        needle = "Builds an evaluator for the assertions in canonical property order.";
      }
      {
        label = "property order source";
        needle = ".assertions()";
      }
      {
        label = "deterministic state fold";
        needle = "for state in &mut self.states";
      }
      {
        label = "point-local leaf cache";
        needle = "type HostConditionEvaluationCache = BTreeMap<HostConditionLeafKey, bool>;";
      }
      {
        label = "leaf cache field";
        needle = "leaf_cache: &'state mut HostConditionEvaluationCache";
      }
      {
        label = "leaf cache key";
        needle = "HostConditionLeafKey::from_leaf";
      }
      {
        label = "cached condition helper";
        needle = "host_condition_is_true_with_cache";
      }
      {
        label = "deterministic deadline set";
        needle = "let mut deadlines = BTreeSet::new();";
      }
      {
        label = "sorted outcome emission";
        needle = "sort_host_assertion_outcomes";
      }
      {
        label = "offline shared evaluator";
        needle = "HostAssertionEvaluator::new(properties)";
      }
      {
        label = "offline custom oracle";
        needle = "check_run_with_oracle";
      }
      {
        label = "guest marker sorted insertion";
        needle = "binary_search_by";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_evaluation_order.rs" orderTest [
      {
        label = "stable id evaluation order test";
        needle = "properties_are_evaluated_by_stable_id_and_each_named_predicate_once_per_point";
      }
      {
        label = "online/offline order test";
        needle = "online_and_offline_custom_oracles_observe_identical_order";
      }
      {
        label = "compound duplicate single-evaluation test";
        needle = "duplicate_named_leaves_inside_one_predicate_are_evaluated_once_per_point";
      }
      {
        label = "eventually duplicate single-evaluation test";
        needle = "eventually_trigger_and_property_share_one_named_leaf_evaluation_per_point";
      }
      {
        label = "oracle call capture";
        needle = "struct RecordingOracle";
      }
      {
        label = "event-log offset capture";
        needle = "observed.event_log_offset().events";
      }
      {
        label = "per-point expected order";
        needle = "expected_calls_at";
      }
      {
        label = "retained offset input";
        needle = "RecordedAssertionLog::from_segments";
      }
      {
        label = "online evaluator path";
        needle = "HostAssertionEvaluator::new";
      }
      {
        label = "offline evaluator path";
        needle = "check_run_with_oracle";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion evaluation order import";
        needle = "assertionEvaluationOrder = import ./phase4-assertion-evaluation-order.nix";
      }
      {
        label = "phase4 assertion evaluation order attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionEvaluationOrder\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_evaluation_order.rs" orderTest [
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
    ];
in
  if failures != []
  then throw "crucible phase4 assertion-evaluation-order check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-assertion-evaluation-order";
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
          name = "run-assertion-evaluation-order";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-assertion-evaluation-order-target" \
              -p crucible \
              --test assertion_evaluation_order \
              --test assertion_evaluation_timing \
              --test offline_assertion_checker \
              --test assertion_log_fold \
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
            assertion_evaluation_order=true
            RESULT
          '';
        }
      ];
    }
