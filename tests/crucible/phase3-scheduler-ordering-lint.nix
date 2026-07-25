{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerOrderingLint",
  taskIds ? ["T-SCHED-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;
  clippyConfig = builtins.readFile ../../crates/clippy.toml;
  harnessLintMain = builtins.readFile ../../crates/crucible-harness/tests/harness_lint.rs;
  harnessLintAnnotations = builtins.readFile ../../crates/crucible-harness/tests/harness_lint_annotations.rs;
  harnessLintCommon = builtins.readFile ../../crates/crucible-harness/tests/support/harness_lint/common.rs;
  harnessLintScan = builtins.readFile ../../crates/crucible-harness/tests/support/harness_lint/scan.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  eventOrderTest = builtins.readFile ../../crates/crucible/tests/scheduler_event_order.rs;

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

  orderingPathSources = [
    {
      label = "crates/crucible/src/scheduler.rs";
      content = scheduler;
    }
    {
      label = "crates/crucible/src/model.rs";
      content = model;
    }
    {
      label = "crates/crucible/src/model/canonical.rs";
      content = canonical;
    }
  ];

  bannedOrderingTokens = [
    {
      label = "HashMap on scheduler ordering path";
      needle = "HashMap";
    }
    {
      label = "HashSet on scheduler ordering path";
      needle = "HashSet";
    }
    {
      label = "default hasher on scheduler ordering path";
      needle = "DefaultHasher";
    }
    {
      label = "random default hash state on scheduler ordering path";
      needle = "RandomState";
    }
    {
      label = "std hash_map module on scheduler ordering path";
      needle = "std::collections::hash_map";
    }
  ];

  orderingPathFailures =
    lib.concatMap (
      source:
        forbiddenFor source.label source.content bannedOrderingTokens
    )
    orderingPathSources;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-9 checked off";
        needle = "- [x] **T-SCHED-9**";
      }
      {
        label = "T-SCHED-9 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerOrderingLint`";
      }
      {
        label = "SCHED-19 default hasher requirement";
        needle = "never the language's default randomized hasher";
      }
      {
        label = "gate:harness-lint routing";
        needle = "*Gate:* `gate:harness-lint`";
      }
    ]
    ++ failuresFor "crates/clippy.toml" clippyConfig [
      {
        label = "HashMap disallowed type";
        needle = "std::collections::HashMap";
      }
      {
        label = "HashSet disallowed type";
        needle = "std::collections::HashSet";
      }
      {
        label = "DefaultHasher disallowed type";
        needle = "std::collections::hash_map::DefaultHasher";
      }
      {
        label = "RandomState disallowed type";
        needle = "std::collections::hash_map::RandomState";
      }
      {
        label = "stable identity-hash rationale";
        needle = "default hash seeding is not a stable identity hash";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/harness_lint/common.rs" harnessLintCommon [
      {
        label = "DefaultHasher clippy mirror";
        needle = "std::collections::hash_map::DefaultHasher";
      }
      {
        label = "RandomState clippy mirror";
        needle = "std::collections::hash_map::RandomState";
      }
      {
        label = "default-random-hasher allow rule";
        needle = "\"default-random-hasher\"";
      }
      {
        label = "hash iteration method set";
        needle = "HASH_ITERATION_METHODS";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/harness_lint/scan.rs" harnessLintScan [
      {
        label = "scan bans DefaultHasher and RandomState";
        needle = "\"DefaultHasher\" | \"RandomState\"";
      }
      {
        label = "default-random-hasher rule";
        needle = "\"default-random-hasher\"";
      }
      {
        label = "default hasher custom tier";
        needle = "default_random_hasher_failures";
      }
      {
        label = "unordered map iteration tier";
        needle = "hash_container_iteration_failures";
      }
      {
        label = "hash iteration methods enforced";
        needle = "HASH_ITERATION_METHODS.contains";
      }
      {
        label = "for loop hash iteration rejection";
        needle = "for_loop_hash_iteration_failure";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/harness_lint.rs" harnessLintMain [
      {
        label = "DefaultHasher scan regression";
        needle = "std::collections::hash_map::DefaultHasher::new()";
      }
      {
        label = "spaced DefaultHasher regression";
        needle = "DefaultHasher :: new()";
      }
      {
        label = "RandomState regression";
        needle = "RandomState :: new()";
      }
      {
        label = "default/random hasher assertion";
        needle = "assert_contains(&findings, \"default/random hasher\")";
      }
      {
        label = "hash-container iteration assertion";
        needle = "assert_contains(&findings, \"unordered hash-container iteration\")";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/harness_lint_annotations.rs" harnessLintAnnotations [
      {
        label = "annotated default hasher exception";
        needle = "allow default-random-hasher";
      }
      {
        label = "annotated default hasher path";
        needle = "std::collections::hash_map::DefaultHasher::new()";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduled event total-order key";
        needle = "pub struct ScheduledEventKey";
      }
      {
        label = "canonical due-event ordering";
        needle = "ordered_scheduled_events";
      }
      {
        label = "ordered due-event sort";
        needle = "ordered.sort_by(|left, right| left.key.cmp(&right.key))";
      }
      {
        label = "scheduler-owned event sequence state";
        needle = "event_sequences: EventSequenceState";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" canonical [
      {
        label = "ordered scheduler state map";
        needle = "use std::collections::BTreeMap";
      }
      {
        label = "canonical event sequence writer";
        needle = "fn write_event_sequence_state";
      }
      {
        label = "canonical event sequence key order";
        needle = "for (key, next) in &state.next";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_event_order.rs" eventOrderTest [
      {
        label = "event key total order regression";
        needle = "scheduled_event_keys_order_by_virtual_consumer_producer_sequence";
      }
      {
        label = "materialized scheduler state hash regression";
        needle = "event_sequence_state_is_carried_in_materialized_scheduler_state_hash";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler ordering lint check";
        needle = "schedulerOrderingLint = import ./phase3-scheduler-ordering-lint.nix";
      }
    ]
    ++ orderingPathFailures;
in
  if failures != []
  then throw "crucible phase3 scheduler ordering-lint check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-ordering-lint";
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
          name = "run-scheduler-ordering-lint";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-ordering-lint-target" \
              -p crucible-harness \
              --test harness_lint \
              harness_lint_rejects_banned_code_patterns \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-ordering-lint-target" \
              -p crucible-harness \
              --test harness_lint \
              harness_lint_rejects_spaced_paths_and_grouped_imports \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-ordering-lint-target" \
              -p crucible-harness \
              --test harness_lint \
              harness_lint_rejects_custom_static_analysis_drift \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-ordering-lint-target" \
              -p crucible-harness \
              --test harness_lint_annotations \
              harness_lint_enforces_annotated_exceptions \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-ordering-lint-target" \
              -p crucible \
              --test scheduler_event_order \
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
            gate=gate:harness-lint
            tasks=${taskList}
            component=crucible-scheduler
            ordering_path=no-unordered-map-set-default-random-hasher
            custom_static_tier=hash-iteration,default-random-hasher
            rust_tests=crucible-harness::harness_lint-focused,crucible::scheduler_event_order
            RESULT
          '';
        }
      ];
    }
