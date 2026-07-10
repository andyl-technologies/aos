{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogAssertionFold",
  taskIds ? ["T-OBS-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  eventCatalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  assertionLogFoldTest = builtins.readFile ../../crates/crucible/tests/assertion_log_fold.rs;
  classCatalogTest = builtins.readFile ../../crates/crucible/tests/event_log_class_catalog.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
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
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-7 checked off";
        needle = "- [x] **T-OBS-7**";
      }
      {
        label = "T-OBS-7 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogAssertionFold`";
      }
      {
        label = "one-log assertion fold completion note";
        needle = "same `HostAssertionEvaluator` fold live and\n  offline";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" eventCatalog [
      {
        label = "assertion evaluated catalog kind is causal";
        needle = "kind: \"assertion_evaluated\",\n        class: SchedulerEventLogClass::Causal,";
      }
      {
        label = "assertion state changed catalog kind is causal";
        needle = "kind: \"assertion_state_changed\",\n        class: SchedulerEventLogClass::Causal,";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "guest assertion marker projects through guest_marker kind";
        needle = "EventPayload::new(\"guest_marker\", attributes)";
      }
      {
        label = "guest marker kind attribute";
        needle = "String::from(\"marker_kind\")";
      }
      {
        label = "guest assertion marker typed assertion attribute";
        needle = "String::from(\"assertion\")";
      }
      {
        label = "assertion state id attribute";
        needle = "String::from(\"id\")";
      }
      {
        label = "assertion state new-state attribute";
        needle = "String::from(\"new_state\")";
      }
      {
        label = "guest assertion marker typed condition attribute";
        needle = "String::from(\"condition\")";
      }
      {
        label = "guest assertion marker structured details length";
        needle = "String::from(\"details_len\")";
      }
      {
        label = "guest assertion marker structured detail values";
        needle = "format!(\"detail.{index}.value\")";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "offline reconstructs condition prefix from recorded log";
        needle = "condition_prefix_from_recorded_log";
      }
      {
        label = "offline checker feeds shared evaluator";
        needle = "HostAssertionEvaluator::new(properties)";
      }
      {
        label = "typed assertion-evaluated observable";
        needle = "ObservableEventPayload::AssertionEvaluated";
      }
      {
        label = "assertion-evaluated constructor";
        needle = "pub fn assertion_evaluated";
      }
      {
        label = "online/offline use same finalizer";
        needle = "finalize_prefix";
      }
      {
        label = "guest marker assertion fold";
        needle = "fn observe_guest_marker_assertions";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_log_fold.rs" assertionLogFoldTest [
      {
        label = "assertion state one-log parity test";
        needle = "online_and_offline_fold_read_assertion_state_changes_from_one_event_log";
      }
      {
        label = "assertion evaluated one-log parity test";
        needle = "online_and_offline_fold_read_assertion_evaluated_entries_from_one_event_log";
      }
      {
        label = "guest marker one-log parity test";
        needle = "online_and_offline_fold_read_white_box_markers_from_one_event_log";
      }
      {
        label = "assertion state event kind asserted";
        needle = "assertion_state_changed";
      }
      {
        label = "assertion evaluated event kind asserted";
        needle = "assertion_evaluated";
      }
      {
        label = "assertion state is causal";
        needle = "EventClass::Causal";
      }
      {
        label = "guest assertion marker stored as guest_marker";
        needle = "marker_kind";
      }
      {
        label = "whole report equality";
        needle = "assert_eq!(offline, online)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_class_catalog.rs" classCatalogTest [
      {
        label = "assertion/guest marker catalog class regression";
        needle = "assertion_and_guest_marker_kinds_follow_rfc_catalog_classes";
      }
      {
        label = "assertion state changed is causal";
        needle = "assert_eq!(assertion_entry.class(), EventClass::Causal)";
      }
      {
        label = "assertion evaluated is causal";
        needle = "assert_eq!(evaluated_entry.class(), EventClass::Causal)";
      }
      {
        label = "assertion state id attribute tested";
        needle = "assertion_entry.event_payload().string(\"id\")";
      }
      {
        label = "assertion state new-state attribute tested";
        needle = "assertion_entry.event_payload().string(\"new_state\")";
      }
      {
        label = "guest marker assertion projects to guest_marker";
        needle = "assert_eq!(guest_marker_entry.event_payload().kind(), \"guest_marker\")";
      }
      {
        label = "guest marker assertion exposes detail count";
        needle = "event_payload().u64(\"details_len\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event log assertion fold import";
        needle = "eventLogAssertionFold = import ./phase4-event-log-assertion-fold.nix";
      }
      {
        label = "phase4 event log assertion fold attr path";
        needle = "checks.crucible.phase4.eventLogAssertionFold";
      }
      {
        label = "phase4 event log assertion fold task id";
        needle = "taskIds = [\"T-OBS-7\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/assertion_log_fold.rs" assertionLogFoldTest [
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
  then throw "crucible phase4 event-log assertion-fold check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-assertion-fold";
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
          name = "run-event-log-assertion-fold";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-assertion-fold-target" \
              -p crucible \
              --test assertion_log_fold \
              --test event_log_class_catalog \
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
            event_log_assertion_fold=true
            RESULT
          '';
        }
      ];
    }
