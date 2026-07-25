{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogClassCatalog",
  taskIds ? ["T-OBS-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  catalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  catalogTest = builtins.readFile ../../crates/crucible/tests/event_log_class_catalog.rs;
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
        label = "T-OBS-4 checked off";
        needle = "- [x] **T-OBS-4**";
      }
      {
        label = "T-OBS-4 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogClassCatalog`";
      }
      {
        label = "typed payload-kind completion note";
        needle = "typed payload-kind\n  catalog";
      }
      {
        label = "catalog class requirement";
        needle = "class is a\n  function of the payload kind";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "entry class schema field";
        needle = "class: SchedulerEventLogClass";
      }
      {
        label = "catalog class helper";
        needle = "fn event_kind_catalog_class(payload: &EventPayload)";
      }
      {
        label = "constructor derives payload first";
        needle = "let event_payload = event_payload_from_scheduler_payload(&payload);";
      }
      {
        label = "constructor derives class from typed payload";
        needle = "event_kind_catalog_class_for_entry_construction(&event_payload)";
      }
      {
        label = "entry class catalog predicate";
        needle = "pub fn class_matches_catalog(&self) -> bool";
      }
      {
        label = "append lint calls catalog predicate";
        needle = "if !entry.class_matches_catalog()";
      }
      {
        label = "append lint reads typed payload";
        needle = "event_kind_catalog_class(entry.event_payload())";
      }
      {
        label = "append lint message";
        needle = "does not match catalog class";
      }
      {
        label = "class lookup reads versioned catalog";
        needle = "crate::event_catalog::event_kind_catalog_class(payload.kind())";
      }
      {
        label = "private class mismatch unit test";
        needle = "event_log_append_rejects_class_catalog_mismatch";
      }
      {
        label = "private typed kind drift unit test";
        needle = "event_log_append_rejects_typed_kind_catalog_drift";
      }
      {
        label = "unknown typed kind unit test";
        needle = "event_log_append_rejects_unknown_typed_kind";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" catalog [
      {
        label = "versioned catalog";
        needle = "EVENT_KIND_CATALOG_VERSION";
      }
      {
        label = "causal backend kind";
        needle = "\"backend_input\"";
      }
      {
        label = "causal rng kind";
        needle = "\"rng_draw\"";
      }
      {
        label = "trigger firing catalog kind";
        needle = "\"trigger_fired\"";
      }
      {
        label = "observed io distinct kind";
        needle = "\"observed_io_completion\"";
      }
      {
        label = "diagnostic catalog kind";
        needle = "kind: \"diagnostic\"";
      }
      {
        label = "diagnostic observational class";
        needle = "class: SchedulerEventLogClass::Observational";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_class_catalog.rs" catalogTest [
      {
        label = "catalog derivation test";
        needle = "event_class_is_derived_from_payload_kind_catalog";
      }
      {
        label = "class predicate tested";
        needle = "class_matches_catalog()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event-log class catalog check";
        needle = "eventLogClassCatalog = import ./phase4-event-log-class-catalog.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_class_catalog.rs" catalogTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "public mismatch helper";
        needle = "condition_entry_with_class_for_test";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "enum payload catalog lookup";
        needle = "event_kind_catalog_class(entry.payload())";
      }
      {
        label = "catalog function over scheduler payload";
        needle = "fn event_kind_catalog_class(payload: &SchedulerEventLogPayload)";
      }
      {
        label = "public class test helper";
        needle = "with_class_for_test";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log class catalog check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-class-catalog";
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
          name = "run-event-log-class-catalog";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-class-catalog-target" \
              -p crucible \
              --test event_log_class_catalog \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-class-catalog-target" \
              -p crucible \
              --lib event_log_append_rejects \
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
            component=crucible-event-log
            class_is_catalog_derived=true
            append_lint_rejects_mismatch=true
            RESULT
          '';
        }
      ];
    }
