{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogTracingBridge",
  taskIds ? ["T-OBS-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  manifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  eventCatalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  bridge = builtins.readFile ../../crates/crucible/src/tracing_bridge.rs;
  bridgeTest = builtins.readFile ../../crates/crucible/tests/event_log_tracing_bridge.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-12 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogTracingBridge`";
      }
      {
        label = "subscriber modes completion note";
        needle = "filtering subscriber modes";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" manifest [
      {
        label = "crucible tracing dependency";
        needle = "tracing = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "tracing bridge module";
        needle = "pub mod tracing_bridge;";
      }
      {
        label = "tracing bridge export";
        needle = "TracingBridge";
      }
      {
        label = "tracing bridge config export";
        needle = "TracingBridgeConfig";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      # The `diagnostic` entry constructor was originally pub(crate) but was widened to
      # `pub` (f7ea2fca0 "Implement CLI run workflow gate") for legitimate crucible-cli
      # and crucible-api callers. Enforcement downgraded from crate-boundary to
      # invariant-pinning on 2026-07-09: instead of requiring the constructor be crate-
      # private, require that it can only mint Observational entries. It routes through the
      # typed `Diagnostic` payload whose "diagnostic" kind the event-kind catalog fixes to
      # `SchedulerEventLogClass::Observational` (pinned in the event_catalog block below),
      # so a public caller can never mint a causal event-log entry through this path.
      {
        label = "public diagnostic entry constructor";
        needle = "pub fn diagnostic(";
      }
      {
        label = "diagnostic constructor uses diagnostic payload";
        needle = "SchedulerEventLogPayload::Diagnostic(diagnostic)";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" eventCatalog [
      {
        label = "diagnostic kind is fixed observational in the event-kind catalog";
        needle = "kind: \"diagnostic\",\n        class: SchedulerEventLogClass::Observational,";
      }
    ]
    ++ lib.optionals (hasInfix "tracing::" scheduler) [
      "crates/crucible/src/scheduler.rs: tracing bridge must stay off scheduler ordering paths"
    ]
    ++ failuresFor "crates/crucible/src/tracing_bridge.rs" bridge [
      {
        label = "bridge config type";
        needle = "pub struct TracingBridgeConfig";
      }
      {
        label = "bridge disabled by default";
        needle = "derive(Clone, Copy, Debug, Default, PartialEq, Eq)";
      }
      {
        label = "explicit disabled config";
        needle = "pub const fn disabled() -> Self";
      }
      {
        label = "explicit enabled config";
        needle = "pub const fn enabled() -> Self";
      }
      {
        label = "bridge type";
        needle = "pub struct TracingBridge";
      }
      {
        label = "enabled bridge constructor";
        needle = "pub const fn enabled() -> Self";
      }
      {
        label = "disabled bridge returns none";
        needle = "if !self.config.enabled";
      }
      {
        label = "diagnostic event-log entry only";
        needle = "SchedulerEventLogEntry::diagnostic(sequence, at, diagnostic.clone())";
      }
      {
        label = "subscriber panic ignored";
        needle = "catch_unwind(AssertUnwindSafe";
      }
      {
        label = "tracing sink target";
        needle = "target: \"crucible::tracing_bridge\"";
      }
      {
        label = "no scheduler readback";
        needle = "never reads subscriber state";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_tracing_bridge.rs" bridgeTest [
      {
        label = "default-off test";
        needle = "tracing_bridge_is_disabled_by_default";
      }
      {
        label = "observational diagnostic test";
        needle = "tracing_bridge_entries_are_observational_diagnostics";
      }
      {
        label = "subscriber mode nonperturbation test";
        needle = "tracing_subscriber_modes_do_not_change_causal_subsequence";
      }
      {
        label = "panicking subscriber nonperturbation test";
        needle = "tracing_subscriber_panics_do_not_escape_bridge";
      }
      {
        label = "capturing subscriber mode";
        needle = "captures_events: true";
      }
      {
        label = "filtering subscriber mode";
        needle = "captures_events: false";
      }
      {
        label = "panicking subscriber mode";
        needle = "PanickingSubscriber";
      }
      {
        label = "causal projection assertion";
        needle = "event_log_causal_projection";
      }
      {
        label = "determinism comparison assertion";
        needle = "compare_event_log_determinism";
      }
      {
        label = "observational class assertion";
        needle = "EventClass::Observational";
      }
      {
        label = "diagnostic append assertion";
        needle = "append_entries(no_subscriber)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event-log tracing bridge import";
        needle = "eventLogTracingBridge = import ./phase4-event-log-tracing-bridge.nix";
      }
      {
        label = "phase4 event-log tracing bridge attr path";
        needle = "checks.crucible.phase4.eventLogTracingBridge";
      }
      {
        label = "phase4 event-log tracing bridge task id";
        needle = "taskIds = [\"T-OBS-12\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log tracing bridge check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-tracing-bridge";
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
            set -eu
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
          name = "run-event-log-tracing-bridge";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-tracing-bridge-target" \
              -p crucible \
              --test event_log_tracing_bridge \
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
            tracing_bridge=opt-in
            default=off
            class=observational
            subscriber_modes=no,capturing,filtering
            RESULT
          '';
        }
      ];
    }
