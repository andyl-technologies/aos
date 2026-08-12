{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.formalTraceExport",
  taskIds ? ["T-ASRT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  crateManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  formalTraceExportTest = builtins.readFile ../../crates/crucible/tests/formal_trace_export.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-9 completion note";
        needle = "Completed by `checks.crucible.phase4.formalTraceExport`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "external formal trace export";
        needle = "pub struct ExternalFormalTraceExport";
      }
      {
        label = "external formal trace exporter";
        needle = "pub struct ExternalFormalTraceExporter";
      }
      {
        label = "trace export method";
        needle = "pub fn export_event_log";
      }
      {
        label = "recorded log validation";
        needle = "validate_recorded_event_log_entries";
      }
      {
        label = "trace bytes content hash";
        needle = "ContentHash::from_bytes(&bytes)";
      }
      {
        label = "event-log empty-prefix provenance";
        needle = "scheduler_event_log_empty_prefix";
      }
      {
        label = "stable trace entry material";
        needle = "external_formal_trace_entry_material";
      }
      {
        label = "stable observable material";
        needle = "external_observable_event_payload_material";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "trace export type export";
        needle = "ExternalFormalTraceExport";
      }
      {
        label = "trace exporter export";
        needle = "ExternalFormalTraceExporter";
      }
    ]
    ++ failuresFor "crates/crucible/tests/formal_trace_export.rs" formalTraceExportTest [
      {
        label = "deterministic trace export test";
        needle = "formal_trace_export_is_deterministic_trace_bytes_only";
      }
      {
        label = "invalid log rejection test";
        needle = "formal_trace_export_rejects_invalid_recorded_log";
      }
      {
        label = "free-form string hex encoding test";
        needle = "formal_trace_export_hex_encodes_free_form_strings";
      }
      {
        label = "no runtime evaluator test";
        needle = "formal_trace_export_does_not_add_runtime_formal_evaluator";
      }
      {
        label = "runtime source scan covers scheduler";
        needle = "include_str!(\"../src/scheduler.rs\")";
      }
      {
        label = "runtime source scan covers trigger";
        needle = "include_str!(\"../src/trigger.rs\")";
      }
      {
        label = "manifest dependency scan";
        needle = "include_str!(\"../Cargo.toml\")";
      }
      {
        label = "debug material guard";
        needle = "scheduler segment material";
      }
      {
        label = "solver type guard";
        needle = "struct Solver";
      }
      {
        label = "model-check guard";
        needle = "model_check";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 formal trace export import";
        needle = "formalTraceExport = import ./phase4-formal-trace-export.nix";
      }
      {
        label = "phase4 formal trace export attr path";
        needle = "attrPath = \"checks.crucible.phase4.formalTraceExport\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "solver type";
        needle = "struct Solver";
      }
      {
        label = "model checker type";
        needle = "struct ModelChecker";
      }
      {
        label = "spec evaluator type";
        needle = "struct SpecEvaluator";
      }
      {
        label = "conformance checker";
        needle = "check_conformance";
      }
      {
        label = "spec evaluation entry";
        needle = "evaluate_spec";
      }
    ]
    ++ forbiddenFor "crates/crucible/Cargo.toml" crateManifest [
      {
        label = "SMT dependency";
        needle = "smt";
      }
      {
        label = "Z3 dependency";
        needle = "z3";
      }
      {
        label = "TLA dependency";
        needle = "tla";
      }
      {
        label = "Alloy dependency";
        needle = "alloy";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/formal_trace_export.rs" formalTraceExportTest [
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
  then throw "crucible phase4 formal-trace-export check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-formal-trace-export";
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
          name = "run-formal-trace-export";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-formal-trace-export-target" \
              -p crucible \
              --test formal_trace_export \
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
            formal_trace_export=true
            RESULT
          '';
        }
      ];
    }
