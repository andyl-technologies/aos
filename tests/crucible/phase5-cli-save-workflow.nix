{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSaveWorkflow",
  taskIds ? ["T-CLI-9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = builtins.readFile ../../crates/crucible-cli/src/main.rs;
  sessionLib = builtins.readFile ../../crates/crucible-session/src/lib.rs;
  apiLifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  apiServer = builtins.readFile ../../crates/crucible-api/src/server.rs;
  apiStreaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
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

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-9 remains open";
        needle = "- [ ] **T-CLI-9** Implement `save`";
      }
      {
        label = "T-CLI-9 progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliSaveWorkflow`";
      }
      {
        label = "T-CLI-9 oracle validated save scope";
        needle = "validates the returned materialized";
      }
      {
        label = "T-CLI-9 process qemu save progress";
        needle = "process-tests real-binary `save --backend qemu`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI save progress note";
        needle = "`T-CLI-9` remains open. `checks.crucible.phase5.cliSaveWorkflow` currently";
      }
      {
        label = "phase5 CLI remote save progress";
        needle = "routes remote-daemon quiescence and virtual-time saves over the RPC control API";
      }
      {
        label = "phase5 CLI remote selector proof progress";
        needle = "routes remote selector proof queries over RPC breakpoint-firing payloads";
      }
      {
        label = "phase5 CLI process qemu save progress";
        needle = "process-tests real-binary `save --backend qemu` JSONL output and handle export";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "save arguments";
        needle = "struct SaveArgs";
      }
      {
        label = "save at enum";
        needle = "enum SaveAtArg";
      }
      {
        label = "save invocation plan";
        needle = "struct SaveInvocationPlan";
      }
      {
        label = "save output target";
        needle = "enum SaveOutputTarget";
      }
      {
        label = "save planner";
        needle = "fn plan_save_invocation";
      }
      {
        label = "virtual time coordinate";
        needle = "max_virtual_time";
      }
      {
        label = "property selector coordinate";
        needle = "--property <assertion>";
      }
      {
        label = "marker selector coordinate";
        needle = "--marker <name>";
      }
      {
        label = "save handle schema";
        needle = "crucible.savepoint-handle.v2";
      }
      {
        label = "save oracle proof";
        needle = "struct SavepointOracleProof";
      }
      {
        label = "save workflow runner";
        needle = "fn run_control_client_save_workflow_async";
      }
      {
        label = "save checkpoint oracle validation";
        needle = "fn validate_savepoint_checkpoint";
      }
      {
        label = "typed savepoint payload";
        needle = "savepoint_info";
      }
      {
        label = "save handle exporter";
        needle = "fn export_savepoint_handle";
      }
      {
        label = "save handle encoder";
        needle = "fn savepoint_handle_bytes";
      }
      {
        label = "remote save workflow runner";
        needle = "fn run_remote_save_workflow";
      }
      {
        label = "remote virtual-time save coverage";
        needle = "remote-virtual-time-save";
      }
      {
        label = "machine-readable handle path summary";
        needle = "out={}";
      }
      {
        label = "create-savepoint reply materialization marker";
        needle = "\"materialization\", \"create-savepoint\", \"reply\"";
      }
      {
        label = "oracle validation status";
        needle = "fat==thin-passed";
      }
      {
        label = "label-bearing create savepoint";
        needle = "SessionCommand::CreateSavepoint";
      }
      {
        label = "property breakpoint selector";
        needle = "SaveAtSelector::PropertyViolation";
      }
      {
        label = "marker breakpoint selector";
        needle = "SaveAtSelector::Marker";
      }
      {
        label = "selector breakpoint proof";
        needle = "fn run_save_selector_to_boundary";
      }
      {
        label = "selector firing validation";
        needle = "fn validate_save_selector_firing";
      }
      {
        label = "selector advancement wait";
        needle = "fn wait_for_save_workflow_advanced_paused";
      }
      {
        label = "scenario assertion evaluator source";
        needle = "HostAssertionEvaluator::new";
      }
      {
        label = "scenario marker source catalog";
        needle = "SaveGuestMarkerSource";
      }
      {
        label = "scenario marker cmdline source";
        needle = "crucible-guest-marker=";
      }
      {
        label = "wrong marker selector rejection";
        needle = "wrong-marker-stop";
      }
      {
        label = "marker selector predicate";
        needle = "Predicate::guest_marker";
      }
      {
        label = "marker selector event-log source";
        needle = "guest_marker_observation";
      }
      {
        label = "second declared property selector test";
        needle = "split-property-stop";
      }
      {
        label = "marker without source test";
        needle = "no-source-marker-stop";
      }
      {
        label = "non-fixed marker selector test";
        needle = "phase-two-marker";
      }
      {
        label = "marker without source helper";
        needle = "write_marker_selector_without_source_scenario";
      }
      {
        label = "selector proof rejection test";
        needle = "cli_save_selector_proof_rejects_invalid_breakpoint_evidence";
      }
      {
        label = "save planning test";
        needle = "cli_save_workflow_plans_quiescence_and_virtual_time_savepoints";
      }
      {
        label = "save export test";
        needle = "cli_save_workflow_executes_local_double_and_exports_handle";
      }
      {
        label = "qemu-selected save runner identity";
        needle = "save-qemu-runner";
      }
      {
        label = "qemu-selected save test";
        needle = "qemu-save";
      }
      {
        label = "qemu-selected dispatch save test";
        needle = "qemu-dispatch-save";
      }
      {
        label = "remote daemon save test";
        needle = "cli_save_workflow_executes_remote_daemon_savepoint";
      }
      {
        label = "remote daemon dispatch save test";
        needle = "remote-dispatch-save";
      }
      {
        label = "remote daemon selector save test";
        needle = "remote-selector-save";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" apiStreaming [
      {
        label = "property selector breakpoint id";
        needle = "breakpoint_id";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" apiLifecycle [
      {
        label = "lifecycle white-box policy hook";
        needle = "with_white_box_policy_provider";
      }
      {
        label = "quiescent loop records schedule decision";
        needle = "quiescent lifecycle loop could not record virtual-time decision";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "RPC snapshot query decoder";
        needle = "QueryResult::Snapshot(EngineSnapshot";
      }
      {
        label = "RPC snapshot scenario identity";
        needle = "query result snapshot scenario id";
      }
      {
        label = "RPC savepoint request label payload";
        needle = "\"savepoint-label\"";
      }
      {
        label = "RPC duration step request payload";
        needle = "\"step-duration-nanos\"";
      }
      {
        label = "RPC breakpoint firing query decoder";
        needle = "parse_breakpoint_firings_fields";
      }
      {
        label = "RPC breakpoint firing result model";
        needle = "QueryResult::BreakpointFirings(firings)";
      }
      {
        label = "RPC breakpoint id response decoder";
        needle = "parse_breakpoint_id_line";
      }
      {
        label = "RPC breakpoint predicate request payload";
        needle = "\"breakpoint-predicate\"";
      }
      {
        label = "RPC breakpoint policy request payload";
        needle = "\"breakpoint-policy\"";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/server.rs" apiServer [
      {
        label = "RPC snapshot query parser";
        needle = "Ok(QueryKind::Snapshot)";
      }
      {
        label = "RPC breakpoint firing query parser";
        needle = "Ok(QueryKind::BreakpointFirings)";
      }
      {
        label = "RPC snapshot result wire";
        needle = "\"snapshot|{}|{}|{}|{}|{}|{}|{}|{}|{}\"";
      }
      {
        label = "RPC breakpoint firing result wire";
        needle = "breakpoint_firings_wire";
      }
      {
        label = "RPC breakpoint firing result prefix";
        needle = "\"breakpoint-firings|{}\"";
      }
      {
        label = "RPC breakpoint id result wire";
        needle = "breakpoint_id_wire";
      }
      {
        label = "RPC breakpoint spec request parser";
        needle = "parse_breakpoint_spec_lines";
      }
      {
        label = "RPC savepoint result wire";
        needle = "\"savepoint|{}|{}|{}\"";
      }
      {
        label = "RPC savepoint request parser";
        needle = "savepoint-label=";
      }
      {
        label = "RPC duration step request parser";
        needle = "step-duration-nanos=";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "breakpoint firing query plumbing";
        needle = "BreakpointFirings";
      }
      {
        label = "guest marker breakpoint policy coverage";
        needle = "breakpoint_conditions_cover_guest_marker_white_box_leaves";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "machine-readable save path test";
        needle = "cli_save_machine_readable_jsonl_reports_handle_path";
      }
      {
        label = "machine-readable save export kind";
        needle = "\\\"kind\\\":\\\"save_export\\\"";
      }
      {
        label = "machine-readable save output path";
        needle = "out=";
      }
      {
        label = "process qemu save JSONL regression";
        needle = "cli_save_qemu_process_jsonl_reports_identity_and_handle";
      }
      {
        label = "process qemu save runner kind";
        needle = "\"save_qemu_runner\"";
      }
      {
        label = "process qemu backend fidelity";
        needle = "summary\\\":\\\"Qemu\\\"";
      }
      {
        label = "process qemu patch series";
        needle = "qemu_patch_series=sha256-process-qemu-patch-series";
      }
      {
        label = "process qemu handle materialization";
        needle = "materialization\\tcreate-savepoint\\treply";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI save workflow check";
        needle = "cliSaveWorkflow = import ./phase5-cli-save-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI save workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-save-workflow";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "unpack";
          script = ''
            set -eu
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            set -eu
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
          name = "run-cli-save-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-cli \
              cli_save \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-session \
              breakpoint_conditions_cover_guest_marker_white_box_leaves \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-cli \
              cli_save_qemu_process_jsonl_reports_identity_and_handle \
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
            check=$ATTR_PATH
            tasks=$TASK_IDS
            component=crucible-cli
            contract=save-workflow-progress
            process_qemu_save=marker-resolved-jsonl-handle
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
