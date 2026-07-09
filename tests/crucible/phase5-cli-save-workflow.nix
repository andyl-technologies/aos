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
  apiControlClient = builtins.readFile ../../crates/crucible-api/tests/gate_control_client.rs;
  apiLifecycleUnary = builtins.readFile ../../crates/crucible-api/tests/gate_lifecycle_unary.rs;
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  defaultChecks = builtins.readFile ./default.nix;
  saveWorkflowGate = builtins.readFile ./phase5-cli-save-workflow.nix;

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
        label = "T-CLI-9 checklist complete";
        needle = "- [x] **T-CLI-9** Implement `save`";
      }
      {
        label = "T-CLI-9 completion note";
        needle = "Completed by `checks.crucible.phase5.cliSaveWorkflow`";
      }
      {
        label = "T-CLI-9 oracle validated save scope";
        needle = "validates the returned materialized";
      }
      {
        label = "T-CLI-9 process qemu save progress";
        needle = "process-tests real-binary `save --backend qemu`";
      }
      {
        label = "T-CLI-9 remote selector source transfer progress";
        needle = "transfers arbitrary scenario selector sources";
      }
      {
        label = "T-CLI-9 backend-executed QEMU savepoint completion";
        needle = "backend-executed patched-QEMU `snapshot-save`\n  smoke";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI save completion note";
        needle = "`T-CLI-9` is green through `checks.crucible.phase5.cliSaveWorkflow`";
      }
      {
        label = "phase5 CLI remote save progress";
        needle = "routes\n  remote-daemon quiescence and virtual-time saves over the RPC control API";
      }
      {
        label = "phase5 CLI remote selector proof progress";
        needle = "routes remote selector proof\n  queries over RPC breakpoint-firing payloads";
      }
      {
        label = "phase5 CLI process qemu save progress";
        needle = "process-tests real-binary\n  `save --backend qemu` JSONL output and handle export";
      }
      {
        label = "phase5 CLI remote selector source transfer progress";
        needle = "transfers arbitrary scenario\n  selector sources";
      }
      {
        label = "phase5 CLI backend-executed QEMU savepoint completion";
        needle = "backend-executed patched-QEMU\n  `snapshot-save` smoke";
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
      {
        label = "remote inline scenario source transfer";
        needle = "CreateSessionRequest::inline_form(run_plan.scenario.scenario_form().clone(), seed)";
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
        label = "form-bearing inline create session constructor";
        needle = "pub fn inline_form";
      }
      {
        label = "inline scenario source field";
        needle = "scenario_form: Option<ScenarioDefForm>";
      }
      {
        label = "inline scenario identity validation";
        needle = "InlineScenarioIdentityMismatch";
      }
      {
        label = "inline scenario white-box policy derivation";
        needle = "scenario_form_white_box_policies";
      }
      {
        label = "request-aware white-box policy resolution";
        needle = "white_box_policies_for_source";
      }
      {
        label = "source-aware lifecycle loop factory";
        needle = "new_with_source_factory";
      }
      {
        label = "quiescent loop records schedule decision";
        needle = "quiescent lifecycle loop could not record virtual-time decision";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "RPC snapshot query decoder";
        needle = "QueryResult::Snapshot(Box::new(EngineSnapshot";
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
      {
        label = "RPC inline scenario source payload encoder";
        needle = "\"scenario-payload\"";
      }
      {
        label = "RPC inline scenario source compact encoder";
        needle = "scenario_form.to_compact_binary()";
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
      {
        label = "RPC inline scenario source payload parser";
        needle = "parse_scenario_form_line(Some(line), \"scenario-payload=\")";
      }
      {
        label = "RPC inline scenario source identity validation";
        needle = "scenario payload id";
      }
      {
        label = "RPC inline scenario source constructor";
        needle = "CreateSessionRequest::inline_form(scenario_form, seed)";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client.rs" apiControlClient [
      {
        label = "RPC inline form wire snapshot";
        needle = "create-session-inline-form-request";
      }
      {
        label = "RPC inline form payload assertion";
        needle = "form-bearing inline create-session must transfer source payload";
      }
      {
        label = "RPC inline form conformance marker";
        needle = "create-session-inline-form";
      }
      {
        label = "RPC inline form typed request";
        needle = "CreateSessionRequest::inline_form";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_lifecycle_unary.rs" apiLifecycleUnary [
      {
        label = "inline form identity mismatch regression";
        needle = "create_session_rejects_inline_form_identity_mismatch_without_side_effects";
      }
      {
        label = "inline source public request construction";
        needle = "CreateSessionSource::Inline";
      }
      {
        label = "inline source mismatch error assertion";
        needle = "InlineScenarioIdentityMismatch";
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
        needle = "assert_machine_readable_jsonl(&stdout, &[\"save_export\"])?";
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
    ]
    ++ failuresFor "tests/crucible/phase5-cli-save-workflow.nix" saveWorkflowGate [
      {
        label = "patched QEMU build dependency";
        needle = "pkgs.qemu-crucible";
      }
      {
        label = "QMP savepoint job polling";
        needle = "wait_for_cli_save_qemu_job";
      }
      {
        label = "backend-executed patched QEMU snapshot save";
        needle = "snapshot-save=concluded";
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
        pkgs.jq
        pkgs.qemu-crucible
        pkgs.rust
        pkgs.sed
        pkgs.socat
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
              -p crucible-api \
              rpc_wire_contract_snapshots_cover_lifecycle_and_streaming_message_variants \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-api \
              control_client_trait_is_transport_agnostic_over_in_process_and_rpc \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-api \
              create_session_rejects_inline_form_identity_mismatch_without_side_effects \
              -- --test-threads=1
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

            qemu_pid=""
            qmp_socket="$TMPDIR/cli-save-qemu-qmp.sock"
            vmstate="$TMPDIR/cli-save-qemu-vmstate.qcow2"
            qemu_stderr="$TMPDIR/cli-save-qemu.stderr"
            rm -f "$qmp_socket" "$vmstate" "$qemu_stderr"

            cleanup_cli_save_qemu() {
              if [ -n "$qemu_pid" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
                qemu_pid=""
              fi
            }

            fail_cli_save_qemu() {
              echo "FAIL: $*" >&2
              if [ -s "$qemu_stderr" ]; then
                cat "$qemu_stderr" >&2
              fi
              cleanup_cli_save_qemu
              exit 1
            }

            trap cleanup_cli_save_qemu EXIT

            wait_for_cli_save_qemu_socket() {
              waited=0
              while [ "$waited" -lt 600 ]; do
                if [ -S "$qmp_socket" ]; then
                  return 0
                fi
                sleep 0.1
                waited=$((waited + 1))
              done
              return 1
            }

            qmp_cli_save_cmd() {
              socket="$1"
              request="$2"
              response="$3"
              response_err="$response.err"

              {
                printf '{"execute":"qmp_capabilities"}\r\n'
                printf '%s\r\n' "$request"
              } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

              if [ ! -s "$response" ]; then
                cat "$response_err" >&2 || true
                return 1
              fi

              if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                cat "$response" >&2
                return 1
              fi
              jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
            }

            wait_for_cli_save_qemu_job() {
              socket="$1"
              job="$2"
              waited=0
              while [ "$waited" -lt 600 ]; do
                if qmp_cli_save_cmd "$socket" '{"execute":"query-jobs"}' "$TMPDIR/qmp-cli-save-jobs.json"; then
                  if jq -e -s --arg job "$job" '
                    [.[] | select(has("return"))][-1].return[]
                    | select(.id == $job)
                    | has("error")
                  ' "$TMPDIR/qmp-cli-save-jobs.json" >/dev/null; then
                    cat "$TMPDIR/qmp-cli-save-jobs.json" >&2
                    return 1
                  fi
                  if jq -e -s --arg job "$job" '
                    [.[] | select(has("return"))][-1].return[]
                    | select(.id == $job)
                    | .status == "concluded"
                  ' "$TMPDIR/qmp-cli-save-jobs.json" >/dev/null; then
                    return 0
                  fi
                fi
                sleep 0.25
                waited=$((waited + 1))
              done
              return 1
            }

            "${pkgs.qemu-crucible}/bin/qemu-img" create -f qcow2 "$vmstate" 32M >/dev/null
            timeout 120 "${pkgs.qemu-crucible}/bin/qemu-system-x86_64" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel tcg,thread=single \
              -cpu qemu64,-rdrand,-rdseed \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c109 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -blockdev driver=file,filename="$vmstate",node-name=vmfile \
              -blockdev driver=qcow2,file=vmfile,node-name=vmstate \
              -S \
              -no-shutdown \
              -no-reboot \
              2> "$qemu_stderr" &
            qemu_pid="$!"

            wait_for_cli_save_qemu_socket || fail_cli_save_qemu "patched QEMU QMP socket did not appear"
            qmp_cli_save_cmd \
              "$qmp_socket" \
              '{"execute":"snapshot-save","arguments":{"job-id":"cli-save-qemu-save","tag":"cli-save-qemu-savepoint","vmstate":"vmstate","devices":["vmstate"]}}' \
              "$TMPDIR/qmp-cli-save-snapshot-save.json" \
              || fail_cli_save_qemu "patched QEMU snapshot-save command failed"
            wait_for_cli_save_qemu_job "$qmp_socket" "cli-save-qemu-save" \
              || fail_cli_save_qemu "patched QEMU snapshot-save job did not conclude"
            qmp_cli_save_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-cli-save-quit.json" >/dev/null 2>&1 || true
            wait "$qemu_pid" || fail_cli_save_qemu "patched QEMU exited unsuccessfully after snapshot-save"
            qemu_pid=""

            cat > "$TMPDIR/cli-save-qemu-snapshot.result" <<'RESULT'
            snapshot-save=concluded
            backend_executed_qemu_savepoint=patched-qemu-snapshot-save
            RESULT
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            grep -q '^snapshot-save=concluded$' "$TMPDIR/cli-save-qemu-snapshot.result"
            cp "$TMPDIR/cli-save-qemu-snapshot.result" "$out/qemu-snapshot-save.result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=$ATTR_PATH
            tasks=$TASK_IDS
            component=crucible-cli
            contract=save-workflow-progress
            process_qemu_save=marker-resolved-jsonl-handle
            remote_inline_scenario_transfer=form-bearing-rpc-payload
            backend_executed_qemu_savepoint=patched-qemu-snapshot-save
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
