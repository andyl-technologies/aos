{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliResumeWorkflow",
  taskIds ? ["T-CLI-10"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  apiVmResume = builtins.readFile ../../crates/crucible-api/src/vm_resume.rs;
  simBackend = import ./_crucible-local-and-test-backends-source.nix;
  sessionValidation = builtins.readFile ../../crates/crucible-session/src/validation.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  qemuBackendExecutor = builtins.readFile ../../crates/crucible-qemu/src/realization/backend_executor.rs;
  qemuNodeExecutor = builtins.readFile ../../crates/crucible-qemu/src/realization/node_executor.rs;
  qemuNodeExecutorTests = builtins.readFile ../../crates/crucible-qemu/src/realization/node_executor/tests.rs;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack:
    needle
    == ""
    || builtins.replaceStrings [needle] [""] haystack != haystack;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: forbidden:
    lib.concatMap (
      item:
        lib.optionals (hasInfix item.needle content) [
          "${fileLabel}: forbidden ${item.label}: `${item.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-10 partial-evidence note";
        needle = "Completed under `checks.crucible.phase5.cliResumeWorkflow`";
      }
      {
        label = "T-CLI-10 local resume progress";
        needle = "handle- or store-backed local-double resume";
      }
      {
        label = "T-CLI-10 remote daemon resume progress";
        needle = "routes remote-daemon resume over";
      }
      {
        label = "T-CLI-10 terminal oracle progress";
        needle = "replay-oracle-validating";
      }
      {
        label = "T-CLI-10 local-QEMU realization coordinator progress";
        needle = "`crucible-qemu` owns the typed realization coordinator";
      }
      {
        label = "T-CLI-10 local-QEMU real node executor progress";
        needle = "Linux real-node realization executor";
      }
      {
        label = "T-CLI-10 local-QEMU realization proof progress";
        needle = "`materialization=qemu-vm-realization`, `operation=resume`,\n  `executor=model-checkpoint`, branch";
      }
      {
        label = "T-CLI-10 local-QEMU coordinator invocation progress";
        needle = "invoke the `crucible-qemu` resume coordinator through a";
      }
      {
        label = "T-CLI-10 process qemu resume progress";
        needle = "Process-tests cover real-binary\n  `resume --backend qemu` JSONL";
      }
      {
        label = "T-CLI-10 QMP snapshot-load smoke progress";
        needle = "QMP `snapshot-load` smoke";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI resume completion note";
        needle = "`T-CLI-10` is completed through `checks.crucible.phase5.cliResumeWorkflow`";
      }
      {
        label = "phase5 CLI resume local-QEMU coordinator progress";
        needle = "`crucible-qemu` realization coordinator owns";
      }
      {
        label = "phase5 CLI resume local-QEMU real node executor progress";
        needle = "Linux real-node realization executor";
      }
      {
        label = "phase5 CLI resume local-QEMU realization proof progress";
        needle = "`materialization=qemu-vm-realization`, `operation=resume`,\n  `executor=model-checkpoint`, branch";
      }
      {
        label = "phase5 CLI resume local-QEMU coordinator invocation progress";
        needle = "invoke the `crucible-qemu` resume coordinator through a";
      }
      {
        label = "phase5 CLI process qemu resume progress";
        needle = "process-level `resume --backend qemu` JSONL output checks those\n  coordinator-derived proof fields from that model-checkpoint executor plus";
      }
      {
        label = "phase5 CLI QMP snapshot-load smoke progress";
        needle = "QMP `snapshot-load` smoke";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "resume arguments";
        needle = "struct ResumeArgs";
      }
      {
        label = "resume invocation plan";
        needle = "struct ResumeInvocationPlan";
      }
      {
        label = "resume savepoint ref";
        needle = "enum ResumeSavepointRef";
      }
      {
        label = "savepoint handle decoder";
        needle = "fn decode_savepoint_handle";
      }
      {
        label = "resume planner";
        needle = "fn plan_resume_invocation";
      }
      {
        label = "resume resolver";
        needle = "fn resolve_resume_savepoint";
      }
      {
        label = "checkpoint hash parser";
        needle = "fn parse_blake3_content_hash";
      }
      {
        label = "resume handle scenario payload";
        needle = "scenario-payload";
      }
      {
        label = "resume handle schedule payload";
        needle = "schedule-payload";
      }
      {
        label = "resume evidence validator";
        needle = "fn resume_handle_evidence";
      }
      {
        label = "resume local double runner";
        needle = "fn run_local_double_resume_workflow";
      }
      {
        label = "resume local-QEMU runner";
        needle = "fn run_local_qemu_resume_workflow";
      }
      {
        label = "resume dispatches the live QEMU workflow";
        needle = "fn run_local_qemu_resume_workflow";
      }
      {
        label = "resume local-QEMU thin-replay proof";
        needle = "resume-thin-replay";
      }
      {
        label = "resume terminal configuration report";
        needle = "terminal_configuration: actor_report.final_snapshot.configuration.clone()";
      }
      {
        label = "resume remote daemon runner";
        needle = "fn run_remote_resume_workflow";
      }
      {
        label = "resume remote control client workflow";
        needle = "fn run_remote_control_client_resume_workflow_async";
      }
      {
        label = "resume RPC request";
        needle = "ResumeSessionRequest::new";
      }
      {
        label = "resume interactive command driver";
        needle = "enum ResumeInteractiveCommandDriver";
      }
      {
        label = "resume interactive actor acknowledgement";
        needle = "fn resume_actor_interactive_command";
      }
      {
        label = "resume interactive stdin reader";
        needle = "fn drive_resumed_actor_interactive_command_reader";
      }
      {
        label = "resume interactive final state";
        needle = "final=interactive";
      }
      {
        label = "resume interactive savepoint command test";
        needle = "SessionCommandKind::CreateSavepoint";
      }
      {
        label = "resume interactive rejection test";
        needle = "interactive command `start`";
      }
      {
        label = "resume property predicate";
        needle = "fn resume_property_violation_predicate";
      }
      {
        label = "resume property breakpoint validation";
        needle = "fn validate_resume_property_firing";
      }
      {
        label = "resume terminal oracle validation";
        needle = "fn validate_resume_terminal_savepoint";
      }
      {
        label = "resume terminal source ancestry validation";
        needle = "fn validate_resume_terminal_source_ancestor";
      }
      {
        label = "resume replay anchor validation";
        needle = "fn validate_resume_replay_anchor";
      }
      {
        label = "resume rejects tampered handle frontier";
        needle = "cli_resume_workflow_rejects_tampered_handle_frontier";
      }
      {
        label = "resume rejects non-descendant terminal snapshot";
        needle = "cli_resume_terminal_oracle_rejects_non_descendant_snapshot";
      }
      {
        label = "resume oracle output";
        needle = "resume-oracle";
      }
      {
        label = "resume oracle canonical log";
        needle = "resume_oracle_validation";
      }
      {
        label = "resume property final state";
        needle = "property-failed";
      }
      {
        label = "resume evidence oracle gate";
        needle = "savepoint handle oracle status";
      }
      {
        label = "resume scaled wait budget";
        needle = "fn resume_actor_boundary_yield_budget";
      }
      {
        label = "resume lifecycle loop";
        needle = "struct ResumeRecordingLifecycleLoop";
      }
      {
        label = "bare checkpoint closure loader";
        needle = "fn savepoint_store_evidence";
      }
      {
        label = "resume planning test";
        needle = "cli_resume_workflow_plans_handles_hashes_and_rejects_malformed_inputs";
      }
      {
        label = "resume execution test";
        needle = "cli_resume_workflow_executes_local_double_handle";
      }
      {
        label = "resume remote daemon execution test";
        needle = "cli_resume_workflow_executes_remote_daemon_handle";
      }
      {
        label = "resume remote watch status";
        needle = "run-watch\\tstate=stopped\\tfrontier_ticks=2";
      }
      {
        label = "resume remote interactive command test";
        needle = "run_remote_resume_workflow_with_interactive_commands";
      }
      {
        label = "resume remote interactive final state";
        needle = "remote_interactive_final";
      }
      {
        label = "resume remote interactive stop final state";
        needle = "remote_interactive_stop_final";
      }
      {
        label = "resume terminal remote interactive final state";
        needle = "remote_interactive_terminal_final";
      }
      {
        label = "resume terminal remote interactive cleanup";
        needle = "terminal remote interactive finalization should remove the stopped session";
      }
      {
        label = "resume unverified evidence test";
        needle = "cli_resume_workflow_rejects_unverified_handle_evidence";
      }
      {
        label = "resume long virtual-time test";
        needle = "cli_resume_workflow_allows_virtual_time_beyond_ack_yield_bound";
      }
      {
        label = "resume bare hash store loader test";
        needle = "cli_resume_workflow_executes_local_double_bare_hash_from_store";
      }
      {
        label = "resume bare hash missing index artifact test";
        needle = "cli_resume_workflow_rejects_missing_bare_hash_store_index_as_artifact";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/validation.rs" sessionValidation [
      {
        label = "resume realization proof";
        needle = "struct ResumeRealizationProof";
      }
      {
        label = "resume realization proof derivation";
        needle = "realize_resume_from_savepoint";
      }
      {
        label = "resume ancestor replay branch";
        needle = "ancestor-replay";
      }
    ]
    ++ forbiddenFor "crates/crucible-session/src/validation.rs" sessionValidation [
      {
        label = "QEMU boundary term";
        needle = "qemu";
      }
      {
        label = "QEMU boundary type";
        needle = "Qemu";
      }
      {
        label = "QEMU uppercase boundary term";
        needle = "QEMU";
      }
      {
        label = "loadvm boundary term";
        needle = "loadvm";
      }
      {
        label = "savevm boundary term";
        needle = "savevm";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_resume.rs" apiVmResume [
      {
        label = "resume API VM realization proof";
        needle = "struct ModelCheckpointVmResumeRealizationProof";
      }
      {
        label = "resume API VM realization derivation";
        needle = "realize_model_checkpoint_vm_resume_from_savepoint";
      }
      {
        label = "resume API injectable QEMU executor hook";
        needle = "realize_qemu_vm_resume_from_savepoint_with_executor";
      }
      {
        label = "resume API-owned QEMU coordinator invocation";
        needle = "resume_qemu_vm(";
      }
      {
        label = "resume API-owned QEMU backend executor";
        needle = "QemuBackendRealizationExecutor::new";
      }
      {
        label = "resume API-owned QEMU model backend";
        needle = "SimBackend::from_restorable_checkpoints";
      }
      {
        label = "resume API-owned QEMU replay oracle status";
        needle = "QemuReplayOracleValidation::NotRun";
      }
      {
        label = "resume API-owned QEMU model executor marker";
        needle = "model-checkpoint";
      }
      {
        label = "resume API-owned QEMU ancestor replay branch";
        needle = "ancestor-replay";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "resume QEMU realization coordinator";
        needle = "pub fn resume_qemu_vm";
      }
      {
        label = "resume QEMU ancestor replay branch";
        needle = "QemuVmRealizationKind::AncestorReplay";
      }
      {
        label = "resume QEMU exact snapshot policy";
        needle = "QemuExactSnapshotPolicy::default";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization/backend_executor.rs" qemuBackendExecutor [
      {
        label = "resume QEMU backend realization executor";
        needle = "struct QemuBackendRealizationExecutor";
      }
      {
        label = "resume QEMU backend exact snapshot test";
        needle = "qemu_backend_realization_executor_restores_exact_snapshot";
      }
      {
        label = "resume QEMU backend ancestor replay test";
        needle = "qemu_backend_realization_executor_replays_from_cached_ancestor";
      }
      {
        label = "resume QEMU baked genesis config mismatch regression";
        needle = "load_baked_genesis(&genesis, baked_admission)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization/node_executor.rs" qemuNodeExecutor [
      {
        label = "resume QEMU real node executor";
        needle = "pub struct QemuNodeRealizationExecutor";
      }
      {
        label = "resume QEMU real node launcher";
        needle = "pub trait QemuNodeRealizationLauncher";
      }
      {
        label = "resume QEMU warm restore launcher";
        needle = "pub struct QemuWarmRestoreNodeLauncher";
      }
      {
        label = "resume QEMU warm restore launch composition";
        needle = "spawn_setup_and_restore_qemu_node(";
      }
      {
        label = "resume QEMU real node baked load";
        needle = "QemuNodeRestorePlan::baked_genesis(admission)";
      }
      {
        label = "resume QEMU real node replay shared memory";
        needle = ".advance_to_horizon(horizon)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization/node_executor/tests.rs" qemuNodeExecutorTests [
      {
        label = "resume QEMU real node no generic snapshot regression";
        needle = "qemu_node_realization_executor_replays_without_generic_snapshot_or_restore";
      }
    ]
    ++ failuresFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "resume model backend restorable checkpoint constructor";
        needle = "pub fn from_restorable_checkpoint";
      }
      {
        label = "resume model backend restorable checkpoints constructor";
        needle = "pub fn from_restorable_checkpoints";
      }
      {
        label = "resume model backend checkpoint state derivation";
        needle = "fn from_checkpoint(checkpoint: &Checkpoint) -> Self";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "process qemu resume live-asset admission regression";
        needle = "cli_resume_qemu_process_requires_packaged_live_guest_assets";
      }
      {
        label = "process qemu resume no-unwired assertion";
        needle = "!stderr.contains(\"execution is unavailable\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI resume workflow check";
        needle = "cliResumeWorkflow = import ./phase5-cli-resume-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI resume workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-resume-workflow";
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
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
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
          name = "run-cli-resume-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-resume-workflow-target" \
              -p crucible-cli \
              cli_resume \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-resume-workflow-target" \
              -p crucible-cli \
              cli_resume_qemu_process_requires_packaged_live_guest_assets \
              -- --test-threads=1

            qemu_pid=""
            qmp_socket="$TMPDIR/cli-resume-qemu-qmp.sock"
            vmstate="$TMPDIR/cli-resume-qemu-vmstate.qcow2"
            qemu_stderr="$TMPDIR/cli-resume-qemu.stderr"
            rm -f "$qmp_socket" "$vmstate" "$qemu_stderr"

            cleanup_cli_resume_qemu() {
              if [ -n "$qemu_pid" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
                qemu_pid=""
              fi
            }

            fail_cli_resume_qemu() {
              echo "FAIL: $*" >&2
              if [ -s "$qemu_stderr" ]; then
                cat "$qemu_stderr" >&2
              fi
              cleanup_cli_resume_qemu
              exit 1
            }

            trap cleanup_cli_resume_qemu EXIT

            wait_for_cli_resume_qemu_socket() {
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

            qmp_cli_resume_exchange() {
              socket="$1"
              request="$2"
              response="$3"
              response_err="$response.err"

              {
                sleep 0.1
                printf '{"execute":"qmp_capabilities"}\r\n'
                sleep 0.1
                printf '%s\r\n' "$request"
                sleep 0.25
              } | socat -T 10 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true
            }

            qmp_cli_resume_cmd() {
              socket="$1"
              request="$2"
              response="$3"
              response_err="$response.err"
              attempts=0

              while [ "$attempts" -lt 20 ]; do
                qmp_cli_resume_exchange "$socket" "$request" "$response"

                if [ ! -s "$response" ]; then
                  attempts=$((attempts + 1))
                  sleep 0.25
                  continue
                fi

                if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                  cat "$response" >&2
                  return 1
                fi
                if jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null; then
                  return 0
                fi

                attempts=$((attempts + 1))
                sleep 0.25
              done

              if [ -s "$response" ]; then
                cat "$response" >&2
              else
                cat "$response_err" >&2 || true
              fi
              return 1
            }

            qmp_cli_resume_job_started() {
              socket="$1"
              job="$2"
              response="$3.probe"

              if ! qmp_cli_resume_cmd "$socket" '{"execute":"query-jobs"}' "$response"; then
                return 1
              fi
              if jq -e -s --arg job "$job" '
                ([.[] | select(has("return"))][-1].return // [])[]
                | select(.id == $job)
                | has("error")
              ' "$response" >/dev/null; then
                cat "$response" >&2
                return 1
              fi
              jq -e -s --arg job "$job" '
                any((([.[] | select(has("return"))][-1].return // [])[]); .id == $job)
              ' "$response" >/dev/null
            }

            qmp_cli_resume_job_cmd() {
              socket="$1"
              request="$2"
              response="$3"
              job="$4"
              response_err="$response.err"
              attempts=0

              while [ "$attempts" -lt 20 ]; do
                qmp_cli_resume_exchange "$socket" "$request" "$response"

                if [ -s "$response" ]; then
                  if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                    cat "$response" >&2
                    return 1
                  fi
                  if jq -e -s --arg job "$job" '
                    ([.[] | select(has("return"))] | length >= 2)
                    or any(.[]; .event == "JOB_STATUS_CHANGE" and .data.id == $job)
                  ' "$response" >/dev/null; then
                    return 0
                  fi
                fi

                if qmp_cli_resume_job_started "$socket" "$job" "$response"; then
                  return 0
                fi

                attempts=$((attempts + 1))
                sleep 0.25
              done

              if [ -s "$response" ]; then
                cat "$response" >&2
              else
                cat "$response_err" >&2 || true
              fi
              return 1
            }

            wait_for_cli_resume_qemu_job() {
              socket="$1"
              job="$2"
              waited=0
              while [ "$waited" -lt 600 ]; do
                if qmp_cli_resume_cmd "$socket" '{"execute":"query-jobs"}' "$TMPDIR/qmp-cli-resume-jobs.json"; then
                  if jq -e -s --arg job "$job" '
                    [.[] | select(has("return"))][-1].return[]
                    | select(.id == $job)
                    | has("error")
                  ' "$TMPDIR/qmp-cli-resume-jobs.json" >/dev/null; then
                    cat "$TMPDIR/qmp-cli-resume-jobs.json" >&2
                    return 1
                  fi
                  if jq -e -s --arg job "$job" '
                    [.[] | select(has("return"))][-1].return[]
                    | select(.id == $job)
                    | .status == "concluded"
                  ' "$TMPDIR/qmp-cli-resume-jobs.json" >/dev/null; then
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
              -seed 0x0010c10a \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -blockdev driver=file,filename="$vmstate",node-name=vmfile \
              -blockdev driver=qcow2,file=vmfile,node-name=vmstate \
              -S \
              -no-shutdown \
              -no-reboot \
              2> "$qemu_stderr" &
            qemu_pid="$!"

            wait_for_cli_resume_qemu_socket || fail_cli_resume_qemu "patched QEMU QMP socket did not appear"
            qmp_cli_resume_job_cmd \
              "$qmp_socket" \
              '{"execute":"snapshot-save","arguments":{"job-id":"cli-resume-qemu-save","tag":"cli-resume-qemu-savepoint","vmstate":"vmstate","devices":["vmstate"]}}' \
              "$TMPDIR/qmp-cli-resume-snapshot-save.json" \
              "cli-resume-qemu-save" \
              || fail_cli_resume_qemu "patched QEMU snapshot-save command failed"
            wait_for_cli_resume_qemu_job "$qmp_socket" "cli-resume-qemu-save" \
              || fail_cli_resume_qemu "patched QEMU snapshot-save job did not conclude"
            qmp_cli_resume_job_cmd \
              "$qmp_socket" \
              '{"execute":"snapshot-load","arguments":{"job-id":"cli-resume-qemu-load","tag":"cli-resume-qemu-savepoint","vmstate":"vmstate","devices":["vmstate"]}}' \
              "$TMPDIR/qmp-cli-resume-snapshot-load.json" \
              "cli-resume-qemu-load" \
              || fail_cli_resume_qemu "patched QEMU snapshot-load command failed"
            wait_for_cli_resume_qemu_job "$qmp_socket" "cli-resume-qemu-load" \
              || fail_cli_resume_qemu "patched QEMU snapshot-load job did not conclude"
            qmp_cli_resume_cmd "$qmp_socket" '{"execute":"cont"}' "$TMPDIR/qmp-cli-resume-cont.json" \
              || fail_cli_resume_qemu "patched QEMU cont command failed"
            qmp_cli_resume_cmd "$qmp_socket" '{"execute":"query-status"}' "$TMPDIR/qmp-cli-resume-status.json" \
              || fail_cli_resume_qemu "patched QEMU status query failed"
            jq -e -s '[.[] | select(has("return"))][-1].return.status == "running"' \
              "$TMPDIR/qmp-cli-resume-status.json" >/dev/null \
              || fail_cli_resume_qemu "patched QEMU did not report running after snapshot-load and cont"
            qmp_cli_resume_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-cli-resume-quit.json" >/dev/null 2>&1 || true
            wait "$qemu_pid" || fail_cli_resume_qemu "patched QEMU exited unsuccessfully after snapshot-load"
            qemu_pid=""

            cat > "$TMPDIR/cli-resume-qemu-snapshot.result" <<'RESULT'
            snapshot-save=concluded
            snapshot-load=concluded
            qmp-cont-status=running
            qmp_snapshot_load_smoke=job-concluded-and-running
            RESULT
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            grep -q '^snapshot-save=concluded$' "$TMPDIR/cli-resume-qemu-snapshot.result"
            grep -q '^snapshot-load=concluded$' "$TMPDIR/cli-resume-qemu-snapshot.result"
            grep -q '^qmp-cont-status=running$' "$TMPDIR/cli-resume-qemu-snapshot.result"
            grep -q '^qmp_snapshot_load_smoke=job-concluded-and-running$' "$TMPDIR/cli-resume-qemu-snapshot.result"
            cp "$TMPDIR/cli-resume-qemu-snapshot.result" "$out/qemu-snapshot-load.result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=$ATTR_PATH
            tasks=$TASK_IDS
            open_tasks=$OPEN_TASK_IDS
            status=complete
            evidence_scope=resume-model-and-qmp-smoke
            component=crucible-cli
            contract=resume-workflow-progress
            process_qemu_resume=marker-resolved-jsonl-oracle
            qmp_snapshot_load_smoke=job-concluded-and-running
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
