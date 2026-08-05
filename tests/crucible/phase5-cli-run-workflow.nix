{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliRunWorkflow",
  taskIds ? ["T-CLI-6"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliCargo = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliProduction = import ./_rust-source.nix {
    inherit lib;
    entry = ../../crates/crucible-cli/src/main.rs;
    fragmentDirs = [../../crates/crucible-cli/src/cli];
  };
  sessionCore = import ./_crucible-session-source.nix {inherit lib;};
  apiLifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  apiServer = builtins.readFile ../../crates/crucible-api/src/server.rs;
  apiStreaming = builtins.readFile ../../crates/crucible-api/src/streaming.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-6 partial-evidence note";
        needle = "Completed under `checks.crucible.phase5.cliRunWorkflow`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI run workflow green note";
        needle = "`T-CLI-6` is completed through `checks.crucible.phase5.cliRunWorkflow`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "run scenario argument";
        needle = "scenario: Option<String>";
      }
      {
        label = "until flag model";
        needle = "enum RunUntilArg";
      }
      {
        label = "save policy model";
        needle = "enum RunSaveOnArg";
      }
      {
        label = "run invocation plan";
        needle = "struct RunInvocationPlan";
      }
      {
        label = "run planner";
        needle = "fn plan_run_invocation";
      }
      {
        label = "scenario validator";
        needle = "fn resolve_run_scenario";
      }
      {
        label = "canonical scenario TOML parser";
        needle = "ScenarioDefForm::from_canonical_toml";
      }
      {
        label = "stored scenario refs";
        needle = "RunScenarioRef::Stored";
      }
      {
        label = "DAG store scenario load";
        needle = "LocalDagStore::new";
      }
      {
        label = "invalid scenario error";
        needle = "InvalidScenario(String)";
      }
      {
        label = "invalid scenario exit code";
        needle = "Self::InvalidScenario(_) => 5";
      }
      {
        label = "start command";
        needle = "SessionCommandKind::Start";
      }
      {
        label = "continue command";
        needle = "SessionCommandKind::Continue";
      }
      {
        label = "API-owned startup command plan";
        needle = "startup_commands";
      }
      {
        label = "attached control command plan";
        needle = "initial_control_commands";
      }
      {
        label = "local double run executor";
        needle = "fn run_local_double_workflow";
      }
      {
        label = "async lifecycle workflow";
        needle = "fn run_local_double_workflow_async";
      }
      {
        label = "interactive stdin lifecycle workflow";
        needle = "fn run_local_double_workflow_stdin_async";
      }
      {
        label = "lifecycle control plane";
        needle = "LifecycleControlPlane::new";
      }
      {
        label = "in-process lifecycle client";
        needle = "InProcessLifecycleClient::new";
      }
      {
        label = "remote lifecycle RPC client";
        needle = "RpcControlClient::new";
      }
      {
        label = "daemon RPC endpoint";
        needle = "RpcEndpoint::http2";
      }
      {
        label = "shared control-client run workflow";
        needle = "fn run_control_client_workflow_async";
      }
      {
        label = "stdin control-client run workflow";
        needle = "fn run_control_client_workflow_stdin_async";
      }
      {
        label = "incremental stdin interactive driver";
        needle = "fn drive_interactive_stdin_commands";
      }
      {
        label = "testable interactive command reader";
        needle = "fn drive_interactive_command_reader";
      }
      {
        label = "user-visible interactive acknowledgement";
        needle = "interactive-ack\\tcommand=";
      }
      {
        label = "incremental acknowledgement flush";
        needle = "writer.flush()";
      }
      {
        label = "inline session create";
        needle = "CreateSessionRequest::inline";
      }
      {
        label = "interactive startup pause";
        needle = "with_start_paused";
      }
      {
        label = "control attach";
        needle = "control_attach";
      }
      {
        label = "streaming command send";
        needle = "send_command";
      }
      {
        label = "event-log stream";
        needle = "recv_event";
      }
      {
        label = "state update stream";
        needle = "recv_state_update";
      }
      {
        label = "run final state observer";
        needle = "fn observe_run_final_state";
      }
      {
        label = "terminal condition classifier";
        needle = "fn terminal_final_state";
      }
      {
        label = "terminal outcome label";
        needle = "fn terminal_outcome_label";
      }
      {
        label = "outcome-derived run status";
        needle = "fn run_status_from_observation";
      }
      {
        label = "closed outcome status mapping";
        needle = "fn status_from_outcome";
      }
      {
        label = "property terminal is distinct";
        needle = "property-missing";
      }
      {
        label = "property failure terminal is distinct";
        needle = "property-failed";
      }
      {
        label = "watch runtime status formatter";
        needle = "fn run_watch_status";
      }
      {
        label = "watch stdout marker";
        needle = "run-watch\\t";
      }
      {
        label = "save policy uses terminal savepoint";
        needle = "fn run_terminal_savepoint_for_policy";
      }
      {
        label = "savepoint stdout marker";
        needle = "run-savepoint\\tpolicy=";
      }
      {
        label = "savepoint stdout uses checkpoint handle";
        needle = "\\tcheckpoint={}";
      }
      {
        label = "user-visible backend stdout emission";
        needle = "for line in &outcome.stdout";
      }
      {
        label = "budget timeout stops session for savepoint";
        needle = "fn stop_budget_timed_out_session";
      }
      {
        label = "interactive mode";
        needle = "RunExecutionMode::Interactive";
      }
      {
        label = "interactive command set";
        needle = "fn run_interactive_session_command_set";
      }
      {
        label = "bounded acknowledgement quanta";
        needle = "RUN_INTERACTIVE_ACK_QUANTA_BOUND";
      }
      {
        label = "virtual-time budget";
        needle = "max_virtual_time";
      }
      {
        label = "parsed virtual-time budget";
        needle = "max_virtual_time_ticks";
      }
      {
        label = "duration budget parser";
        needle = "fn parse_run_duration_budget_ticks";
      }
      {
        label = "quantum budget";
        needle = "max_quanta";
      }
      {
        label = "observed final frontier";
        needle = "final_frontier_ticks";
      }
      {
        label = "observed final quanta";
        needle = "final_quanta";
      }
      {
        label = "outcome exit code mapping";
        needle = "outcome_exit_codes";
      }
      {
        label = "timeout exit code";
        needle = "BackendCommandStatus::Timeout";
      }
      {
        label = "canonical run scenario log entry";
        needle = "kind: String::from(\"run_scenario\")";
      }
      {
        label = "canonical run state update log entry";
        needle = "kind: String::from(\"run_state_update\")";
      }
      {
        label = "canonical run stream event log entry";
        needle = "kind: String::from(\"run_stream_event\")";
      }
      {
        label = "canonical run watch status log entry";
        needle = "kind: String::from(\"run_watch_status\")";
      }
      {
        label = "canonical run savepoint log entry";
        needle = "kind: String::from(\"run_savepoint\")";
      }
      {
        label = "interactive ack log entry";
        needle = "kind: String::from(\"interactive_ack\")";
      }
      {
        label = "run workflow normal test";
        needle = "cli_run_workflow_plans_start_continue_stream_and_budgets";
      }
      {
        label = "run workflow virtual-time test";
        needle = "cli_run_workflow_supports_virtual_time_budget";
      }
      {
        label = "run workflow interactive test";
        needle = "cli_run_workflow_interactive_pauses_at_genesis_and_accepts_session_commands";
      }
      {
        label = "run workflow rejection test";
        needle = "cli_run_workflow_rejects_bad_scenarios_and_invalid_budgets";
      }
      {
        label = "run workflow exit-code test";
        needle = "cli_run_workflow_uses_uniform_outcome_exit_code_mapping";
      }
      {
        label = "run workflow local double execution test";
        needle = "cli_run_workflow_executes_local_double_session_and_timeout_budget";
      }
      {
        label = "run workflow production daemon execution test";
        needle = "cli_run_workflow_executes_remote_daemon_session_against_production_server";
      }
      {
        label = "run workflow interactive parser test";
        needle = "cli_run_workflow_parses_interactive_session_commands";
      }
      {
        label = "run workflow interactive reader acknowledgement test";
        needle = "cli_run_workflow_acknowledges_interactive_reader_commands";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionCore [
      {
        label = "live snapshot outcome mirror";
        needle = "outcome_kind: AtomicU8";
      }
      {
        label = "live snapshot view outcome";
        needle = "pub outcome: Option<OutcomeKind>";
      }
      {
        label = "engine snapshot terminal savepoint";
        needle = "pub terminal_savepoint: Option<Checkpoint>";
      }
      {
        label = "live snapshot terminal savepoint mirror";
        needle = "terminal_savepoint_words: [AtomicU64; 4]";
      }
      {
        label = "terminal transition materializes savepoint";
        needle = "fn enter_stopped";
      }
      {
        label = "terminal transition saves checkpoint";
        needle = "self.graph.save_checkpoint(&self.configuration)?";
      }
      {
        label = "live snapshot publishes stopped outcome";
        needle = "outcome_kind_from_engine_state";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" apiLifecycle [
      {
        label = "quiescent lifecycle loop";
        needle = "pub struct QuiescentLifecycleLoop";
      }
      {
        label = "quiescent loop delegates scheduler boundary";
        needle = "impl QuantumLoop for QuiescentLifecycleLoop";
      }
      {
        label = "quiescent loop emits scheduler event-log entries";
        needle = "SchedulerEventLogEntry::diagnostic";
      }
      {
        label = "quiescent loop advances event-log offset";
        needle = "EventLogOffset::new(Default::default(), 0, self.event_log_events)";
      }
      {
        label = "API startup sends Start";
        needle = "send_runtime_command(runtime, SessionCommand::Start).await?;";
      }
      {
        label = "API startup sends Continue";
        needle = "send_runtime_command(runtime, SessionCommand::Continue).await?;";
      }
      {
        label = "API startup waits for running";
        needle = "wait_for_live_state(runtime, LiveStateKind::Running";
      }
      {
        label = "API session frontier summary";
        needle = "pub frontier: VirtualTime";
      }
      {
        label = "API session quanta summary";
        needle = "pub quanta_stepped: u64";
      }
      {
        label = "API session outcome summary";
        needle = "pub outcome: Option<OutcomeKind>";
      }
      {
        label = "API session terminal savepoint summary";
        needle = "pub terminal_savepoint: Option<ContentHash>";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "RPC list-sessions decodes outcome";
        needle = "parse_outcome_field";
      }
      {
        label = "RPC list-sessions decodes terminal savepoint";
        needle = "parse_content_hash_field";
      }
      {
        label = "RPC list-sessions requires outcome field";
        needle = "\"session outcome\"";
      }
      {
        label = "RPC list-sessions requires terminal savepoint field";
        needle = "\"session terminal savepoint\"";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/server.rs" apiServer [
      {
        label = "production HTTP/2 lifecycle server";
        needle = "pub async fn serve_lifecycle_http2";
      }
      {
        label = "server hosts create-session";
        needle = "\"/crucible.rpc/create-session\"";
      }
      {
        label = "server hosts control attach";
        needle = "\"/crucible.rpc/control/attach\"";
      }
      {
        label = "server hosts control send";
        needle = "\"/crucible.rpc/control/send\"";
      }
      {
        label = "server streams attached control body";
        needle = "fn control_event_body";
      }
      {
        label = "server streams event frames";
        needle = "encode_streaming_event_frame";
      }
      {
        label = "server encodes session outcome";
        needle = "outcome_wire_name(session.outcome)";
      }
      {
        label = "server outcome wire vocabulary";
        needle = "fn outcome_wire_name";
      }
      {
        label = "server encodes terminal savepoint";
        needle = "content_hash_option_wire(session.terminal_savepoint)";
      }
      {
        label = "server terminal savepoint wire vocabulary";
        needle = "fn content_hash_option_wire";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/streaming.rs" apiStreaming [
      {
        label = "streaming command uses actor-yield budget";
        needle = "max_actor_yields: u64";
      }
      {
        label = "streaming command waits for live state";
        needle = "fn wait_for_streaming_state";
      }
      {
        label = "streaming command reports bounded ack failure";
        needle = "StreamingApiError::StateDidNotAdvance";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliCargo [
      {
        label = "CLI depends on API lifecycle";
        needle = "crucible-api = { path = \"../crucible-api\" }";
      }
      {
        label = "CLI owns async runtime for local double workflow";
        needle = "tokio = { workspace = true }";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI run workflow check";
        needle = "cliRunWorkflow = import ./phase5-cli-run-workflow.nix";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "stale T-CLI-6 progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliRunWorkflow`";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "stale T-CLI-6 open note";
        needle = "`T-CLI-6` remains open. `checks.crucible.phase5.cliRunWorkflow` currently";
      }
    ]
    ++ forbiddenFor "crates/crucible-api/src/streaming.rs" apiStreaming [
      {
        label = "ignored streaming actor-yield budget";
        needle = "_max_actor_yields: u64";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/{main.rs,cli/**}" cliProduction [
      {
        label = "CLI owns scheduler loop";
        needle = builtins.concatStringsSep "_" ["drive" "quantum("];
      }
      {
        label = "CLI owns raw stdin parser loop";
        needle = builtins.concatStringsSep "::" ["std" "io" "stdin"];
      }
      {
        label = "host PATH QEMU discovery";
        needle = "std::env::var(\"PATH\")";
      }
      {
        label = "self-certifying CLI run proof";
        needle = "fn proves_t_cli_6";
      }
      {
        label = "planner-only run executor";
        needle = "fn execute_run_invocation_plan";
      }
      {
        label = "event-name heuristic for property terminal";
        needle = "event.contains(\"assertion\")";
      }
      {
        label = "string-matched terminal pass status";
        needle = "\"quiescent\" | \"stopped\" | \"property\"";
      }
      {
        label = "static event-log streaming proof flag";
        needle = "streams_canonical_event_log: true";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-cli-run-workflow";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_CLI_6_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
        '';
      }
      {
        name = "run-cli-run-workflow";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_CLI_6_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_CLI_6_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-cli-run-workflow-target" \
            -p crucible-cli \
            cli_run_workflow \
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
          open_tasks=$OPEN_TASK_IDS
          status=complete
          evidence_scope=run-workflow-model-and-double
          RESULT
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 CLI run workflow gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds openTaskIds dependencies;
        failureText = failureText;
      };
    };
  }
