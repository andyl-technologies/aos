{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliResumeWorkflow",
  taskIds ? ["T-CLI-10"],
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
        label = "T-CLI-10 remains open";
        needle = "- [ ] **T-CLI-10** Implement `resume`";
      }
      {
        label = "T-CLI-10 progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliResumeWorkflow`";
      }
      {
        label = "T-CLI-10 handle-backed resume progress";
        needle = "local-double resume to quiescence, virtual-time, interactive command driving";
      }
      {
        label = "T-CLI-10 remote daemon resume progress";
        needle = "resume over `ResumeSession` RPC for handle-backed virtual-time runs";
      }
      {
        label = "T-CLI-10 terminal oracle progress";
        needle = "replay-oracle-validating";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI resume progress note";
        needle = "`T-CLI-10` remains open. `checks.crucible.phase5.cliResumeWorkflow` currently";
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
        label = "bare checkpoint closure blocker";
        needle = "DAG-store checkpoint closure loading remains tracked by {task_id}";
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
        label = "resume remote watch blocker";
        needle = "remote daemon resume --watch remains tracked by T-CLI-10";
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
        label = "resume bare hash blocker test";
        needle = "cli_resume_workflow_rejects_bare_hash_until_closure_loader_exists";
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
            contract=resume-workflow-progress
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
