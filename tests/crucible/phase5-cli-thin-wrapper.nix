{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliThinWrapper",
  taskIds ? ["T-CLI-2"],
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
  cliMain = import ./_cli-source.nix {inherit lib;};
  session = import ./_crucible-session-source.nix {inherit lib;};
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-2 checked off";
        needle = "- [x] **T-CLI-2**";
      }
      {
        label = "T-CLI-2 completion note";
        needle = "Completed by `checks.crucible.phase5.cliThinWrapper`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI thin-wrapper status note";
        needle = "`T-CLI-2` is green through `checks.crucible.phase5.cliThinWrapper`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "thin-wrapper plan type";
        needle = "struct CliThinWrapperPlan";
      }
      {
        label = "thin-wrapper planner";
        needle = "fn plan_cli_invocation";
      }
      {
        label = "dispatch enforces thin-wrapper plan";
        needle = "let thin_plan = plan_cli_invocation(cli);";
      }
      {
        label = "thin-wrapper proof predicate";
        needle = "fn proves_t_cli_2";
      }
      {
        label = "closed CLI subcommand model";
        needle = "enum CliSubcommand";
      }
      {
        label = "API operation allow-list";
        needle = "enum CliApiCall";
      }
      {
        label = "API operation closed set";
        needle = "CliApiCall::ALL.contains(call)";
      }
      {
        label = "API operations name ControlClient methods";
        needle = "fn control_client_method";
      }
      {
        label = "session command closed set";
        needle = "SessionCommandKind::ALL.contains(command)";
      }
      {
        label = "dispatch plan executor";
        needle = "fn execute_cli_dispatch_plan";
      }
      {
        label = "operation recorder trait";
        needle = "trait CliOperationRecorder";
      }
      {
        label = "dispatch consumes executable plan";
        needle = "execute_cli_dispatch_plan(&thin_plan, &mut NullOperationRecorder)?";
      }
      {
        label = "delegated driver set";
        needle = "enum CliDelegatedDriver";
      }
      {
        label = "non-canonical state references";
        needle = "CliStateReferenceKind::ContentAddressedStore";
      }
      {
        label = "daemon connection is a handle not state";
        needle = "CliStateReferenceKind::DaemonConnection";
      }
      {
        label = "explicit no canonical run state";
        needle = "owns_canonical_run_state: false";
      }
      {
        label = "explicit no scheduler implementation";
        needle = "implements_scheduler: false";
      }
      {
        label = "explicit no checkpoint materialization";
        needle = "implements_checkpoint_materialization: false";
      }
      {
        label = "explicit no fork logic";
        needle = "implements_fork_logic: false";
      }
      {
        label = "no extra control capability field";
        needle = "extra_control_capabilities: Vec";
      }
      {
        label = "run delegates to session";
        needle = "Commands::Run(_) => CliThinWrapperPlan";
      }
      {
        label = "verify delegates to replay oracle";
        needle = "CliDelegatedDriver::ReplayOracle";
      }
      {
        label = "selftest delegates to gate catalog";
        needle = "CliDelegatedDriver::HarnessGateCatalog";
      }
      {
        label = "search/fuzz delegate to exploration engine";
        needle = "CliDelegatedDriver::ExplorationEngine";
      }
      {
        label = "triage delegates to triage engine";
        needle = "CliDelegatedDriver::TriageEngine";
      }
      {
        label = "debug delegates to debugger";
        needle = "CliDelegatedDriver::TimeTravelDebugger";
      }
      {
        label = "serve delegates to API host";
        needle = "CliDelegatedDriver::DaemonHost";
      }
      {
        label = "completions stays auxiliary";
        needle = "CliDelegatedDriver::ShellCompletionGenerator";
      }
      {
        label = "all subcommands thin-wrapper test";
        needle = "cli_thin_wrapper_maps_every_subcommand_to_session_api_or_declared_driver";
      }
      {
        label = "negative thin-wrapper capability test";
        needle = "cli_thin_wrapper_rejects_canonical_state_or_extra_control_capabilities";
      }
      {
        label = "recorder-backed thin-wrapper test";
        needle = "cli_thin_wrapper_emits_only_control_client_methods_and_session_command_kinds";
      }
      {
        label = "fake recorder records session commands";
        needle = "struct RecordingOperationRecorder";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "session command kind closed set";
        needle = "pub const ALL:";
      }
      {
        label = "session command start";
        needle = "Self::Start";
      }
      {
        label = "session command debug goto";
        needle = "Self::DebugGoto";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "ControlClient trait";
        needle = "pub trait ControlClient";
      }
      {
        label = "ControlClient hello method";
        needle = "fn hello(&self";
      }
      {
        label = "ControlClient list scenarios method";
        needle = "fn list_scenarios(&self";
      }
      {
        label = "API lifecycle create";
        needle = "fn create_session(";
      }
      {
        label = "ControlClient list sessions method";
        needle = "fn list_sessions(&self";
      }
      {
        label = "ControlClient destroy session method";
        needle = "fn destroy_session(";
      }
      {
        label = "API reproduction read";
        needle = "fn get_reproduction(";
      }
      {
        label = "ControlClient control attach method";
        needle = "fn control_attach(";
      }
      {
        label = "ControlClient control send method";
        needle = "fn control_send(&self";
      }
      {
        label = "ControlClient watch attach method";
        needle = "fn watch_attach(&self";
      }
      {
        label = "ControlClient unary send method";
        needle = "fn send_command(&self";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI thin-wrapper check";
        needle = "cliThinWrapper = import ./phase5-cli-thin-wrapper.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "fake API operation outside ControlClient";
        needle = "ServeTransport";
      }
      {
        label = "CLI-owned engine state";
        needle = "Engine<";
      }
      {
        label = "CLI-owned session actor";
        needle = "SessionActor";
      }
      {
        label = "CLI-owned temporal graph";
        needle = "TemporalGraph";
      }
      {
        label = "CLI direct scheduler command application";
        needle = "apply_command(";
      }
      {
        label = "CLI spawning scheduler/runtime work";
        needle = "tokio::spawn";
      }
      {
        label = "CLI wall-clock canonical input";
        needle = "Instant::now";
      }
      {
        label = "CLI wall-clock canonical input";
        needle = "SystemTime::now";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-cli-thin-wrapper";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_CLI_2_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
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
        name = "run-cli-thin-wrapper";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_CLI_2_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_CLI_2_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-cli-thin-wrapper-target" \
            -p crucible-cli \
            cli_thin_wrapper \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 CLI thin-wrapper gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
