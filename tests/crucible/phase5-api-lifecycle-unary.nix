{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.apiLifecycleUnary",
  taskIds ? ["T-API-3"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  apiDoc = builtins.readFile ../../docs/rfcs/0010-crucible/21-api.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  apiCargo = builtins.readFile ../../crates/crucible-api/Cargo.toml;
  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiClient = builtins.readFile ../../crates/crucible-api/src/client.rs;
  model = import ./_crucible-model-source.nix {inherit lib;};
  lifecycle = builtins.readFile ../../crates/crucible-api/src/lifecycle.rs;
  lifecycleTest = builtins.readFile ../../crates/crucible-api/tests/gate_lifecycle_unary.rs;
  controlClientTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/tests/gate_control_client.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/21-api.md" apiDoc [
      {
        label = "T-API-3 completion note";
        needle = "Completed by `checks.crucible.phase5.apiLifecycleUnary`";
      }
      {
        label = "T-API-5 completion note";
        needle = "Completed by `checks.crucible.phase5.apiOpenSetPayload`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 API lifecycle status note";
        needle = "`T-API-3` is green through `checks.crucible.phase5.apiLifecycleUnary`";
      }
    ]
    ++ failuresFor "crates/crucible-api/Cargo.toml" apiCargo [
      {
        label = "crucible production dependency";
        needle = ''crucible = { path = "../crucible" }'';
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "lifecycle module exported";
        needle = "pub mod lifecycle";
      }
      {
        label = "lifecycle control plane re-exported";
        needle = "LifecycleControlPlane";
      }
      {
        label = "in-process lifecycle client re-exported";
        needle = "InProcessLifecycleClient";
      }
      {
        label = "resume session request re-exported";
        needle = "ResumeSessionRequest";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/client.rs" apiClient [
      {
        label = "control client list scenarios method";
        needle = "fn list_scenarios(&self)";
      }
      {
        label = "control client create session method";
        needle = "fn create_session(";
      }
      {
        label = "control client resume session method";
        needle = "fn resume_session(";
      }
      {
        label = "control client list sessions method";
        needle = "fn list_sessions(&self)";
      }
      {
        label = "control client destroy session method";
        needle = "fn destroy_session(";
      }
      {
        label = "RPC list scenarios path";
        needle = ''"/crucible.rpc/list-scenarios"'';
      }
      {
        label = "RPC create session path";
        needle = ''"/crucible.rpc/create-session"'';
      }
      {
        label = "RPC resume session path";
        needle = ''"/crucible.rpc/resume-session"'';
      }
      {
        label = "RPC inline scenario seed field";
        needle = ''"scenario-seed"'';
      }
      {
        label = "RPC resume session encoder";
        needle = "fn encode_resume_session_request";
      }
      {
        label = "RPC resume scenario payload";
        needle = "scenario-payload";
      }
      {
        label = "RPC resume session decoder";
        needle = "fn decode_resume_session_response";
      }
      {
        label = "RPC list sessions path";
        needle = ''"/crucible.rpc/list-sessions"'';
      }
      {
        label = "RPC destroy session path";
        needle = ''"/crucible.rpc/destroy-session"'';
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "opaque inline scenario transport constructor";
        needle = "pub fn from_content_hash_seed_and_app_random_draw_cap";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lifecycle.rs" lifecycle [
      {
        label = "lifecycle control plane";
        needle = "pub struct LifecycleControlPlane";
      }
      {
        label = "transport-facing in-process lifecycle client";
        needle = "pub struct InProcessLifecycleClient";
      }
      {
        label = "scenario catalog entry";
        needle = "pub struct ScenarioCatalogEntry";
      }
      {
        label = "seed-parameterized scenario catalog source";
        needle = "pub enum ScenarioCatalogSource";
      }
      {
        label = "canonical material scenario constructor";
        needle = "pub fn from_canonical_material";
      }
      {
        label = "create session request";
        needle = "pub struct CreateSessionRequest";
      }
      {
        label = "resume session request";
        needle = "pub struct ResumeSessionRequest";
      }
      {
        label = "resume session response";
        needle = "pub struct ResumeSessionResponse";
      }
      {
        label = "create source enum";
        needle = "pub enum CreateSessionSource";
      }
      {
        label = "session ref carries seed";
        needle = "pub struct SessionRef";
      }
      {
        label = "destroy session request";
        needle = "pub struct DestroySessionRequest";
      }
      {
        label = "hello negotiates protocol";
        needle = "negotiate_rpc_protocol(request.version)";
      }
      {
        label = "control client implementation";
        needle = "impl<L, F> ControlClient for InProcessLifecycleClient";
      }
      {
        label = "actor spawned for created session";
        needle = "tokio::spawn(async move { actor.run().await })";
      }
      {
        label = "create sends Start";
        needle = "SessionCommand::Start";
      }
      {
        label = "start-paused waits for Paused";
        needle = "LiveStateKind::Paused";
      }
      {
        label = "start-running sends Continue";
        needle = "SessionCommand::Continue";
      }
      {
        label = "scenario seed mismatch rejection";
        needle = "ScenarioSeedMismatch";
      }
      {
        label = "resume checkpoint rejection";
        needle = "ResumeCheckpoint";
      }
      {
        label = "resume lifecycle method";
        needle = "pub async fn resume_session";
      }
      {
        label = "resume checkpoint closure validation";
        needle = "fn validate_resume_checkpoint_closure";
      }
      {
        label = "resume baked genesis validation";
        needle = "baked genesis checkpoint";
      }
      {
        label = "resume checkpoint instantiation";
        needle = "Engine::from_recorded_checkpoint";
      }
      {
        label = "list reads live mirror";
        needle = "runtime.live.read()";
      }
      {
        label = "destroy sends Stop";
        needle = "SessionCommand::Stop";
      }
      {
        label = "epoch guard";
        needle = "EpochMismatch";
      }
      {
        label = "absent destroy idempotent";
        needle = "already_absent: true";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_lifecycle_unary.rs" lifecycleTest [
      {
        label = "hello/list side-effect-free test";
        needle = "lifecycle_hello_and_list_scenarios_are_side_effect_free";
      }
      {
        label = "create/list/destroy test";
        needle = "create_list_destroy_session_maps_to_start_stop_and_live_mirror";
      }
      {
        label = "epoch mismatch test";
        needle = "destroy_session_rejects_epoch_mismatch_without_dropping_actor";
      }
      {
        label = "inline scenario test";
        needle = "create_session_accepts_inline_scenario_without_registry_entry";
      }
      {
        label = "unknown scenario test";
        needle = "create_session_rejects_unknown_scenario_without_side_effects";
      }
      {
        label = "control client trait lifecycle test";
        needle = "lifecycle_unary_methods_are_exposed_on_control_client_trait";
      }
      {
        label = "start-paused false test";
        needle = "create_session_start_paused_false_continues_to_running";
      }
      {
        label = "scenario seed materialization test";
        needle = "scenario_ref_create_materializes_the_requested_seed";
      }
      {
        label = "inline seed mismatch test";
        needle = "create_session_rejects_inline_seed_mismatch_without_side_effects";
      }
      {
        label = "resume checkpoint closure test";
        needle = "resume_session_accepts_checkpoint_closure_and_paused_live_mirror";
      }
      {
        label = "resume checkpoint rejection test";
        needle = "resume_session_rejects_mismatched_checkpoint_closure_without_side_effects";
      }
      {
        label = "resume genesis material rejection test";
        needle = "resume_session_rejects_tampered_zero_time_baked_genesis";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_client*.rs" controlClientTest [
      {
        label = "RPC server backed by lifecycle control plane";
        needle = "LifecycleControlPlane<ServerQuantumLoop";
      }
      {
        label = "RPC server constructs real lifecycle plane";
        needle = "lifecycle_control_plane()";
      }
      {
        label = "RPC create request parser";
        needle = "parse_create_session_request";
      }
      {
        label = "RPC resume request parser";
        needle = "parse_resume_session_request";
      }
      {
        label = "RPC resume scenario payload parser";
        needle = "parse_scenario_form_line";
      }
      {
        label = "RPC resume lifecycle path";
        needle = "RPC resume session should decode";
      }
      {
        label = "RPC resume route";
        needle = ''"/crucible.rpc/resume-session"'';
      }
      {
        label = "RPC inline scenario reconstruction";
        needle = "ScenarioDef::from_content_hash_seed_and_app_random_draw_cap";
      }
      {
        label = "RPC inline scenario seed parser";
        needle = ''"scenario-seed="'';
      }
      {
        label = "RPC start-paused false path";
        needle = "with_start_paused(false)";
      }
      {
        label = "RPC inline lifecycle path";
        needle = "RPC inline create session should decode";
      }
      {
        label = "RPC inline mismatch rejection";
        needle = "RPC inline seed mismatch should reject";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes API lifecycle unary check";
        needle = "apiLifecycleUnary = import ./phase5-api-lifecycle-unary.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-api-lifecycle-unary";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_API_3_FAILURES = failureText;
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
        name = "run-phase5-api-lifecycle-unary";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_API_3_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_API_3_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-lifecycle-unary-target" \
            -p crucible-api \
            --test gate_lifecycle_unary \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-api-lifecycle-unary-target" \
            -p crucible-api \
            --test gate_control_client \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          set -eu

          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'hello=side_effect_free\n'
            printf 'list_scenarios=registry_read\n'
            printf 'create_session=start_command\n'
            printf 'list_sessions=live_mirror_read\n'
            printf 'destroy_session=epoch_guarded_stop\n'
            printf 'rpc_lifecycle=control_client_transport\n'
          } > "$out/result"
        '';
      }
    ];
  }
