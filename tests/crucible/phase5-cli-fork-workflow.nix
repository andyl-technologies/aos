{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliForkWorkflow",
  taskIds ? ["T-CLI-11"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliFork = builtins.readFile ../../crates/crucible-cli/src/cli/resume_fork.rs;
  apiLifecycle = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/src/vm_lifecycle.rs;
  };
  apiRuntime =
    builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/runtime.rs
    + builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/quantum_loop.rs
    + builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/quantum_loop/lifecycle/restart_ownership.rs;
  qemuLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch/plugin_config.rs;
  qemuNodeLaunch = builtins.readFile ../../crates/crucible-qemu/src/supervision/node_step_gate/support.rs;
  pluginRuntime = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/live_whitebox/app_random.rs;
  liveWhiteboxGate = builtins.readFile ./phase2-qemu-live-whitebox-doorbell.nix;
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-11 partial-evidence note";
        needle = "Completed under `checks.crucible.phase5.cliForkWorkflow`";
      }
      {
        label = "T-CLI-11 local child runner progress";
        needle = "store-backed no-divergence local-double forks through an independent child";
      }
      {
        label = "T-CLI-11 override execution progress";
        needle = "applies\n  repeatable post-fork `--override` decisions";
      }
      {
        label = "T-CLI-11 seed execution progress";
        needle = "applies explicit post-fork `--seed` in the local double by deriving the child's";
      }
      {
        label = "T-CLI-11 child artifact progress";
        needle = "writes a CLI-replayable child reproduction artifact whose\n  embedded seed remains the scenario-form seed";
      }
      {
        label = "T-CLI-11 local-QEMU fork routing progress";
        needle = "routes explicitly selected local-QEMU forks through the same child-session";
      }
      {
        label = "T-CLI-11 process qemu fork progress";
        needle = "process-tests real-binary `fork --backend qemu` JSONL";
      }
      {
        label = "T-CLI-11 production qemu reseed completion";
        needle = "For the production QEMU backend, `--seed` now re-seeds the live";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI fork completion note";
        needle = "`T-CLI-11` is completed through `checks.crucible.phase5.cliForkWorkflow`";
      }
      {
        label = "phase5 CLI fork override progress";
        needle = "repeatable post-fork\n  `--override` decision application";
      }
      {
        label = "phase5 CLI fork seed progress";
        needle = "explicit post-fork\n  `--seed` execution in\n  the local double by deriving the child's post-fork decision stream";
      }
      {
        label = "phase5 CLI fork artifact progress";
        needle = "CLI-replayable child reproduction artifact writing whose\n  embedded seed remains the scenario-form seed plus fork-seed provenance output";
      }
      {
        label = "phase5 CLI fork local-QEMU progress";
        needle = "explicitly selected local-QEMU forks through\n  the same child-session materialization";
      }
      {
        label = "phase5 CLI process qemu fork progress";
        needle = "process-level\n  `fork --backend qemu` JSONL output plus child artifact creation";
      }
      {
        label = "phase5 production qemu reseed completion";
        needle = "Production-QEMU\n  `--seed` forks now re-seed scheduler";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "fork arguments";
        needle = "struct ForkArgs";
      }
      {
        label = "fork invocation plan";
        needle = "struct ForkInvocationPlan";
      }
      {
        label = "fork decision override";
        needle = "struct ForkDecisionOverride";
      }
      {
        label = "fork planner";
        needle = "fn plan_fork_invocation";
      }
      {
        label = "fork override parser";
        needle = "fn parse_fork_decision_override";
      }
      {
        label = "shared savepoint resolver";
        needle = "fn resolve_savepoint_ref";
      }
      {
        label = "fork local-double runner";
        needle = "fn run_local_double_fork_workflow";
      }
      {
        label = "fork local-QEMU runner";
        needle = "fn run_local_qemu_fork_workflow";
      }
      {
        label = "fork dispatches the live QEMU workflow";
        needle = "fn run_local_qemu_fork_workflow";
      }
      {
        label = "fork local-QEMU thin-replay proof";
        needle = "fork-thin-replay";
      }
      {
        label = "fork child actor runner";
        needle = "fn run_forked_savepoint_actor_with_driver_async";
      }
      {
        label = "fork oracle output";
        needle = "fork-oracle";
      }
      {
        label = "fork oracle canonical log";
        needle = "fork_oracle_validation";
      }
      {
        label = "fork seed execution";
        needle = "with_post_fork_seed";
      }
      {
        label = "fork seed provenance";
        needle = "fork_seed";
      }
      {
        label = "fork seed output";
        needle = "fn fork_seed_label";
      }
      {
        label = "fork seeded savepoint divergence";
        needle = "seed_again_outcome.terminal_savepoint";
      }
      {
        label = "fork seeded virtual-time boundary";
        needle = "child-seed-virtual";
      }
      {
        label = "fork seeded artifact replay";
        needle = "assert_fork_artifact_replays(&seed_cli, &seeded_outcome, inherited_seed)";
      }
      {
        label = "fork override lowering";
        needle = "fn fork_override_decisions";
      }
      {
        label = "fork artifact writer";
        needle = "fn write_fork_reproduction_artifact";
      }
      {
        label = "fork artifact replay test";
        needle = "fn assert_fork_artifact_replays";
      }
      {
        label = "fork artifact output";
        needle = "fork-artifact";
      }
      {
        label = "test double cannot certify override consumption";
        needle = "test double must not certify exact override consumption";
      }
      {
        label = "fork help test";
        needle = "cli_fork_help_surface_lists_wip_flags";
      }
      {
        label = "fork planning test";
        needle = "cli_fork_workflow_plans_savepoint_overrides_and_rejects_malformed_inputs";
      }
      {
        label = "fork bare-hash store loader test";
        needle = "cli_fork_workflow_executes_local_double_bare_hash_from_store";
      }
      {
        label = "fork execution test";
        needle = "cli_fork_workflow_executes_local_double_handle";
      }
      {
        label = "fork local-QEMU live route test";
        needle = "cli_fork_workflow_routes_local_qemu_into_live_guest_configuration";
      }
      {
        label = "fork tampered frontier test";
        needle = "cli_fork_workflow_rejects_tampered_handle_frontier";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/cli/resume_fork.rs" cliFork [
      {
        label = "fork local-QEMU production reseed";
        needle = "config.with_branch_reseed(";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle.rs" apiLifecycle [
      {
        label = "production lifecycle follows authored whitebox policy";
        needle = ".with_whitebox(whitebox)";
      }
      {
        label = "production lifecycle gates app-random on whitebox opt-in";
        needle = "if vm.white_box == crucible::WhiteBoxPolicy::Enabled";
      }
      {
        label = "production lifecycle wires app-random";
        needle = "launch = launch.with_app_random(app_random);";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/runtime.rs" apiRuntime [
      {
        label = "production relaunch preowns authenticated launch configuration";
        needle = "fn prepare_terminal_lifecycle_ownership(";
      }
      {
        label = "production relaunch binds the app-random continuation";
        needle = "bind_successor_app_random(launch.clone(), successor_app_random)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/plugin_config.rs" qemuLaunch [
      {
        label = "QEMU launch carries complete branch seed";
        needle = "pub fn with_branch_seed";
      }
      {
        label = "QEMU launch carries app-random continuation";
        needle = "pub fn with_continuation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/supervision/node_step_gate/support.rs" qemuNodeLaunch [
      {
        label = "production node launcher installs app-random";
        needle = "plugin = plugin.with_app_random(app_random.clone())";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/live_whitebox/app_random.rs" pluginRuntime [
      {
        label = "live plugin switches branch seed";
        needle = "fn apply_branch_reseed_if_due";
      }
      {
        label = "live plugin restores stream positions";
        needle = "stream.advance_by(*draws);";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-whitebox-doorbell.nix" liveWhiteboxGate [
      {
        label = "patched-QEMU branch seed proof";
        needle = "app_random_branch_seed_live_qemu=true";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "process qemu fork live-asset admission regression";
        needle = "cli_fork_qemu_process_requires_packaged_live_guest_assets";
      }
      {
        label = "process qemu fork no-unwired assertion";
        needle = "!stderr.contains(\"execution is unavailable\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI fork workflow check";
        needle = "cliForkWorkflow = import ./phase5-cli-fork-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI fork workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-fork-workflow";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
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
          name = "run-cli-fork-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-fork-workflow-target" \
              -p crucible-cli \
              cli_fork \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-fork-workflow-target" \
              -p crucible-cli \
              cli_fork_qemu_process_requires_packaged_live_guest_assets \
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
            evidence_scope=fork-model-and-process-routing
            component=crucible-cli
            contract=fork-workflow-progress
            process_qemu_fork=marker-resolved-jsonl-artifact
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
