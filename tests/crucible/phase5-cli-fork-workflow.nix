{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliForkWorkflow",
  taskIds ? ["T-CLI-11"],
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
        label = "T-CLI-11 remains open";
        needle = "- [ ] **T-CLI-11** Implement `fork`";
      }
      {
        label = "T-CLI-11 progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliForkWorkflow`";
      }
      {
        label = "T-CLI-11 local child runner progress";
        needle = "no-divergence local-double forks through an independent child session";
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
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI fork progress note";
        needle = "`T-CLI-11` remains open. `checks.crucible.phase5.cliForkWorkflow` currently";
      }
      {
        label = "phase5 CLI fork override progress";
        needle = "repeatable post-fork\n  `--override` decision application";
      }
      {
        label = "phase5 CLI fork seed progress";
        needle = "explicit post-fork `--seed` execution in\n  the local double by deriving the child's post-fork decision stream";
      }
      {
        label = "phase5 CLI fork artifact progress";
        needle = "CLI-replayable child reproduction artifact writing whose\n  embedded seed remains the scenario-form seed plus fork-seed provenance output";
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
        label = "fork override virtual-time test";
        needle = "child-override-virtual";
      }
      {
        label = "fork override stopped test";
        needle = "child-override-stopped";
      }
      {
        label = "fork override interactive test";
        needle = "child-override-interactive";
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
        label = "fork bare-hash blocker test";
        needle = "cli_fork_workflow_rejects_bare_hash_until_closure_loader_exists";
      }
      {
        label = "fork execution test";
        needle = "cli_fork_workflow_executes_local_double_handle";
      }
      {
        label = "fork tampered frontier test";
        needle = "cli_fork_workflow_rejects_tampered_handle_frontier";
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
            contract=fork-workflow-progress
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
