{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliForkWorkflow",
  taskIds ? [],
  openTaskIds ? ["T-CLI-11"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
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
        label = "T-CLI-11 remains open";
        needle = "- [ ] **T-CLI-11** Implement `fork`";
      }
      {
        label = "T-CLI-11 partial-evidence note";
        needle = "Partial evidence under `checks.crucible.phase5.cliForkWorkflow`";
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
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI fork completion note";
        needle = "`T-CLI-11` has partial coverage through `checks.crucible.phase5.cliForkWorkflow`";
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
      {
        label = "phase5 CLI fork local-QEMU progress";
        needle = "explicitly selected local-QEMU forks through\n  the same child-session materialization";
      }
      {
        label = "phase5 CLI process qemu fork progress";
        needle = "process-level\n  `fork --backend qemu` JSONL output plus child artifact creation";
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
        label = "fork local-QEMU identity output";
        needle = "fork-qemu-runner";
      }
      {
        label = "fork local-QEMU canonical log";
        needle = "fork_qemu_runner";
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
        label = "fork bare-hash store loader test";
        needle = "cli_fork_workflow_executes_local_double_bare_hash_from_store";
      }
      {
        label = "fork execution test";
        needle = "cli_fork_workflow_executes_local_double_handle";
      }
      {
        label = "fork local-QEMU execution test";
        needle = "cli_fork_workflow_executes_local_qemu_handle_with_identity";
      }
      {
        label = "fork tampered frontier test";
        needle = "cli_fork_workflow_rejects_tampered_handle_frontier";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "process qemu fork JSONL regression";
        needle = "cli_fork_qemu_process_jsonl_reports_identity_and_artifact";
      }
      {
        label = "process qemu fork runner kind";
        needle = "\"fork_qemu_runner\"";
      }
      {
        label = "process qemu fork artifact kind";
        needle = "\"fork_reproduction_artifact\"";
      }
      {
        label = "process qemu fork oracle kind";
        needle = "\"fork_oracle_validation\"";
      }
      {
        label = "process qemu fork patch series";
        needle = "qemu_patch_series=sha256-process-qemu-patch-series";
      }
      {
        label = "process qemu fork materialization";
        needle = "materialization=child-session-savepoint";
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
              cli_fork_qemu_process_jsonl_reports_identity_and_artifact \
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
            status=partial
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
