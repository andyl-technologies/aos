{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSearchFuzzWorkflow",
  taskIds ? ["T-CLI-13"],
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
        label = "T-CLI-13 remains open";
        needle = "- [ ] **T-CLI-13** Implement `search`/`fuzz`";
      }
      {
        label = "T-CLI-13 progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliSearchFuzzWorkflow`";
      }
      {
        label = "T-CLI-13 local-double search progress";
        needle = "executes local `--backend double search` without";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI search/fuzz progress note";
        needle = "`checks.crucible.phase5.cliSearchFuzzWorkflow`";
      }
      {
        label = "phase5 CLI local-double search progress";
        needle = "deterministic `search-run` output and `failure_oracle=none`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "search arguments";
        needle = "struct SearchArgs";
      }
      {
        label = "fuzz arguments";
        needle = "struct FuzzArgs";
      }
      {
        label = "search driver plan";
        needle = "struct SearchDriverPlan";
      }
      {
        label = "fuzz driver plan";
        needle = "struct FuzzDriverPlan";
      }
      {
        label = "search planner";
        needle = "fn plan_search_invocation";
      }
      {
        label = "fuzz planner";
        needle = "fn plan_fuzz_invocation";
      }
      {
        label = "advanced search strategy mapping";
        needle = "crucible::SearchStrategy::CoverageGuided";
      }
      {
        label = "coverage fuzz config mapping";
        needle = "crucible::CoverageGuidedFuzzConfig::new";
      }
      {
        label = "local-double search runner";
        needle = "fn run_local_double_search_workflow";
      }
      {
        label = "local-double search output";
        needle = "search-run";
      }
      {
        label = "local-double search no-oracle marker";
        needle = "failure_oracle=none";
      }
      {
        label = "local-double search canonical log";
        needle = "search_strategy_run";
      }
      {
        label = "local-double max-depth blocker";
        needle = "local-double search --max-depth requires the depth-limited search runner tracked by T-CLI-13";
      }
      {
        label = "local-double failure oracle blocker";
        needle = "local-double search currently runs with failure_oracle=none";
      }
      {
        label = "fuzz runner blocker";
        needle = "requires the exploration-engine driver over phase-6 fuzzing policies tracked by T-CLI-13";
      }
      {
        label = "search fuzz help test";
        needle = "cli_search_fuzz_help_surface_lists_wip_flags";
      }
      {
        label = "search fuzz planning test";
        needle = "cli_search_fuzz_workflow_plans_drivers_and_rejects_bad_inputs";
      }
      {
        label = "search fuzz local-double execution test";
        needle = "cli_search_fuzz_workflow_executes_local_double_search";
      }
      {
        label = "search fuzz fuzz-blocker test";
        needle = "cli_search_fuzz_workflow_rejects_fuzz_execution_until_driver_exists";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI search/fuzz workflow check";
        needle = "cliSearchFuzzWorkflow = import ./phase5-cli-search-fuzz-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI search/fuzz workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-search-fuzz-workflow";
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
          name = "run-cli-search-fuzz-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-search-fuzz-workflow-target" \
              -p crucible-cli \
              cli_search_fuzz \
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
            contract=search-fuzz-workflow-progress
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
