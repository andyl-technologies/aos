{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerConservativePdes",
  taskIds ? ["T-SCHED-3"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/crucible-engine/src/lib.rs;
  schedulerPdesTest = builtins.readFile ../../crates/crucible/crucible-engine/tests/scheduler_conservative_pdes.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-3 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerConservativePdes`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/scheduler.rs" scheduler [
      {
        label = "unresolved cross-node dependency type";
        needle = "pub struct UnresolvedCrossNodeDependency";
      }
      {
        label = "conservative authorization type";
        needle = "pub struct ConservativeAdvanceAuthorization";
      }
      {
        label = "dependency extractor";
        needle = "pub fn unresolved_cross_node_dependencies";
      }
      {
        label = "conservative advance guard";
        needle = "pub fn authorize_conservative_advance";
      }
      {
        label = "backend-input-only dependency";
        needle = "ScheduledEventPayload::BackendInput";
      }
      {
        label = "rollback rejection";
        needle = "conservative PDES rejected rollback";
      }
      {
        label = "already-due dependency rejection";
        needle = "unresolved cross-node dependency is due";
      }
      {
        label = "icount ceiling overshoot rejection";
        needle = "conservative PDES rejected icount ceiling overshoot";
      }
      {
        label = "advance window guard";
        needle = "let authorization = authorize_conservative_advance";
      }
      {
        label = "authorized target applied";
        needle = "authorization.authorized_target";
      }
      {
        label = "dependency cap carried to advance plan";
        needle = "conservative_dependency: window.conservative_dependency";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" libSource [
      {
        label = "authorization export";
        needle = "ConservativeAdvanceAuthorization";
      }
      {
        label = "dependency export";
        needle = "UnresolvedCrossNodeDependency";
      }
      {
        label = "advance guard export";
        needle = "authorize_conservative_advance";
      }
      {
        label = "dependency helper export";
        needle = "unresolved_cross_node_dependencies";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/tests/scheduler_conservative_pdes.rs" schedulerPdesTest [
      {
        label = "clamp test";
        needle = "conservative_pdes_authorization_clamps_at_unresolved_cross_node_dependency";
      }
      {
        label = "target-before-dependency test";
        needle = "conservative_pdes_authorization_allows_target_before_dependency";
      }
      {
        label = "rollback test";
        needle = "conservative_pdes_authorization_rejects_rollback";
      }
      {
        label = "cross-node-only test";
        needle = "conservative_pdes_dependencies_only_include_cross_node_backend_input";
      }
      {
        label = "scheduler clamp integration test";
        needle = "single_scheduler_stops_at_future_cross_node_dependency_before_horizon";
      }
      {
        label = "unaligned dependency cap test";
        needle = "single_scheduler_floors_unaligned_dependency_then_rejects_sub_tick_stall";
      }
      {
        label = "due dependency integration test";
        needle = "single_scheduler_rejects_due_cross_node_dependency_before_advance";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/tests/scheduler_conservative_pdes.rs" schedulerPdesTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes conservative PDES check";
        needle = "schedulerConservativePdes = import ./phase3-scheduler-conservative-pdes.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler conservative-PDES check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase3-scheduler-conservative-pdes";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-scheduler-conservative-pdes";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --test scheduler_conservative_pdes \
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
            check=${attrPath}
            tasks=${taskList}
            component=crucible-scheduler
            discipline=conservative-pdes
            rollback=forbidden
            speculation=forbidden
            RESULT
          '';
        }
      ];
    }
