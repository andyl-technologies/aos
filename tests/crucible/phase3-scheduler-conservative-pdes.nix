{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerConservativePdes",
  taskIds ? ["T-SCHED-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulerPdesTest = builtins.readFile ../../crates/crucible/tests/scheduler_conservative_pdes.rs;
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
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
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
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
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
    ++ failuresFor "crates/crucible/tests/scheduler_conservative_pdes.rs" schedulerPdesTest [
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
        needle = "single_scheduler_rejects_unaligned_dependency_ceiling_overshoot";
      }
      {
        label = "due dependency integration test";
        needle = "single_scheduler_rejects_due_cross_node_dependency_before_advance";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_conservative_pdes.rs" schedulerPdesTest [
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
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-conservative-pdes";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
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
          name = "run-scheduler-conservative-pdes";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-conservative-pdes-target" \
              -p crucible \
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
