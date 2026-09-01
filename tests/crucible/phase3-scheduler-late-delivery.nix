{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerLateDelivery",
  taskIds ? ["T-SCHED-18"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  resolveTest = builtins.readFile ../../crates/crucible/tests/scheduler_resolve.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-18 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerLateDelivery`";
      }
      {
        label = "late delivery requirement";
        needle = "Enforce the lookahead guarantee in RESOLVE";
      }
      {
        label = "never deliver late requirement";
        needle = "never deliver the event late";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "late delivery comparison";
        needle = "delivery_time < advanced_to";
      }
      {
        label = "late delivery error";
        needle = "late scheduled event";
      }
      {
        label = "boundary violation";
        needle = "return Err(SchedulerError::BoundaryViolation";
      }
      {
        label = "localized delivery diagnostic";
        needle = "delivery={} advanced_to={}";
      }
      {
        label = "localized producer diagnostic";
        needle = "event.key.producer().node.name";
      }
      {
        label = "exact frontier resolve";
        needle = "delivery_time == advanced_to";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_resolve.rs" resolveTest [
      {
        label = "direct late resolver test";
        needle = "resolve_rejects_late_event_before_advanced_frontier";
      }
      {
        label = "live scheduler late self-delivery test";
        needle = "single_scheduler_rejects_self_delivery_that_would_be_late";
      }
      {
        label = "late message assertion";
        needle = "late scheduled event";
      }
      {
        label = "delivery diagnostic assertion";
        needle = "delivery=3";
      }
      {
        label = "advanced frontier diagnostic assertion";
        needle = "advanced_to=4";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler late-delivery check";
        needle = "schedulerLateDelivery = import ./phase3-scheduler-late-delivery.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_resolve.rs" resolveTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "wall-clock dependency";
        needle = "std::time";
      }
      {
        label = "sleep dependency";
        needle = "sleep(";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler late-delivery check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-late-delivery";
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
          name = "run-scheduler-late-delivery";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-late-delivery-target" \
              -p crucible \
              --test scheduler_resolve \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-late-delivery-target" \
              -p crucible \
              --test scheduler_conservative_pdes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-late-delivery-target" \
              -p crucible \
              --features test-double \
              --test gate_scheduler_liveness \
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
            late_delivery=fail-loud-localized
            exact_frontier_delivery=true
            deliver_late=false
            RESULT
          '';
        }
      ];
    }
