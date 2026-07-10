{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerRunCeiling",
  taskIds ? ["T-SCHED-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  runCeilingTest = builtins.readFile ../../crates/crucible/tests/scheduler_run_ceiling.rs;
  shmem = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  shmemTest = builtins.readFile ../../crates/crucible-shmem/tests/advance_ceiling_handoff.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-14 checked off";
        needle = "- [x] **T-SCHED-14**";
      }
      {
        label = "T-SCHED-14 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerRunCeiling`";
      }
      {
        label = "single ceiling requirement";
        needle = "single per-node max-advance ceiling";
      }
      {
        label = "published once requirement";
        needle = "published once per quantum";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "ceiling publication record";
        needle = "pub struct SchedulerRunCeilingPublication";
      }
      {
        label = "shmem ABI conversion";
        needle = "pub fn to_shmem_ceiling";
      }
      {
        label = "publication log";
        needle = "ceiling_publications";
      }
      {
        label = "publication accessor";
        needle = "run_ceiling_publications";
      }
      {
        label = "single publish helper";
        needle = "fn publish_run_ceiling";
      }
      {
        label = "ceiling-before-current guard";
        needle = "max_advance_icount < current_icount.ticks";
      }
      {
        label = "publication append";
        needle = "self.ceiling_publications.push(publication.clone())";
      }
      {
        label = "RUN critical section";
        needle = "SchedulerCriticalSection::enter(self)";
      }
      {
        label = "RUN publishes from advance plan";
        needle = "self.scheduler.publish_run_ceiling(";
      }
      {
        label = "RUN consumes published ceiling";
        needle = "plan.ceiling.max_advance_icount != plan.target_counter";
      }
      {
        label = "last advance records ceiling";
        needle = "ceiling: plan.ceiling.clone()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "ceiling publication export";
        needle = "SchedulerRunCeilingPublication";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_run_ceiling.rs" runCeilingTest [
      {
        label = "single publication test";
        needle = "run_publishes_one_max_advance_ceiling_for_selected_node";
      }
      {
        label = "no intermediate publication test";
        needle = "each_run_gets_one_ceiling_and_no_intermediate_publication";
      }
      {
        label = "no-run no-ceiling test";
        needle = "control_only_quantum_publishes_no_run_ceiling";
      }
      {
        label = "published target consumption test";
        needle = "run_consumes_the_published_ceiling_as_its_target";
      }
      {
        label = "shmem ABI test";
        needle = "published_ceiling_converts_to_and_publishes_through_shmem_abi";
      }
      {
        label = "shmem conversion call";
        needle = ".to_shmem_ceiling()";
      }
      {
        label = "shmem slot publish call";
        needle = "slot.publish_scheduler_ceiling(ceiling)";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmem [
      {
        label = "shmem slot publish API";
        needle = "pub fn publish_scheduler_ceiling";
      }
      {
        label = "ABI field release store";
        needle = ".store(ceiling.max_advance_icount, Ordering::Release)";
      }
      {
        label = "node ceiling acquire load";
        needle = "pub fn load_node_ceiling";
      }
      {
        label = "advance ceiling authorization";
        needle = "pub fn authorize_advance_ceiling";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/advance_ceiling_handoff.rs" shmemTest [
      {
        label = "shmem handoff regression";
        needle = "scheduler_publishes_ceiling_and_node_publishes_reached_icount";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler run-ceiling check";
        needle = "schedulerRunCeiling = import ./phase3-scheduler-run-ceiling.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_run_ceiling.rs" runCeilingTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler run-ceiling check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-run-ceiling";
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
          name = "run-scheduler-run-ceiling";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-run-ceiling-target" \
              -p crucible \
              --features test-double \
              --test scheduler_run_ceiling \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-run-ceiling-target" \
              -p crucible-shmem \
              --test advance_ceiling_handoff \
              scheduler_publishes_ceiling_and_node_publishes_reached_icount \
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
            run_ceiling=single-max-advance-publication-per-RUN
            shmem_field=max_advance_icount
            intermediate_ceiling=false
            wake_ordering=covered-by-checks.crucible.phase3.schedulerWakeOrdering
            RESULT
          '';
        }
      ];
    }
