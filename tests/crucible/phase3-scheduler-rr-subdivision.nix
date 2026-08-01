{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerRrSubdivision",
  taskIds ? ["T-SCHED-28"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  rrSubdivisionTest = builtins.readFile ../../crates/crucible/tests/scheduler_rr_subdivision.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-28 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerRrSubdivision`";
      }
      {
        label = "fixed ascending rotation note";
        needle = "fixed ascending rotation";
      }
      {
        label = "single ceiling note";
        needle = "single node-level ceiling";
      }
      {
        label = "plugin internal note";
        needle = "plugin-internal";
      }
      {
        label = "single-vCPU note";
        needle = "single-vCPU";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "RR subdivision policy";
        needle = "pub struct SchedulerRunSubdivisionPolicy";
      }
      {
        label = "RR subdivision slice";
        needle = "pub struct SchedulerRunSubdivisionSlice";
      }
      {
        label = "RR subdivision record";
        needle = "pub struct SchedulerRunSubdivisionRecord";
      }
      {
        label = "pure RR helper";
        needle = "pub fn scheduler_rr_run_subdivision";
      }
      {
        label = "scenario policy builder";
        needle = "with_run_subdivision_policy";
      }
      {
        label = "subdivision record accessor";
        needle = "pub fn run_subdivision_records";
      }
      {
        label = "policy material participates in scenario identity";
        needle = "run_subdivision_policy_material";
      }
      {
        label = "critical section planned RR evidence";
        needle = "planned_run_subdivision";
      }
      {
        label = "critical section records RR evidence";
        needle = "record_run_subdivision";
      }
      {
        label = "single-vCPU degenerate branch";
        needle = "if vcpu_count == 1";
      }
      {
        label = "one ceiling remains published";
        needle = "self.scheduler.publish_run_ceiling(";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "policy exported";
        needle = "SchedulerRunSubdivisionPolicy";
      }
      {
        label = "record exported";
        needle = "SchedulerRunSubdivisionRecord";
      }
      {
        label = "slice exported";
        needle = "SchedulerRunSubdivisionSlice";
      }
      {
        label = "pure helper exported";
        needle = "scheduler_rr_run_subdivision";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_rr_subdivision.rs" rrSubdivisionTest [
      {
        label = "focused scheduler RR subdivision test";
        needle = "scheduler RR subdivision inside RUN";
      }
      {
        label = "multi-vCPU rotation test";
        needle = "multi_vcpu_run_subdivision_uses_fixed_quantum_and_ascending_rotation";
      }
      {
        label = "single-vCPU degenerate test";
        needle = "single_vcpu_subdivision_consumes_whole_budget";
      }
      {
        label = "concurrent completed-record test";
        needle = "concurrent_rr_subdivision_records_one_completed_record_per_outcome";
      }
      {
        label = "failed resolve no-record test";
        needle = "failed_resolve_after_run_plan_records_no_rr_subdivision";
      }
      {
        label = "one node ceiling test";
        needle = "run_subdivision_policy_does_not_publish_extra_ceilings";
      }
      {
        label = "invalid policy test";
        needle = "invalid_rr_policy_rejects_zero_quantum_or_vcpus";
      }
      {
        label = "no policy test";
        needle = "node_without_run_subdivision_policy_records_no_rr_slices";
      }
      {
        label = "expected first partial slice";
        needle = "slice(0, 2, 4)";
      }
      {
        label = "record tied to ceiling";
        needle = "assert_eq!(&record.ceiling, ceiling)";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_rr_subdivision.rs" rrSubdivisionTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler RR subdivision check";
        needle = "schedulerRrSubdivision = import ./phase3-scheduler-rr-subdivision.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler RR subdivision check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-rr-subdivision";
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
          name = "run-scheduler-rr-subdivision";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-rr-subdivision-target" \
              -p crucible \
              --test scheduler_rr_subdivision \
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
            gate=gate:single-vm-fingerprint,gate:layer1-injection
            rr_subdivision_internal=true
            single_node_ceiling=true
            RESULT
          '';
        }
      ];
    }
