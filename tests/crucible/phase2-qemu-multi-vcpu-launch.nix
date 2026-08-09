{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuMultiVcpuLaunch",
  taskIds ? ["T-QEMU-15" "T-DET-29"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  launchLib = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  validationLib =
    builtins.readFile ../../crates/crucible-qemu/src/launch/validation.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/validation/values.rs;
  launchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  determinismSpec = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  spatialSpec = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismSpec [
      {
        label = "T-DET-29 task traceability marker";
        needle = "**T-DET-29**";
      }
      {
        label = "T-DET-29 completion note names launch gate";
        needle = "`checks.crucible.phase2.qemuMultiVcpuLaunch`";
      }
      {
        label = "T-DET-29 completion note names MTTCG rejection";
        needle = "rejects MTTCG";
      }
      {
        label = "T-DET-30 task traceability marker";
        needle = "**T-DET-30**";
      }
      {
        label = "T-DET-30 completion note names launch check";
        needle = "`checks.crucible.phase2.qemuMultiVcpuLaunch`";
      }
      {
        label = "T-DET-30 completion note names fixed topology";
        needle = "fixed-at-genesis topology";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-15 task traceability marker";
        needle = "**T-QEMU-15**";
      }
      {
        label = "T-QEMU-15 completion note names multi-vCPU acceptance";
        needle = "accepts `smp_vcpus >= 1`";
      }
      {
        label = "T-QEMU-15 completion note names pre-spawn MTTCG rejection";
        needle = "pre-spawn validator rejects MTTCG";
      }
      {
        label = "T-QEMU-15 completion note names RFC alias";
        needle = "`crucible-rr-quantum-icount`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialSpec [
      {
        label = "World schema carries vCPU count";
        needle = "pub smp_vcpus: u16,";
      }
      {
        label = "World schema hashes fixed vCPU count";
        needle = "Fixed vCPU count. `N >= 1`";
      }
      {
        label = "SPAT-8 permits fixed multi-vCPU RR contract";
        needle = "Each VM node MUST request a fixed vCPU count `N >= 1`";
      }
      {
        label = "SPAT-8 rejects MTTCG";
        needle = "never MTTCG";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" launchLib [
      {
        label = "deterministic profile stores vCPU count";
        needle = "smp_vcpus: u16,";
      }
      {
        label = "zero vCPU profile rejection";
        needle = "if self.smp_vcpus == 0";
      }
      {
        label = "zero vCPU profile error";
        needle = "LaunchProfileError::SmpVcpuCountZero";
      }
      {
        label = "deterministic profile receives candidate vCPU count";
        needle = "smp_vcpus: self.smp_vcpus,";
      }
      {
        label = "canonical args emit selected vCPU count";
        needle = "self.smp_vcpus.to_string(),";
      }
      {
        label = "canonical args keep single-threaded TCG";
        needle = "DEFAULT_ACCEL.to_owned(),";
      }
      {
        label = "canonical args pin RR quantum";
        needle = "\"shift={},sleep=off,align=off,rr_switch_quantum={}\",";
      }
      {
        label = "scenario material hashes selected vCPU count";
        needle = "format!(\"smp_vcpus={}\", self.smp_vcpus),";
      }
      {
        label = "scenario material records fixed topology";
        needle = "\"vcpu_topology=fixed-at-genesis\".to_owned(),";
      }
      {
        label = "scenario material forbids runtime CPU hotplug";
        needle = "\"runtime_cpu_hotplug=forbidden\".to_owned(),";
      }
      {
        label = "scenario material hashes RR quantum";
        needle = "format!(\"rr_switch_quantum={}\", self.rr_switch_quantum),";
      }
      {
        label = "scenario material records RR units";
        needle = "\"rr_switch_quantum_units=node-icount\".to_owned(),";
      }
      {
        label = "scenario material records ascending vCPU rotation";
        needle = "\"rr_vcpu_rotation=ascending-vcpu-id\".to_owned(),";
      }
      {
        label = "scenario material records uniform per-vCPU CPU model";
        needle = "\"per_vcpu_cpu_model=uniform\".to_owned(),";
      }
      {
        label = "scenario material records per-vCPU TSC source";
        needle = "\"per_vcpu_tsc_source=node-icount\".to_owned(),";
      }
      {
        label = "scenario material records per-vCPU RNG source";
        needle = "\"per_vcpu_rng_source=scenario-seed-and-run-seed\".to_owned(),";
      }
      {
        label = "scenario material records per-vCPU RNG timing axis";
        needle = "\"per_vcpu_rng_timing_axis=node-icount\".to_owned(),";
      }
      {
        label = "scenario material records deterministic secondary vCPU bringup";
        needle = "\"secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic\".to_owned(),";
      }
      {
        label = "vCPU count accessor";
        needle = "pub fn smp_vcpus(&self) -> u16";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/validation.rs" validationLib [
      {
        label = "MTTCG validator rejection";
        needle = "QemuPreSpawnLaunchValidationError::MultiThreadTcg";
      }
      {
        label = "single-threaded sim TCG must be pinned";
        needle = "QemuPreSpawnLaunchValidationError::SingleThreadSimNotPinned";
      }
      {
        label = "RR quantum validator supports current patch option and RFC alias";
        needle = "&[\"rr_switch_quantum\", \"crucible-rr-quantum-icount\"],";
      }
      {
        label = "RR quantum duplicate label covers alias/current ambiguity";
        needle = "\"rr_switch_quantum\",";
      }
      {
        label = "duplicate deterministic sub-options rejected";
        needle = "QemuPreSpawnLaunchValidationError::DuplicateSubOption";
      }
      {
        label = "unique accelerator thread parser";
        needle = "unique_comma_value(&lower, \"-accel\", \"thread\")?";
      }
      {
        label = "unique RR quantum parser across alias/current key";
        needle = "unique_comma_value_any(";
      }
      {
        label = "unpinned RR quantum rejected";
        needle = "QemuPreSpawnLaunchValidationError::RrSwitchQuantumUnpinned";
      }
      {
        label = "sleep realtime switching rejected";
        needle = "validate_required_icount_value(icount, \"sleep\", \"off\")?;";
      }
      {
        label = "align realtime switching rejected";
        needle = "validate_required_icount_value(icount, \"align\", \"off\")?;";
      }
      {
        label = "realtime launch option rejected";
        needle = "\"-realtime\" | \"-real-time\" => Err(";
      }
      {
        label = "zero RR quantum rejected";
        needle = "QemuPreSpawnLaunchValidationError::RrSwitchQuantumZero";
      }
      {
        label = "SMP validator accepts positive counts";
        needle = "fn validate_pre_spawn_smp";
      }
      {
        label = "SMP validator rejects zero";
        needle = "QemuPreSpawnLaunchValidationError::SmpZero";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "multi-vCPU RR test";
        needle = "multi_vcpu_round_robin_launch_is_pinned_validated_and_hashed";
      }
      {
        label = "multi-vCPU canonical smp assertion";
        needle = "window == [\"-smp\", \"4\"]";
      }
      {
        label = "multi-vCPU RR quantum assertion";
        needle = "rr_switch_quantum=8192";
      }
      {
        label = "multi-vCPU pre-spawn validation assertion";
        needle = "validation.smp_vcpus(), 4";
      }
      {
        label = "multi-vCPU CPU model validation assertion";
        needle = "validation.cpu_model(), \"qemu64,-rdrand,-rdseed\"";
      }
      {
        label = "multi-vCPU scenario material assertion";
        needle = "material.contains(\"smp_vcpus=4\")";
      }
      {
        label = "multi-vCPU fixed topology assertion";
        needle = "material.contains(\"vcpu_topology=fixed-at-genesis\")";
      }
      {
        label = "multi-vCPU no runtime hotplug assertion";
        needle = "material.contains(\"runtime_cpu_hotplug=forbidden\")";
      }
      {
        label = "multi-vCPU uniform CPU model assertion";
        needle = "material.contains(\"per_vcpu_cpu_model=uniform\")";
      }
      {
        label = "multi-vCPU per-vCPU TSC assertion";
        needle = "material.contains(\"per_vcpu_tsc_source=node-icount\")";
      }
      {
        label = "multi-vCPU per-vCPU RNG assertion";
        needle = "material.contains(\"per_vcpu_rng_source=scenario-seed-and-run-seed\")";
      }
      {
        label = "multi-vCPU per-vCPU RNG timing assertion";
        needle = "material.contains(\"per_vcpu_rng_timing_axis=node-icount\")";
      }
      {
        label = "multi-vCPU deterministic secondary bringup assertion";
        needle = "material.contains(\"secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic\")";
      }
      {
        label = "vCPU count changes scenario material";
        needle = "different_vcpu_count";
      }
      {
        label = "RR quantum changes scenario material";
        needle = "different_quantum";
      }
      {
        label = "zero vCPU rejection assertion";
        needle = "LaunchProfileError::SmpVcpuCountZero";
      }
      {
        label = "duplicate accelerator thread assertion";
        needle = "sim,thread=single,thread=multi";
      }
      {
        label = "duplicate RR quantum assertion";
        needle = "rr_switch_quantum=4096,rr_switch_quantum=8192";
      }
      {
        label = "mixed current and RFC alias assertion";
        needle = "rr_switch_quantum=4096,crucible-rr-quantum-icount=4096";
      }
      {
        label = "sleep realtime switching assertion";
        needle = "shift=0,sleep=on,align=off,rr_switch_quantum=4096";
      }
      {
        label = "align realtime switching assertion";
        needle = "shift=0,sleep=off,align=on,rr_switch_quantum=4096";
      }
      {
        label = "realtime option assertion";
        needle = "\"-realtime\", \"mlock=on\"";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes QEMU multi-vCPU launch check";
        needle = "qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu multi-vCPU launch check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-multi-vcpu-launch";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-qemu-multi-vcpu-launch";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-multi-vcpu-launch-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test deterministic_launch \
              multi_vcpu_round_robin_launch_is_pinned_validated_and_hashed \
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
            gate=gate:layer0-determinism
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=complete
            check_scope=task-level
            qemu_5=single-threaded-round-robin-sim-tcg-with-smp-N
            qemu_43=pre-spawn-rr-quantum-validation
            accelerator=sim,thread=single
            accelerator_family=tcg-derived-sim
            stock_tcg_crucible_runtime=forbidden
            smp_vcpus=N>=1
            smp_default=1
            smp_multi_vcpu_test=4
            rr_switch_quantum=content-addressed-node-icount
            rr_switch_quantum_current_qemu_option=rr_switch_quantum
            rr_switch_quantum_rfc_alias=crucible-rr-quantum-icount
            rr_vcpu_rotation=ascending-vcpu-id
            cpu_model_scope=uniform-all-vcpus
            per_vcpu_tsc_source=node-icount
            per_vcpu_rng_source=scenario-seed-and-run-seed
            per_vcpu_rng_timing_axis=node-icount
            vcpu_topology=fixed-at-genesis
            runtime_cpu_hotplug=false
            secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic
            rejects_mttcg=true
            rejects_unpinned_rr_switch_quantum=true
            rejects_adaptive_rr_quantum=true
            rejects_realtime_switching=true
            scenario_hash_folds=smp_vcpus,rr_switch_quantum,rr_vcpu_rotation,cpu_model,per_vcpu_entropy,vcpu_topology
            rust_test=crucible-qemu::deterministic_launch::multi_vcpu_round_robin_launch_is_pinned_validated_and_hashed
            RESULT
          '';
        }
      ];
    }
