{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLaunchValidation",
  taskIds ? ["T-QEMU-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  launchLib = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  launchValidation = builtins.readFile ../../crates/crucible-qemu/src/launch/validation.rs;
  launchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "QEMU-2 launch-configuration rejection";
        needle = "before spawning any child";
      }
      {
        label = "QEMU-43 RR validation";
        needle = "Round-robin single-thread launch validation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "pre-spawn validator export";
        needle = "validate_pre_spawn_qemu_launch_args";
      }
      {
        label = "pre-spawn validation error export";
        needle = "QemuPreSpawnLaunchValidationError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" launchLib [
      {
        label = "default RR switch quantum";
        needle = "const DEFAULT_RR_SWITCH_QUANTUM: u64 = 4096;";
      }
      {
        label = "candidate records RR switch quantum";
        needle = "pub rr_switch_quantum: u64";
      }
      {
        label = "default pins RR switch quantum";
        needle = "rr_switch_quantum: DEFAULT_RR_SWITCH_QUANTUM,";
      }
      {
        label = "canonical QEMU args include RR switch quantum";
        needle = "\"shift={},sleep=off,align=off,rr_switch_quantum={}\",";
      }
      {
        label = "hash material includes RR switch quantum";
        needle = "format!(\"rr_switch_quantum={}\", self.rr_switch_quantum),";
      }
      {
        label = "hash material records RR units";
        needle = "\"rr_switch_quantum_units=node-icount\".to_owned(),";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/validation.rs" launchValidation [
      {
        label = "pre-spawn validator";
        needle = "pub fn validate_pre_spawn_qemu_launch_args";
      }
      {
        label = "validated summary type";
        needle = "pub struct QemuPreSpawnLaunchValidation";
      }
      {
        label = "pre-spawn error type";
        needle = "pub enum QemuPreSpawnLaunchValidationError";
      }
      {
        label = "missing option rejection";
        needle = "MissingOption";
      }
      {
        label = "KVM rejection";
        needle = "KvmOrHardwareAcceleration";
      }
      {
        label = "non-sim accelerator rejection";
        needle = "NonSimAccelerator";
      }
      {
        label = "MTTCG rejection";
        needle = "MultiThreadTcg";
      }
      {
        label = "single-thread pin required";
        needle = "SingleThreadSimNotPinned";
      }
      {
        label = "missing icount rejection";
        needle = "unique_option_value(args, \"-icount\")?";
      }
      {
        label = "shift auto rejection";
        needle = "IcountShiftAuto";
      }
      {
        label = "RR quantum unpinned rejection";
        needle = "RrSwitchQuantumUnpinned";
      }
      {
        label = "CPU host rejection";
        needle = "CpuModelUsesHost";
      }
      {
        label = "CPU entropy feature rejection";
        needle = "CpuEntropyFeatureEnabled";
      }
      {
        label = "machine accelerator rejection";
        needle = "MachineUsesNonSimAcceleration";
      }
      {
        label = "host timing or entropy rejection";
        needle = "HostTimingOrEntropyArgument";
      }
      {
        label = "inline option-value host-source scan";
        needle = "option.split_once('=')";
      }
      {
        label = "user networking rejection";
        needle = "host-timing user networking";
      }
      {
        label = "host RNG rejection";
        needle = "rng-random";
      }
      {
        label = "host RTC utc base rejection";
        needle = "Some(\"utc\") | None";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "canonical validator accept test";
        needle = "pre_spawn_launch_validation_accepts_canonical_arguments";
      }
      {
        label = "KVM and non-sim rejection test";
        needle = "pre_spawn_launch_validation_rejects_kvm_and_non_sim_accelerators";
      }
      {
        label = "stock TCG runtime rejection assertion";
        needle = "QemuPreSpawnLaunchValidationError::NonSimAccelerator";
      }
      {
        label = "icount and MTTCG rejection test";
        needle = "pre_spawn_launch_validation_rejects_bad_icount_and_mttcg";
      }
      {
        label = "host timing entropy rejection test";
        needle = "pre_spawn_launch_validation_rejects_host_cpu_timing_and_entropy";
      }
      {
        label = "missing RTC base rejection assertion";
        needle = "\"-rtc clock=vm\"";
      }
      {
        label = "UTC RTC base rejection assertion";
        needle = "\"base=utc,clock=vm\"";
      }
      {
        label = "inline user networking rejection assertion";
        needle = "\"-netdev=user,id=net1\"";
      }
      {
        label = "inline host RNG rejection assertion";
        needle = "\"-object=rng-random,id=hostrng,filename=/tmp/seed\"";
      }
      {
        label = "canonical RR quantum assertion";
        needle = "validation.rr_switch_quantum(), 4096";
      }
      {
        label = "unpatched RR quantum rejection assertion";
        needle = "RrSwitchQuantumUnpinned";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes QEMU launch validation check";
        needle = "qemuLaunchValidation = import ./phase2-qemu-launch-validation.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu launch-validation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-launch-validation";
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
          name = "run-qemu-launch-validation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-launch-validation-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test deterministic_launch \
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
            check_scope=task-level
            related_gates=gate:layer0-determinism,gate:single-vm-fingerprint
            rust_test=crucible-qemu::deterministic_launch
            rejected=kvm,non-tcg,missing-icount,shift-auto,mttcg,unpinned-rr-quantum,cpu-host,host-timing,host-entropy
            rr_switch_quantum=4096
            rr_switch_quantum_units=node-icount
            pre_spawn_validation=true
            RESULT
          '';
        }
      ];
    }
