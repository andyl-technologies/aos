{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginBootBarrier",
  taskIds ? ["T-PLUG-18"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginBootBarrier = builtins.readFile ../../crates/crucible-qemu-plugin/src/boot_barrier.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  shmem =
    import ./_crucible-shmem-source.nix {inherit lib;}
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/futex.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenBootBarrierApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "std::time::Duration"
    "thread::sleep"
    "sleep("
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
  ];

  failures =
    forbiddenFor "crates/crucible-qemu-plugin/src/boot_barrier.rs" pluginBootBarrier
    (map (needle: {
        label = "host wall-clock or sleep fallback";
        inherit needle;
      })
      forbiddenBootBarrierApis)
    ++ failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-18 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginInstall`";
      }
      {
        label = "boot barrier wording";
        needle = "block on the boot barrier";
      }
      {
        label = "wake_signal futex wording";
        needle = "wake_signal` futex";
      }
      {
        label = "no wall-clock sleep wording";
        needle = "never a fixed wall-clock sleep";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
      {
        label = "initial ceiling starts at zero";
        needle = "max_advance_icount` MUST initialize to 0";
      }
      {
        label = "race-free futex idiom";
        needle = "read-counter / re-check / wait idiom";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmem [
      {
        label = "zero initial ceiling";
        needle = "max_advance_icount: AtomicU64::new(0)";
      }
      {
        label = "idle precondition publisher";
        needle = "pub fn publish_idle";
      }
      {
        label = "non-private futex wait";
        needle = "pub fn futex_wait_nonprivate";
      }
      {
        label = "ceiling acquire load";
        needle = "pub fn load_node_ceiling";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "boot barrier module";
        needle = "pub mod boot_barrier;";
      }
      {
        label = "boot barrier type exported";
        needle = "PluginBootBarrier";
      }
      {
        label = "boot barrier release exported";
        needle = "BootBarrierRelease";
      }
      {
        label = "ready setup ack token exported";
        needle = "PluginReadySetupAck";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/boot_barrier.rs" pluginBootBarrier [
      {
        label = "first guest icount constant";
        needle = "pub const BOOT_BARRIER_FIRST_GUEST_ICOUNT: u64 = 1;";
      }
      {
        label = "boot barrier wait token";
        needle = "pub struct BootBarrierWait";
      }
      {
        label = "boot barrier wait carries ready-ack proof";
        needle = "_setup_ack: PluginReadySetupAck";
      }
      {
        label = "boot barrier release token";
        needle = "pub struct BootBarrierRelease";
      }
      {
        label = "boot barrier core";
        needle = "pub struct PluginBootBarrier";
      }
      {
        label = "publish initial idle precondition";
        needle = "PluginShmemOrdering::publish_idle_wait";
      }
      {
        label = "barrier requires ready ack token";
        needle = "setup_ack: PluginReadySetupAck";
      }
      {
        label = "waits on non-private futex";
        needle = "PluginShmemOrdering::wait_on_wake_signal";
      }
      {
        label = "no-op shim cannot pass blocked barrier";
        needle = "FutexWaitOutcome::Noop";
      }
      {
        label = "blocked barrier error";
        needle = "InitialCeilingStillBlocked";
      }
      {
        label = "marks running after release";
        needle = "PluginShmemOrdering::mark_running_after_wake";
      }
      {
        label = "prepublished ceiling test";
        needle = "boot_barrier_skips_wait_if_scheduler_prepublished_initial_ceiling";
      }
      {
        label = "descriptor wait preparation test";
        needle = "boot_barrier_prepares_futex_wait_with_initial_ceiling_zero";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration wait method";
        needle = "pub fn wait_boot_barrier";
      }
      {
        label = "registration barrier consumes ready ack proof";
        needle = "setup_ack: PluginReadySetupAck";
      }
      {
        label = "wait step checked before side effects";
        needle = "ensure_next_step(PluginRegistrationStep::WaitBootBarrier)";
      }
      {
        label = "registration calls boot barrier";
        needle = "PluginBootBarrier::wait(setup_ack, slot, icount_shift)";
      }
      {
        label = "direct ready ack record forbidden";
        needle = "step == PluginRegistrationStep::SendSetupAck";
      }
      {
        label = "direct wait barrier record forbidden";
        needle = "step == PluginRegistrationStep::WaitBootBarrier";
      }
      {
        label = "boot barrier failure mapping";
        needle = "fail_boot_barrier";
      }
      {
        label = "helper-required test";
        needle = "registration_order_requires_boot_barrier_wait_helper";
      }
      {
        label = "ready ack helper-required test";
        needle = "registration_order_requires_ready_setup_ack_helper";
      }
      {
        label = "first instruction after barrier test";
        needle = "registration_order_waits_boot_barrier_before_first_instruction";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "boot barrier before first instruction in canonical order";
        needle = "PluginRegistrationStep::WaitBootBarrier,\n    PluginRegistrationStep::FirstVisibleInstruction";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin boot-barrier check";
        needle = "qemuPluginBootBarrier = import ./phase2-plugin-boot-barrier.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin boot-barrier check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-boot-barrier";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-plugin-boot-barrier";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-boot-barrier-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              boot_barrier \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-boot-barrier-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              registration_order_requires_ready_setup_ack_helper \
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
            open_tasks=${openTaskList}
            status=partial
            gates=gate:layer1-injection,gate:layer0-determinism
            rust_tests=crucible-qemu-plugin::boot_barrier
            rust_tests_extra=registration_order_requires_ready_setup_ack_helper
            boot_barrier=initial-ceiling-before-first-instruction
            wait_primitive=non-private-wake_signal-futex
            fallback=no-wall-clock-sleep
            registration=WaitBootBarrier-helper-required
            RESULT
          '';
        }
      ];
    }
