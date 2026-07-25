{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginDeviceIoFreeze",
  taskIds ? [],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginDeviceIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/device_io.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginIdleLoopContract =
    pluginIdleLoop
    + builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop/tests/wake_cases.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemSources = builtins.concatStringsSep "\n" (map builtins.readFile [
    ../../crates/crucible-shmem/src/lib.rs
    ../../crates/crucible-shmem/src/shmem/frame_node.rs
    ../../crates/crucible-shmem/src/shmem/frame_node/futex.rs
  ]);
  shmemNodeSlotTests = builtins.readFile ../../crates/crucible-shmem/tests/multi_vcpu_node_slot.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

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

  forbiddenHotPathApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "thread::sleep"
    "park_timeout"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
  ];

  hotPathSources = [
    {
      label = "crates/crucible-qemu-plugin/src/device_io.rs";
      content = pluginDeviceIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = pluginIdleLoop;
    }
  ];

  forbiddenHotPathFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          api:
            lib.optionals (hasInfix api source.content) [
              "${source.label}: forbidden host-time, timeout, or entropy API in device-I/O freeze path: `${api}`"
            ]
        )
        forbiddenHotPathApis
    )
    hotPathSources;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-9 completed by live QEMU callback integration";
        needle = "- [x] **T-PLUG-9**";
      }
      {
        label = "T-PLUG-9 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLiveBlockIo` and";
      }
      {
        label = "device-I/O freeze wording";
        needle = "Implement virtual-time freeze across in-flight device I/O";
      }
      {
        label = "pending-counter wording";
        needle = "`device_io_active`/pending-counter";
      }
      {
        label = "burst-done wording";
        needle = "cleared on burst-done";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "device I/O module exported";
        needle = "pub mod device_io;";
      }
      {
        label = "device I/O freeze state exported";
        needle = "PluginDeviceIoFreeze";
      }
      {
        label = "device I/O token exported";
        needle = "DeviceIoRequestToken";
      }
      {
        label = "device I/O error exported";
        needle = "DeviceIoFreezeError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/device_io.rs" pluginDeviceIo [
      {
        label = "freeze state type";
        needle = "pub struct PluginDeviceIoFreeze";
      }
      {
        label = "freeze owner id";
        needle = "owner_id: u64";
      }
      {
        label = "pending counter";
        needle = "pending_requests: u32";
      }
      {
        label = "burst state";
        needle = "burst_active: bool";
      }
      {
        label = "non-Copy request token";
        needle = "pub struct DeviceIoRequestToken";
      }
      {
        label = "submit path";
        needle = "pub fn begin_submit";
      }
      {
        label = "active flag set on submit";
        needle = "PluginShmemOrdering::publish_device_io_active";
      }
      {
        label = "completion path";
        needle = "pub fn complete_request";
      }
      {
        label = "failure path";
        needle = "pub fn fail_request";
      }
      {
        label = "one-to-one underflow error";
        needle = "CompletionWithoutPendingRequest";
      }
      {
        label = "burst start path";
        needle = "pub fn begin_burst";
      }
      {
        label = "burst done path";
        needle = "pub fn burst_done";
      }
      {
        label = "burst pending rejection";
        needle = "BurstDoneWithPendingRequests";
      }
      {
        label = "active flag clear";
        needle = "PluginShmemOrdering::clear_device_io_active";
      }
      {
        label = "release wakes idle waiters";
        needle = "PluginShmemOrdering::wake_for_device_io_release";
      }
      {
        label = "foreign token rejection";
        needle = "CompletionForDifferentFreezeState";
      }
      {
        label = "submit active test";
        needle = "device_io_submit_sets_active_before_return_and_increments_pending";
      }
      {
        label = "completion clears test";
        needle = "device_io_completion_clears_single_request_hold";
      }
      {
        label = "failure releases test";
        needle = "device_io_failure_releases_the_same_pending_counter";
      }
      {
        label = "burst holds test";
        needle = "device_io_burst_holds_flag_until_burst_done";
      }
      {
        label = "burst pending rejection test";
        needle = "device_io_burst_done_rejects_pending_requests_and_keeps_flag_active";
      }
      {
        label = "wrong-state completion test";
        needle = "device_io_completion_without_matching_pending_request_is_fail_loud";
      }
      {
        label = "foreign token target-pending test";
        needle = "device_io_foreign_token_with_target_pending_is_fail_loud";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs and tests/wake_cases.rs" pluginIdleLoopContract [
      {
        label = "idle plan carries device I/O hold";
        needle = "device_io_holding_ticks";
      }
      {
        label = "idle wake cause for device I/O";
        needle = "IdleWakeCause::DeviceIoFreeze";
      }
      {
        label = "idle path reads shmem flag";
        needle = "PluginShmemOrdering::device_io_active(slot)";
      }
      {
        label = "idle path reads freeze counter";
        needle = "freeze.is_tick_hold_active(slot)";
      }
      {
        label = "timer deadline suppressed";
        needle = "effective_timer_deadline_icount";
      }
      {
        label = "device I/O idle test";
        needle = "idle_loop_device_io_freeze_suppresses_timer_deadline_until_scheduler_wake";
      }
      {
        label = "pending-only idle test";
        needle = "idle_loop_device_io_freeze_uses_pending_counter_when_flag_is_stale";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/{lib.rs,shmem/frame_node.rs}" shmemSources [
      {
        label = "mark device I/O active";
        needle = "pub fn mark_device_io_active";
      }
      {
        label = "clear device I/O active";
        needle = "pub fn clear_device_io_active";
      }
      {
        label = "load device I/O active";
        needle = "pub fn load_device_io_active";
      }
      {
        label = "device I/O active publication";
        needle = "fn publish_device_io_active";
      }
      {
        label = "device I/O release wake";
        needle = "pub fn wake_for_device_io_release";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/multi_vcpu_node_slot.rs" shmemNodeSlotTests [
      {
        label = "node slot device I/O publication test";
        needle = "node_slot_publishes_device_io_active_flag";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin device I/O freeze check";
        needle = "qemuPluginDeviceIoFreeze = import ./phase2-plugin-device-io-freeze.nix";
      }
    ]
    ++ forbiddenHotPathFailures;
in
  if failures != []
  then throw "crucible phase2 plugin device-I/O freeze check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-device-io-freeze";
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
          name = "run-plugin-device-io-freeze";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-device-io-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              device_io_ \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-device-io-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_device_io_freeze_suppresses_timer_deadline_until_scheduler_wake \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-device-io-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_device_io_freeze_uses_pending_counter_when_flag_is_stale \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-device-io-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              node_slot_publishes_device_io_active_flag \
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
            status=complete
            device_io_active=published-before-submit
            pending_counter=one-to-one-submit-completion
            failure_path=releases-pending-request
            burst_done=clears-after-last-completion
            release_wake=recomputes-idle-after-hold-release
            token_owner=foreign-completion-rejected
            idle_timer_deadlines=suppressed-while-device-io-active
            pending_counter_only=suppresses-timer-when-flag-stale
            hot_path_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
