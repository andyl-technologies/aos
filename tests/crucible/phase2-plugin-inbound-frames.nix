{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginInboundFrames",
  taskIds ? ["T-PLUG-8"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  pluginLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/lib.rs;
  };
  pluginInbound = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/inbound.rs;
  };
  pluginIdleLoop = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  };
  pluginIdleLoopInboundTests = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/idle_loop/tests/inbound_cases.rs;
  };
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemDeliveryErrors = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/src/shmem/delivery_errors.rs;
  };
  shmemFrameNode = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/src/shmem/frame_node.rs;
  };
  shmemRingCoverage = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/src/shmem/ring_coverage.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

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
      label = "crates/crucible-qemu-plugin/src/inbound.rs";
      content = pluginInbound;
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
              "${source.label}: forbidden host-time, timeout, or entropy API in inbound frame path: `${api}`"
            ]
        )
        forbiddenHotPathApis
    )
    hotPathSources;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "inbound frame polling wording";
        needle = "Implement inbound-frame polling/injection";
      }
      {
        label = "already-passed failure wording";
        needle = "fail loudly on an already-passed";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "inbound module exported";
        needle = "pub mod inbound;";
      }
      {
        label = "inbound ring type exported";
        needle = "InboundFrameRing";
      }
      {
        label = "inbound batch type exported";
        needle = "InboundFrameBatch";
      }
      {
        label = "inbound helper exported";
        needle = "PluginInboundFrames";
      }
      {
        label = "inbound error exported";
        needle = "InboundFrameError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inbound.rs" pluginInbound [
      {
        label = "ring view type";
        needle = "pub struct InboundFrameRing";
      }
      {
        label = "non-consuming peek helper";
        needle = "pub fn peek_next_delivery_icount";
      }
      {
        label = "uses SPSC peek";
        needle = "PluginShmemOrdering::peek_inbound_delivery_icount";
      }
      {
        label = "due-frame drain helper";
        needle = "pub fn drain_deliverable";
      }
      {
        label = "uses SPSC dequeue";
        needle = "PluginShmemOrdering::dequeue_inbound_frame";
      }
      {
        label = "strict late-head check";
        needle = "delivery_icount < consumer_current_icount";
      }
      {
        label = "current-or-passed-icount delivery check";
        needle = "delivery_icount <= consumer_current_icount";
      }
      {
        label = "idle-window delivery drain";
        needle = "pub fn drain_deliverable_since";
      }
      {
        label = "idle-window preview";
        needle = "pub fn preview_deliverable_since";
      }
      {
        label = "jumped-over delivery test";
        needle = "inbound_frame_drain_since_includes_jumped_over_delivery_window";
      }
      {
        label = "deterministic total order";
        needle = "sort_by_key(FrameEntry::delivery_key)";
      }
      {
        label = "late delivery error";
        needle = "DeliveryAlreadyPassed";
      }
      {
        label = "late delivery carries full key";
        needle = "frame: FrameDeliveryKey";
      }
      {
        label = "ring operation error";
        needle = "RingOperation";
      }
      {
        label = "peek non-consuming test";
        needle = "inbound_frame_peek_uses_minimum_head_delivery_without_consuming";
      }
      {
        label = "total-order drain test";
        needle = "inbound_frame_drain_delivers_current_icount_in_total_order";
      }
      {
        label = "late-head no-consume test";
        needle = "inbound_frame_drain_rejects_late_head_without_consuming";
      }
      {
        label = "materialized late candidate test";
        needle = "inbound_frame_select_rejects_late_candidate_frame";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "begin idle peeks inbound rings";
        needle = "begin_idle_with_inbound_rings";
      }
      {
        label = "complete idle drains inbound rings";
        needle = "complete_after_scheduler_wake_from_inbound_rings";
      }
      {
        label = "pre-advance late-head rejection";
        needle = "reject_already_passed_ring_heads";
      }
      {
        label = "ring drain after wake";
        needle = "PluginInboundFrames::drain_deliverable_since";
      }
      {
        label = "idle inbound error path";
        needle = "IdleHotLoopError::InboundFrames";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop/tests/inbound_cases.rs" pluginIdleLoopInboundTests [
      {
        label = "ring-backed idle test";
        needle = "idle_loop_with_inbound_rings_does_not_consume_before_qemu_completion";
      }
      {
        label = "late ring before direct advance test";
        needle = "idle_loop_rejects_late_inbound_ring_before_direct_advance";
      }
      {
        label = "late ring at begin test";
        needle = "idle_loop_rejects_late_inbound_ring_at_begin_without_publishing";
      }
      {
        label = "late materialized frame before direct advance test";
        needle = "idle_loop_rejects_late_materialized_frame_before_direct_advance";
      }
      {
        label = "raw late inbound delivery before publish test";
        needle = "idle_loop_rejects_raw_late_inbound_delivery_before_publishing";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/ring_coverage.rs" shmemRingCoverage [
      {
        label = "SPSC head delivery peek";
        needle = "pub fn peek_delivery_icount";
      }
      {
        label = "SPSC frame dequeue";
        needle = "pub fn dequeue";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/delivery_errors.rs" shmemDeliveryErrors [
      {
        label = "frame delivery key";
        needle = "pub struct FrameDeliveryKey";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "frame delivery predicate";
        needle = "pub fn is_deliverable_at";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin inbound frames check";
        needle = "qemuPluginInboundFrames = import ./phase2-plugin-inbound-frames.nix";
      }
    ]
    ++ forbiddenHotPathFailures;
in
  if failures != []
  then throw "crucible phase2 plugin inbound-frames check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-inbound-frames";
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
          name = "run-plugin-inbound-frames";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              inbound_frame \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_with_inbound_rings_does_not_consume_before_qemu_completion \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_rejects_late_inbound_ring_before_direct_advance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_rejects_late_inbound_ring_at_begin_without_publishing \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_rejects_late_materialized_frame_before_direct_advance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_rejects_raw_late_inbound_delivery_before_publishing \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-inbound-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_release_advances_injects_due_frames_and_republishes_running \
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
            live_gate=checks.crucible.phase2.qemuLiveNetworkIo
            inbound_peek=non-consuming-min-head-delivery
            injection_order=delivery_icount,src_node,seq
            late_delivery=fails-before-direct-advance
            current_delivery=dequeue-and-inject
            future_delivery=left-queued
            hot_path_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
