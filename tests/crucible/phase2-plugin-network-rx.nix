{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginNetworkRx",
  taskIds ? ["T-PLUG-11"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginInbound = builtins.readFile ../../crates/crucible-qemu-plugin/src/inbound.rs;
  pluginNetworkRx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_rx.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginIdleLoopInboundTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop/tests/inbound_cases.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemDeliveryErrors = builtins.readFile ../../crates/crucible-shmem/src/shmem/delivery_errors.rs;
  shmemFrameNode = builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs;
  shmemRingCoverage = builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs;
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

  forbiddenCallbackApis = [
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
    "Mutex"
    "RwLock"
    ".lock()"
  ];

  hotPathSources = [
    {
      label = "crates/crucible-qemu-plugin/src/network_rx.rs";
      content = pluginNetworkRx;
    }
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = pluginIdleLoop;
    }
  ];

  forbiddenCallbackFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          api:
            lib.optionals (hasInfix api source.content) [
              "${source.label}: forbidden host-time, entropy, or lock API in network RX callback path: `${api}`"
            ]
        )
        forbiddenCallbackApis
    )
    hotPathSources;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-11 is closed by live QEMU callback integration";
        needle = "- [x] **T-PLUG-11**";
      }
      {
        label = "network RX wording";
        needle = "Implement RX injection via the lossless queueing path";
      }
      {
        label = "idle jump ordering wording";
        needle = "after the idle jump, gated by the delivery-icount rule";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "network RX module exported";
        needle = "pub mod network_rx;";
      }
      {
        label = "network RX state exported";
        needle = "PluginNetworkRx";
      }
      {
        label = "lossless RX queue trait exported";
        needle = "LosslessNetworkRxQueue";
      }
      {
        label = "network RX injection metadata exported";
        needle = "NetworkRxInjection";
      }
      {
        label = "network RX error exported";
        needle = "NetworkRxError";
      }
      {
        label = "network RX safe callback body exported";
        needle = "handle_network_rx_idle_callback";
      }
      {
        label = "QEMU RX queue exported";
        needle = "QemuLosslessNetworkRxQueue";
      }
      {
        label = "QEMU net-send symbol exported";
        needle = "QEMU_PLUGIN_NET_SEND_SYMBOL";
      }
      {
        label = "QEMU net-flush symbol exported";
        needle = "QEMU_PLUGIN_NET_FLUSH_SYMBOL";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "QEMU net-send symbol";
        needle = "QEMU_PLUGIN_NET_SEND_SYMBOL";
      }
      {
        label = "QEMU net-send spelling";
        needle = "\"qemu_plugin_net_send\"";
      }
      {
        label = "QEMU net-flush symbol";
        needle = "QEMU_PLUGIN_NET_FLUSH_SYMBOL";
      }
      {
        label = "QEMU net-flush spelling";
        needle = "\"qemu_plugin_net_flush\"";
      }
      {
        label = "QEMU net-can-receive diagnostic symbol";
        needle = "QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL";
      }
      {
        label = "QEMU net-send function pointer";
        needle = "pub type QemuPluginNetSendFn";
      }
      {
        label = "QEMU net-flush function pointer";
        needle = "pub type QemuPluginNetFlushFn";
      }
      {
        label = "network RX state";
        needle = "pub struct PluginNetworkRx";
      }
      {
        label = "QEMU lossless RX queue";
        needle = "pub struct QemuLosslessNetworkRxQueue";
      }
      {
        label = "QEMU required queue symbols";
        needle = "pub fn require(\n        net_send: Option<QemuPluginNetSendFn>,\n        net_flush: Option<QemuPluginNetFlushFn>,";
      }
      {
        label = "QEMU queue trait impl";
        needle = "impl LosslessNetworkRxQueue for QemuLosslessNetworkRxQueue";
      }
      {
        label = "QEMU net-send call";
        needle = "(self.net_send)(payload.as_ptr(), payload.len())";
      }
      {
        label = "QEMU net-flush call";
        needle = "(self.net_flush)()";
      }
      {
        label = "lossless queue trait";
        needle = "pub trait LosslessNetworkRxQueue";
      }
      {
        label = "lossless queue method";
        needle = "queue_lossless_rx";
      }
      {
        label = "lossless flush method";
        needle = "flush_lossless_rx";
      }
      {
        label = "safe idle callback body";
        needle = "pub fn handle_network_rx_idle_callback";
      }
      {
        label = "idle-context injection method";
        needle = "pub fn inject_due_frames_from_idle_context";
      }
      {
        label = "idle delivery floor parameter";
        needle = "passed_delivery_floor_icount";
      }
      {
        label = "deterministic queue order";
        needle = "ordered_frames.sort_by_key(|frame| frame.delivery_key())";
      }
      {
        label = "late delivery floor gate";
        needle = "frame.delivery_icount < passed_delivery_floor_icount";
      }
      {
        label = "future delivery gate";
        needle = "frame.delivery_icount > current_icount";
      }
      {
        label = "payload validation";
        needle = ".payload()";
      }
      {
        label = "lossless queue call";
        needle = ".queue_lossless_rx(payload)";
      }
      {
        label = "lossless flush call";
        needle = ".flush_lossless_rx()";
      }
      {
        label = "late delivery error";
        needle = "DeliveryAlreadyPassed";
      }
      {
        label = "future delivery error";
        needle = "DeliveryNotReached";
      }
      {
        label = "queue error";
        needle = "NetworkRxError::Queue";
      }
      {
        label = "flush error";
        needle = "NetworkRxError::Flush";
      }
      {
        label = "due queue/flush test";
        needle = "network_rx_idle_injection_queues_due_frames_then_flushes";
      }
      {
        label = "jumped-over delivery window test";
        needle = "network_rx_idle_injection_accepts_jumped_over_delivery_window";
      }
      {
        label = "not-ready lossless queue test";
        needle = "network_rx_lossless_queue_holds_not_ready_frame_until_flush";
      }
      {
        label = "future frame no queue test";
        needle = "network_rx_rejects_future_frame_before_queue_or_flush";
      }
      {
        label = "late frame no queue test";
        needle = "network_rx_rejects_late_frame_before_queue_or_flush";
      }
      {
        label = "invalid payload no queue test";
        needle = "network_rx_rejects_invalid_payload_before_queue_or_flush";
      }
      {
        label = "QEMU symbol requirement test";
        needle = "network_rx_requires_qemu_net_send_and_flush_symbols";
      }
      {
        label = "QEMU patch queue call test";
        needle = "network_rx_qemu_lossless_queue_calls_patch_send_and_flush";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inbound.rs" pluginInbound [
      {
        label = "non-consuming delivery preview";
        needle = "pub fn preview_deliverable_since";
      }
      {
        label = "windowed delivery drain";
        needle = "pub fn drain_deliverable_since";
      }
      {
        label = "delivery floor parameter";
        needle = "passed_delivery_floor_icount";
      }
      {
        label = "windowed deliverability";
        needle = "frame.delivery_icount <= consumer_current_icount";
      }
      {
        label = "commit mismatch error";
        needle = "CommittedBatchMismatch";
      }
      {
        label = "jump-window inbound test";
        needle = "inbound_frame_drain_since_includes_jumped_over_delivery_window";
      }
      {
        label = "floor-late no-consume test";
        needle = "inbound_frame_drain_since_rejects_before_floor_without_consuming";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "idle RX completion method";
        needle = "complete_after_scheduler_wake_from_inbound_rings_with_rx_injection";
      }
      {
        label = "direct advance before RX injection";
        needle = "let (advance, pending_advance) =\n            Self::advance_after_scheduler_wake";
      }
      {
        label = "previews inbound before RX queue";
        needle = "PluginInboundFrames::preview_deliverable_since";
      }
      {
        label = "RX callback after preview";
        needle = "handle_network_rx_idle_callback(";
      }
      {
        label = "idle floor passed to RX";
        needle = "request.plan.current_icount";
      }
      {
        label = "commits inbound after RX queue";
        needle = "PluginInboundFrames::drain_deliverable_since";
      }
      {
        label = "commit mismatch fail-loud";
        needle = "CommittedBatchMismatch";
      }
      {
        label = "RX injection result recorded";
        needle = "network_rx_injection: Option<NetworkRxInjection>";
      }
      {
        label = "idle RX error path";
        needle = "IdleHotLoopError::NetworkRxInjection";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop/tests/inbound_cases.rs" pluginIdleLoopInboundTests [
      {
        label = "idle RX ordering test";
        needle = "idle_loop_rx_injection_waits_for_qemu_completion";
      }
      {
        label = "idle RX queue failure no-commit test";
        needle = "idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads";
      }
      {
        label = "queue observes idle status before republish";
        needle = "slot_status_at_queue";
      }
      {
        label = "queue observes direct advance marker";
        needle = "direct_advance_ns_at_queue";
      }
      {
        label = "queue failure leaves ring unread";
        needle = "ring.read_index(), 0";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "frame payload accessor";
        needle = "pub fn payload(&self)";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/delivery_errors.rs" shmemDeliveryErrors [
      {
        label = "frame delivery key";
        needle = "pub struct FrameDeliveryKey";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/ring_coverage.rs" shmemRingCoverage [
      {
        label = "SPSC frame dequeue";
        needle = "pub fn dequeue";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin network RX check";
        needle = "qemuPluginNetworkRx = import ./phase2-plugin-network-rx.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin network-RX check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-network-rx";
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
          name = "run-plugin-network-rx";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-network-rx-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              network_rx \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-network-rx-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              inbound_frame_drain_since_includes_jumped_over_delivery_window \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-network-rx-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_rx_injection_waits_for_qemu_completion \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-network-rx-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads \
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
            rx_injection=idle-context-lossless-queue-and-flush
            qemu_rx_api=qemu_plugin_net_send,qemu_plugin_net_flush
            delivery_gate=floor-through-current-inclusive
            injection_order=delivery_icount,src_node,seq
            idle_order=direct-advance-preview-rx-queue-commit-before-running-publish
            queue_failure=does-not-commit-inbound-ring-read
            hot_path_host_time_lock_apis=forbidden
            RESULT
          '';
        }
      ];
    }
