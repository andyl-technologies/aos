{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginNetworkRx",
  taskIds ? ["T-PLUG-11"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  pluginLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/lib.rs;
  };
  pluginInbound = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/inbound.rs;
  };
  pluginNetworkRx = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/network_rx.rs;
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
        label = "network RX wording";
        needle = "Implement RX injection via the canonical retry path";
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
        label = "canonical RX trait exported";
        needle = "CanonicalNetworkRx";
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
        label = "QEMU canonical RX backend exported";
        needle = "QemuCanonicalNetworkRx";
      }
      {
        label = "QEMU net-inject symbol exported";
        needle = "QEMU_PLUGIN_NET_INJECT_SYMBOL";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "QEMU net-inject symbol";
        needle = "QEMU_PLUGIN_NET_INJECT_SYMBOL";
      }
      {
        label = "QEMU net-inject spelling";
        needle = "\"qemu_plugin_net_inject\"";
      }
      {
        label = "QEMU net-inject function pointer";
        needle = "pub type QemuPluginNetInjectFn";
      }
      {
        label = "network RX state";
        needle = "pub struct PluginNetworkRx";
      }
      {
        label = "QEMU canonical RX backend";
        needle = "pub struct QemuCanonicalNetworkRx";
      }
      {
        label = "QEMU required injection symbol";
        needle = "pub fn require(net_inject: Option<QemuPluginNetInjectFn>)";
      }
      {
        label = "QEMU canonical RX trait impl";
        needle = "impl CanonicalNetworkRx for QemuCanonicalNetworkRx";
      }
      {
        label = "QEMU net-inject call";
        needle = "(self.net_inject)(payload.as_ptr(), payload.len())";
      }
      {
        label = "canonical RX trait";
        needle = "pub trait CanonicalNetworkRx";
      }
      {
        label = "canonical delivery method";
        needle = "try_deliver_rx";
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
        label = "canonical retention result";
        needle = "NetworkRxDeliveryOutcome::Retained";
      }
      {
        label = "bounded RX attempt limit";
        needle = "NETWORK_RX_DELIVERY_ATTEMPT_LIMIT";
      }
      {
        label = "deterministic RX retry interval";
        needle = "NETWORK_RX_RETRY_INTERVAL_ICOUNT";
      }
      {
        label = "canonical retained retry coordinate";
        needle = "retained_retry_icount";
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
        label = "direct delivery call";
        needle = ".try_deliver_rx(payload)";
      }
      {
        label = "future delivery error";
        needle = "DeliveryNotReached";
      }
      {
        label = "delivery error";
        needle = "NetworkRxError::Delivery";
      }
      {
        label = "ordered direct delivery test";
        needle = "network_rx_idle_injection_delivers_due_frames_in_order";
      }
      {
        label = "jumped-over delivery window test";
        needle = "network_rx_idle_injection_accepts_jumped_over_delivery_window";
      }
      {
        label = "backpressure canonical retention test";
        needle = "network_rx_retains_canonical_frame_under_guest_backpressure";
      }
      {
        label = "bounded attempt terminal test";
        needle = "network_rx_fails_loudly_at_canonical_delivery_attempt_limit";
      }
      {
        label = "deterministically spaced retained retry test";
        needle = "network_rx_retries_canonically_retained_past_frame";
      }
      {
        label = "future frame no delivery test";
        needle = "network_rx_rejects_future_frame_before_delivery";
      }
      {
        label = "retained past frame retry test";
        needle = "network_rx_retries_canonically_retained_past_frame";
      }
      {
        label = "invalid payload no delivery test";
        needle = "network_rx_rejects_invalid_payload_before_delivery";
      }
      {
        label = "QEMU symbol requirement test";
        needle = "network_rx_requires_qemu_direct_injection_symbol";
      }
      {
        label = "QEMU direct injection test";
        needle = "network_rx_qemu_direct_injection_transfers_delivered_frame";
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
        label = "retained head publishes retry deadline from last attempt";
        needle = ".last_delivery_attempt_icount()";
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
      {
        label = "retained head backlog and deadline regression test";
        needle = "inbound_retained_head_authorizes_blocked_fifo_backlog";
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
        label = "previews inbound before direct RX injection";
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
        label = "commits only delivered inbound prefix";
        needle = "PluginInboundFrames::commit_delivered_prefix";
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
        label = "idle RX delivery failure no-commit test";
        needle = "idle_loop_rx_delivery_failure_does_not_commit_inbound_ring_reads";
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
              idle_loop_rx_delivery_failure_does_not_commit_inbound_ring_reads \
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
            rx_injection=idle-context-direct-delivery-canonical-ring-retention
            qemu_rx_api=qemu_plugin_net_inject
            delivery_gate=floor-through-current-inclusive
            injection_order=delivery_icount,src_node,seq
            idle_order=direct-advance-preview-rx-deliver-accepted-prefix-before-running-publish
            delivery_failure=does-not-commit-inbound-ring-read
            hot_path_host_time_lock_apis=forbidden
            RESULT
          '';
        }
      ];
    }
