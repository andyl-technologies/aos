{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuInjectionContract",
  taskIds ? ["T-QEMU-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  qemuLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/lib.rs;
  };
  qemuNode = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/node.rs;
  };
  quantumLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/quantum.rs;
  };
  # Production-only slice for the no-unwrap/no-expect forbids (test code is
  # allowed panic shortcuts, matching the workspace clippy allow policy).
  # splitString uses a regex separator, so route through a regex-safe sentinel.
  quantumProd = builtins.head (
    lib.splitString "@@CFGTEST@@" (
      builtins.replaceStrings ["\n#[cfg(test)]"] ["@@CFGTEST@@"] quantumLib
    )
  );
  pluginInbound = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/inbound.rs;
  };
  pluginDeviceIo = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/device_io.rs;
  };
  pluginIdleLoop = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  };
  pluginNetworkRx = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/network_rx.rs;
  };
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "completion note names injection contract";
        needle = "QEMU-level injection-contract enforcement";
      }
      {
        label = "completion note names device I/O freeze";
        needle = "freeze observations";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "device I/O freeze report exported";
        needle = "QemuDeviceIoFreezeReport";
      }
      {
        label = "device I/O freeze observation exported";
        needle = "QemuDeviceIoFreezeObservation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "emitted frame carries emit icount";
        needle = "pub emit_icount: Icount";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/quantum.rs" quantumLib [
      {
        label = "delivery key helper";
        needle = "pub fn delivery_key(&self) -> FrameDeliveryKey";
      }
      {
        label = "exact delivery ceiling helper";
        needle = "fn authorize_qemu_delivery_ceiling";
      }
      {
        label = "exact delivery ceiling allowed";
        needle = "earliest_possible_delivery_icount == Some(max_advance_icount)";
      }
      {
        label = "passed-delivery floor tracked";
        needle = "passed_delivery_floor";
      }
      {
        label = "preview before commit";
        needle = "fn preview_due_inbound_since";
      }
      {
        label = "late frame error";
        needle = "DeliveryAlreadyPassed";
      }
      {
        label = "commit mismatch error";
        needle = "DequeuedUnexpectedDelivery";
      }
      {
        label = "deterministic due-frame order";
        needle = "sort_by_key(QemuDueInboundFrame::delivery_key)";
      }
      {
        label = "device I/O freeze report type";
        needle = "pub struct QemuDeviceIoFreezeReport";
      }
      {
        label = "device I/O slot observation";
        needle = "device_io_freeze_from_snapshot";
      }
      {
        label = "quantum report carries device I/O freeze";
        needle = "pub device_io_freeze: QemuDeviceIoFreezeReport";
      }
      {
        label = "emitted frame preserves emit icount";
        needle = "emit_icount: Icount";
      }
      {
        label = "router inbound sequence counter";
        needle = "next_router_inbound_sequence";
      }
      {
        label = "router inbound sequence overflow";
        needle = "InboundSequenceOverflow";
      }
      {
        label = "exact delivery test";
        needle = "qemu_quantum_accepts_exact_delivery_horizon_in_total_order";
      }
      {
        label = "deliver-frame sequence test";
        needle = "qemu_quantum_deliver_frame_assigns_router_sequences";
      }
      {
        label = "deliver-frame sequence overflow test";
        needle = "qemu_quantum_deliver_frame_fails_loud_on_sequence_overflow";
      }
      {
        label = "overshoot rejection test";
        needle = "qemu_quantum_rejects_horizon_that_would_pass_possible_frame_delivery";
      }
      {
        label = "late no-consume test";
        needle = "qemu_quantum_rejects_late_inbound_frame_without_consuming";
      }
      {
        label = "mid-quantum late no-consume test";
        needle = "qemu_quantum_rejects_mid_quantum_late_frame_without_consuming";
      }
      {
        label = "device I/O freeze report test";
        needle = "qemu_quantum_reports_device_io_freeze_across_burst_release";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inbound.rs" pluginInbound [
      {
        label = "plugin deterministic inbound order";
        needle = "sort_by_key(FrameEntry::delivery_key)";
      }
      {
        label = "plugin late frame failure";
        needle = "DeliveryAlreadyPassed";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "QEMU RX injection callback";
        needle = "handle_network_rx_idle_callback";
      }
      {
        label = "lossless RX flush";
        needle = "flush_lossless_rx";
      }
      {
        label = "delivery gate validation";
        needle = "validate_delivery_gate";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/device_io.rs" pluginDeviceIo [
      {
        label = "device I/O freeze state";
        needle = "PluginDeviceIoFreeze";
      }
      {
        label = "device I/O active publish";
        needle = "PluginShmemOrdering::publish_device_io_active";
      }
      {
        label = "device I/O active clear";
        needle = "PluginShmemOrdering::clear_device_io_active";
      }
      {
        label = "device I/O release wake";
        needle = "wake_for_device_io_release";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "device I/O suppresses timer deadline";
        needle = "idle_loop_device_io_freeze_suppresses_timer_deadline_until_scheduler_wake";
      }
      {
        label = "pending counter covers stale flag";
        needle = "idle_loop_device_io_freeze_uses_pending_counter_when_flag_is_stale";
      }
      {
        label = "idle loop computes device I/O freeze wake";
        needle = "IdleWakeCause::DeviceIoFreeze";
      }
      {
        label = "RX injection waits for QEMU completion";
        needle = "idle_loop_rx_injection_waits_for_qemu_completion";
      }
      {
        label = "RX failure does not commit inbound frames";
        needle = "idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/quantum.rs" quantumProd [
      {
        label = "production unwrap";
        needle = ".unwrap()";
      }
      {
        label = "production expect";
        needle = ".expect(";
      }
      {
        label = "hard-coded host shell";
        needle = "/bin/sh";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu injection contract check";
        needle = "qemuInjectionContract = import ./phase2-qemu-injection-contract.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu injection-contract check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-injection-contract";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      cargoDeps = cargoDeps;

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
          name = "run-qemu-injection-contract";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-injection-contract-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              quantum::tests \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-injection-contract-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              inbound::tests \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-injection-contract-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              network_rx::tests \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-injection-contract-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              device_io::tests \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-injection-contract-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              idle_loop::tests \
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
            attr_path=${attrPath}
            tasks=${taskList}
            qemu_37=exact-delivery-total-order-and-late-fail-loud
            qemu_38=device-io-freeze-observed-through-node-slot
            exact_delivery=authorized-at-delivery-icount
            overshoot=past-delivery-rejected
            emitted_frame=emit-icount-preserved
            plugin_rx=lossless-queue-and-flush
            plugin_device_io=device_io_active-submit-clear-release-wake
            plugin_idle_loop=device_io_freeze-and-rx-injection
            rust_tests=crucible-qemu::quantum::tests,crucible-qemu-plugin::inbound/network_rx/device_io/idle_loop::tests
            RESULT
          '';
        }
      ];

      meta = {
        description = "Crucible Phase 2 QEMU injection-contract and device-I/O freeze gate";
      };
    }
