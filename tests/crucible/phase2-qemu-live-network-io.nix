{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveNetworkIo",
  taskIds ? ["T-PLUG-8" "T-PLUG-10" "T-PLUG-11"],
  openTaskIds ? [],
  busyCeiling ? "4000000000",
  networkTimeoutSecs ? "120",
  secondRunLoad ? "1",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
  networkInitramfs = import ./phase2-qemu-live-network-io-guest.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-network-io";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    # The standard AOS kernel carries CONFIG_PACKET=y and CONFIG_VIRTIO_NET=y;
    # the gate uses that shipped fixture instead of a gate-only kernel variant.
    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${networkInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    CRUCIBLE_NETWORK_IO_BUSY_CEILING = busyCeiling;
    CRUCIBLE_NETWORK_IO_TIMEOUT_SECS = networkTimeoutSecs;
    CRUCIBLE_NETWORK_IO_SECOND_RUN_LOAD = secondRunLoad;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
    ATTR_PATH = attrPath;

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
        name = "run-live-network-io";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"
          kernel_config=$(ls "$GUEST_KERNEL"/boot/config-* | head -1)
          test -n "$kernel_config"
          grep -Fxq 'CONFIG_PACKET=y' "$kernel_config"
          grep -Fxq 'CONFIG_VIRTIO_NET=y' "$kernel_config"
          grep -Fxq 'guest_traffic_origin=guest-only' \
            ${networkInitramfs}/evidence.env
          grep -Fxq 'guest_interface=virtio-net-eth0' \
            ${networkInitramfs}/evidence.env

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-network-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-network-io

          run_dir="$TMPDIR/live-network-io-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-network-io.result"
          timeout -k 15 590 \
            "$TMPDIR/live-network-io-target/debug/examples/crucible-qemu-live-network-io" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$GUEST_INITRD" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-network-io' "$report"
          grep -Fxq 'certification=guest-tx-router-reply-guest-rx-ack' "$report"
          grep -Fxq 'network_backend=hostless-qemu-hubport' "$report"
          grep -Fxq 'network_ring=SLOT_NET_ROUTER' "$report"
          grep -Fxq 'host_traffic_injector=false' "$report"
          grep -Eq '^probe_emit_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^reply_delivery_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'reply_latency_icount=100000000' "$report"
          grep -Eq '^ack_emit_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'acknowledgement_seen=true' "$report"
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Eq '^hostile_probe_emit_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^absolute_probe_origin_equal=(true|false)$' "$report"
          grep -Eq '^hostile_acknowledgement_offset_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^acknowledgement_offset_equal=(true|false)$' "$report"
          grep -Fxq 'determinism_scope=router-delivery-and-frame-order' "$report"
          grep -Fxq 'host_load_applied=true' "$report"
          grep -Fxq 'delayed_reply_applied=false' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=certifying-live-guest-network-plugin-ring-exchange\n'
            printf 'proven=guest-originated-tx,hostless-router-ring,exact-router-latency,lossless-qemu-rx,guest-ack,frame-order-host-load-invariance\n'
            printf 'kernel_packet_socket=built-in\n'
            printf 'kernel_virtio_net=built-in\n'
          } >> "$out/result"
        '';
      }
    ];
  }
