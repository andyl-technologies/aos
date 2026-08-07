{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveNodeStep",
  # This is the FIRST gate that drives a real scheduler-facing QemuNode against a
  # live QEMU child (the M1 quantum/fingerprint gates drive the mapped shared
  # memory hot path directly and never construct a node). It stands the whole
  # node up — plugin IPC control, the mapped quantum hot path, the production
  # QemuLiveHostIoRuntime, and a typed QMP VMState channel — then advances it
  # through a busy-window ceiling schedule via QemuNode::advance_to_ceiling,
  # proving the node's split start/await/finish quantum path is byte-deterministic
  # live (T-IO-3 host-I/O runtime; contributes to T-PLUG-10..13 node-driven paths).
  taskIds ? [],
  openTaskIds ? [],
  # Busy-window schedule: every ceiling stays strictly below the diskless-firmware
  # idle onset (~15.8M icount) so the guest is always executing and each bounded
  # step stops exactly at its ceiling — dodging the open early-boot idle-warp
  # nondeterminism, which only occurs in idle windows.
  ceilingStep ? "3000000",
  stepCount ? "4",
  busyCap ? "15000000",
  stepTimeoutSecs ? "240",
  # Run the whole scenario twice, the second run under host CPU load, and require
  # byte-identical per-step accounting and execution fingerprint.
  secondRunLoad ? "1",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  idleInitramfs = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-node-step";
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

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${idleInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_NODE_STEP_CEILING_STEP = ceilingStep;
    CRUCIBLE_NODE_STEP_COUNT = stepCount;
    CRUCIBLE_NODE_STEP_BUSY_CAP = busyCap;
    CRUCIBLE_NODE_STEP_TIMEOUT_SECS = stepTimeoutSecs;
    CRUCIBLE_NODE_STEP_SECOND_RUN_LOAD = secondRunLoad;
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
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
        name = "run-live-node-step";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-node-step-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-node-step

          run_dir="$TMPDIR/live-node-step-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-node-step.result"
          # Arg order: QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD]. The
          # diskless firmware-pinned launch attaches no block device, so the Linux
          # guest never issues unserviced virtio-blk I/O during the busy window.
          timeout -k 15 590 \
            "$TMPDIR/live-node-step-target/debug/examples/crucible-qemu-live-node-step" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            "$GUEST_INITRD" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-node-step' "$report"
          grep -Fxq 'plugin_loaded=rust-control-cdylib' "$report"
          grep -Fxq 'node_kind=live-qemu-node' "$report"
          grep -Fxq 'host_io_runtime=qemu-live-host-io-runtime' "$report"
          grep -Fxq 'qmp_channel=vmstate-shutdown-only' "$report"
          # The runner drove every scheduled busy-window step through the live
          # QemuNode's public advance_to_ceiling path.
          grep -Eq '^quantum_count=[1-9][0-9]*$' "$report"
          # Raw-vs-logical accounting: every busy-window step's completion icount
          # equals its target ceiling (logical offset zero) and reached the horizon
          # rather than parking idle — no idle-jump offset leaked into a busy
          # boundary, and the node never stalled below a ceiling.
          grep -Eq '^quantum_step\[0\] target=[1-9][0-9]* completion=[1-9][0-9]* logical_offset=0 reissue_count=[0-9]+ reached_horizon=true$' "$report"
          ! grep -Eq 'logical_offset=[1-9]' "$report"
          ! grep -q 'reached_horizon=false' "$report"
          grep -Fxq 'busy_window_logical_offset_zero=true' "$report"
          # The node's shutdown escalation reaped the child cleanly.
          grep -Fxq 'orderly_child_exit=true' "$report"
          # The whole run repeated (second run under host CPU load) and produced a
          # byte-identical execution fingerprint and per-step accounting.
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Fxq 'host_load_applied=true' "$report"
          grep -Eq '^execution_fingerprint=[0-9a-f]+$' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=first-live-qemu-node-bounded-step-through-advance-to-ceiling\n'
            printf 'proven=live-node-bringup,busy-window-step-determinism,raw-vs-logical-offset-zero,run-twice-determinism,orderly-node-shutdown\n'
          } >> "$out/result"
        '';
      }
    ];
  }
