{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLive9pIo",
  # The FIRST gate that drives real guest 9p I/O toward SLOT_9P_IO. It documents
  # a currently-open gap: under the sim accelerator a guest's `mount -t 9p` does
  # NOT reach the crucible SLOT_9P_IO substrate, even though the guest boots and
  # the identical mount reaches QEMU's 9p device under TCG. Two legs pin the
  # signature so the gap is caught by CI, not chat:
  #   - reference (sim) leg: boots the guest with a crucible-shmem virtio-9p
  #     device + a mount initrd on the sim+plugin raw hot path, services
  #     SLOT_9P_IO, and observes frames_processed=0 while the guest boots
  #     (idle-jumps to the ceiling once its mount blocks); run twice, the
  #     icount-domain observations must match;
  #   - TCG control leg: boots the same guest + 9p device under TCG with no
  #     plugin and confirms the guest issues a real 9p op (QEMU's msize warning),
  #     proving the sim-leg zero is a forward gap, not a guest that never mounts.
  # When the C-side forward fix lands (SLOT_9P_IO starts receiving the op), the
  # sim leg's frames_processed becomes nonzero and this gate flips RED on
  # purpose, signalling that it must be upgraded to assert forwarding + post-0039
  # guest progress. No checklist task flips here.
  taskIds ? [],
  openTaskIds ? [],
  # A busy ceiling above the diskless idle onset (~15.8M): the guest boots to
  # userspace and runs its mount workload before it touches 9p, so the op lands
  # far later than a virtio-blk realize-time probe.
  busyCeiling ? "100000000",
  ninepTimeoutSecs ? "60",
  secondRunLoad ? "1",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  # A stock kernel with 9p built IN (CONFIG_NET_9P=y / CONFIG_9P_FS=y) on top of
  # the same config the other crucible live gates boot under the sim accelerator.
  # The 9p=y-only `linux-crucible` fixture kernel does not boot under sim (its
  # stripped, no-ACPI config is sim-incompatible), whereas pkgs.linux's config
  # boots reliably under sim, so 9p support is layered onto that instead. Built
  # in means the mount initrd stays tiny -- a large module-loading initrd
  # perturbs the guest's early-boot memory layout under sim.
  ninepKernel = pkgs.linuxWith ''
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_9P_FS=y
    CONFIG_9P_FS_POSIX_ACL=y
    CONFIG_NETFS_SUPPORT=y
  '';

  ninepInitramfs = import ./phase2-qemu-live-9p-io-guest.nix {inherit pkgs;};

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-9p-io";
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

    GUEST_KERNEL = builtins.toString ninepKernel;
    GUEST_INITRD = "${ninepInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    CRUCIBLE_9P_IO_BUSY_CEILING = busyCeiling;
    CRUCIBLE_9P_IO_TIMEOUT_SECS = ninepTimeoutSecs;
    CRUCIBLE_9P_IO_SECOND_RUN_LOAD = secondRunLoad;
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
        name = "run-live-9p-io";
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
            --target-dir "$TMPDIR/live-9p-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-ninep-io

          run_dir="$TMPDIR/live-9p-io-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-9p-io.result"
          # Arg order: QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY INITRD. The
          # initrd is required -- a virtio-9p filesystem is untouched until the
          # guest mounts it.
          timeout -k 15 590 \
            "$TMPDIR/live-9p-io-target/debug/examples/crucible-qemu-live-ninep-io" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            "$GUEST_INITRD" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-9p-io' "$report"
          grep -Fxq 'diagnostic=9p-forward-gap-under-sim' "$report"
          grep -Fxq 'ninep_ring=SLOT_9P_IO' "$report"
          # The pinned signature of the forward gap:
          #   1. the sim leg processed ZERO 9p frames (the mount op does not
          #      reach SLOT_9P_IO under sim) -- the run PASSing already asserts
          #      frames_processed==0 in-process, this makes it visible;
          #   2. the same guest DOES issue a 9p op under TCG (control), so the
          #      zero is a forward gap, not a broken guest;
          #   3. the two sim runs' icount-domain observations matched.
          grep -Fxq 'sim_leg_forwarded=false' "$report"
          grep -Eq '^frames_processed=0$' "$report"
          grep -Fxq 'tcg_control_issued_9p=true' "$report"
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Fxq 'host_load_applied=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=diagnostic-9p-forward-gap-under-sim\n'
            printf 'proven=tcg-control-issues-9p-op,sim-leg-frames-processed-zero,run-twice-observation-determinism\n'
            printf 'documents=stock-virtio-9p-op-does-not-reach-SLOT_9P_IO-under-sim-accel\n'
          } >> "$out/result"
        '';
      }
    ];
  }
