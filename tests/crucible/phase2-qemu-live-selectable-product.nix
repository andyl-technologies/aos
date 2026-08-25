{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveSelectableProduct",
  taskIds ? ["T-CAM-2.8"],
  openTaskIds ? [],
  completionCeiling ? "8000000000",
  timeoutSecs ? "1500",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  networkInitramfs = import ./phase2-qemu-live-network-io-guest.nix {
    inherit pkgs;
    selectable = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-selectable-product";
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
    GUEST_INITRD = "${networkInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    CRUCIBLE_SELECTABLE_PRODUCT_CEILING = completionCeiling;
    CRUCIBLE_SELECTABLE_PRODUCT_TIMEOUT_SECS = timeoutSecs;
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
        name = "run-live-selectable-product";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"
          grep -Fxq 'selectable_product=true' ${networkInitramfs}/evidence.env
          grep -Fxq 'selectable_guest_surface=crucible-guest-typed-cli' \
            ${networkInitramfs}/evidence.env

          cargo build \
            --frozen \
            --offline \
            --release \
            --target-dir "$TMPDIR/live-selectable-product-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-selectable-product

          run_dir="$TMPDIR/live-selectable-product-run"
          report="$TMPDIR/live-selectable-product.result"
          mkdir -p "$run_dir"
          timeout -k 15 3090 \
            "$TMPDIR/live-selectable-product-target/release/examples/crucible-qemu-live-selectable-product" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$GUEST_INITRD" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:typed-choice-product-checkpoint' "$report"
          grep -Fxq 'guest=real-network-product-initramfs' "$report"
          grep -Fxq 'first_selectable=network.recovery-policy' "$report"
          grep -Fxq 'second_selectable=network.retry-quanta' "$report"
          grep -Eq '^capture_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'restored_pending_exact=true' "$report"
          grep -Fxq 'durable_envelope_round_trip=true' "$report"
          grep -Fxq 'completed_requests=2' "$report"
          grep -Fxq 'selected_value=discrete-fast,integer-7' "$report"
          grep -Fxq 'selected_frame=crucible-selected-fast-q7' "$report"
          grep -Eq '^selected_frame_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'source_process_force_crashed=true' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=real-product-discrete-and-integral-choice-pending-exact-restore\n'
            printf 'proven=typed-guest-registration,catalog-freeze,pending-request-vmstate,canonical-plan-sidecar,fresh-qemu-restore,exact-reply,guest-selected-network-behavior\n'
          } >> "$out/result"
        '';
      }
    ];
  }
