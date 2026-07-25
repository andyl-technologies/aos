# Drop-one attribution aggregate.
#
# For every carried patch N, `_drop-one.nix` attempts to remove N from the
# series (3-way `git rebase --onto`) and observes the result LIVE (nothing about
# the clean/conflict split or the build-fail/succeed split is hardcoded -- it is
# all an output of building this gate, so a future reordering/decoupling of the
# series automatically migrates patches between branches). Each patch resolves to
# exactly one attribution method:
#
#   drop-one-source-dependency : N cannot be removed without breaking a later
#                                patch's 3-way application (the tightly-coupled
#                                majority of this facade-first series).
#   drop-one-build-required    : N drops clean but full-minus-N fails to build
#                                because earlier code references N's symbols.
#   drop-one-symbol            : N drops clean, full-minus-N builds, and N's
#                                exported ABI symbols are present in the full
#                                binary and absent in the variant.
#   drop-one-semantic          : N drops clean, full-minus-N builds and exports
#                                no ABI symbol; a sim-mode runtime probe shows N's
#                                effect present in full and absent in the variant.
#   drop-one-composition       : Legacy fail-closed classification for a patch
#                                whose runtime effect was not reached. The
#                                aggregate rejects this result.
#
# This is layered on top of the source-provenance attribution gate; together they
# give every patch runtime-or-assembly load-bearing evidence, no bare needle.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests.dropOne",
  qemuPackage ? pkgs.qemu-crucible,
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = series.patchFiles;
  patchCount = builtins.length patchFiles;

  # Exported-ABI-symbol discriminators for the patches that expose plugin API
  # symbols (used only if the patch drops clean AND builds -- otherwise the live
  # outcome is source-dependency or build-required). Extracted from each patch's
  # QEMU_PLUGIN_API declarations. Patches with no entry expose no ABI symbol and
  # fall to the semantic discriminator when they drop clean and build.
  symbolDiscriminators = {
    "0006-crucible-clock-deadline.patch" = ["qemu_plugin_clock_deadline_ns"];
    "0009-crucible-net-deterministic.patch" = [
      "qemu_plugin_net_inject"
      "qemu_plugin_net_send"
      "qemu_plugin_net_flush"
      "qemu_plugin_net_can_receive"
    ];
    "0010-crucible-plugin-time-advance.patch" = [
      "qemu_plugin_has_time_control"
      "qemu_plugin_register_time_advance_cb"
      "qemu_plugin_advance_time_ns"
    ];
    "0011-crucible-plugin-icount-raw.patch" = ["qemu_plugin_icount_raw"];
    "0012-crucible-plugin-vcpu-exit.patch" = ["qemu_plugin_force_vcpu_exit"];
    "0013-crucible-plugin-wake-fd.patch" = [
      "qemu_plugin_register_wake_fd"
      "qemu_plugin_request_shutdown"
      "qemu_plugin_crucible_single_threaded_rr"
    ];
    "0014-crucible-plugin-tcg-exec-cb.patch" = ["qemu_plugin_register_tcg_exec_cb"];
    "0015-crucible-blk-shmem.patch" = ["qemu_plugin_register_blk_cb"];
    "0018-crucible-dev-cb-api.patch" = ["qemu_plugin_register_9p_cb"];
    "0020-crucible-net-tx-callback.patch" = ["qemu_plugin_register_net_tx_cb"];
    "0025-crucible-sim-idle-callbacks.patch" = ["qemu_plugin_register_vcpu_idle_resume_cb"];
    "0026-crucible-sim-shmem-dispatch.patch" = ["qemu_plugin_register_sim_shmem_dispatch_cb"];
    "0028-crucible-det-ipi.patch" = ["qemu_plugin_crucible_register_ipi_delivery_cb"];
    "0029-crucible-vcpu-introspect.patch" = [
      "qemu_plugin_read_vcpu_regs"
      "qemu_plugin_rr_cursor"
    ];
    "0030-crucible-preemption-inject.patch" = ["qemu_plugin_inject_preemption"];
    "0033-crucible-sim-observer.patch" = ["qemu_plugin_register_sim_shmem_observer_cb"];
    "0036-crucible-raw-state-export.patch" = [
      "qemu_plugin_crucible_guest_ram_region_copy"
      "qemu_plugin_crucible_guest_ram_regions"
      "qemu_plugin_crucible_request_terminal_pause"
      "qemu_plugin_crucible_vmstate_snapshot_begin"
      "qemu_plugin_crucible_vmstate_snapshot_copy"
      "qemu_plugin_crucible_vmstate_snapshot_free"
      "qemu_plugin_crucible_vmstate_snapshot_size"
    ];
    "0039-crucible-blk-device-completion-advance.patch" = [
      "qemu_plugin_register_blk_wait_cb"
    ];
    "0040-crucible-9p-sync-kick.patch" = [];
  };

  dropOnes =
    lib.imap (i: patch: let
      index = i + 1;
      symbols =
        if builtins.hasAttr patch symbolDiscriminators
        then symbolDiscriminators.${patch}
        else [];
      # 0007 (block-rtc-read) forces the sim RTC to the virtual clock; it is only
      # observable when the guest reads a host-backed RTC, so its variant probe
      # runs with -rtc clock=host.
      rtcClock =
        if patch == "0007-crucible-block-rtc-read.patch"
        then "host"
        else "vm";
    in {
      inherit index patch symbols;
      drv = import ./_drop-one.nix {
        inherit pkgs lib qemuPackage index rtcClock;
        expectAbsentSymbols = symbols;
        attrPath = "${attrPath}.p${toString index}";
      };
    })
    patchFiles;

  perPatchChecks =
    lib.concatMapStringsSep "\n" (entry: ''
      result="${entry.drv}/result"
      grep -q '^PASS$' "$result"
      grep -q "^dropped_patch=${entry.patch}$" "$result"
      cp "$result" "$out/per-patch/${entry.patch}.result"
      method=$(gawk -F= '/^attribution_method=/ { print $2 }' "$result")
      printf '%s\t%s\t%s\n' "${toString entry.index}" "${entry.patch}" "$method" \
        >> "$out/methods.tsv"
    '')
    dropOnes;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-patch-drop-one";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils pkgs.gawk pkgs.grep];
    PATCH_COUNT = toString patchCount;

    phases = [
      {
        name = "aggregate-drop-one-attribution";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out/per-patch"
          : > "$out/methods.tsv"

          ${perPatchChecks}

          # Every patch resolves to exactly one recognized attribution method.
          bad=$(gawk -F'\t' '
            $3 != "drop-one-source-dependency" &&
            $3 != "drop-one-build-required" &&
            $3 != "drop-one-symbol" &&
            $3 != "drop-one-semantic" &&
            $3 != "drop-one-composition" &&
            $3 != "structural-fallback" { print }
          ' "$out/methods.tsv")
          if [ -n "$bad" ]; then
            echo "patches without a recognized drop-one method:" >&2
            printf '%s\n' "$bad" >&2
            exit 1
          fi

          rows=$(wc -l < "$out/methods.tsv" | tr -d ' ')
          test "$rows" -eq "$PATCH_COUNT"

          count() { gawk -F'\t' -v m="$1" '$3==m{c++} END{print c+0}' "$out/methods.tsv"; }
          n_srcdep=$(count drop-one-source-dependency)
          n_build=$(count drop-one-build-required)
          n_symbol=$(count drop-one-symbol)
          n_semantic=$(count drop-one-semantic)
          n_composition=$(count drop-one-composition)
          n_fallback=$(count structural-fallback)
          test "$n_composition" -eq 0
          test "$n_fallback" -eq 0

          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          patch_count=${toString patchCount}
          every_patch_has_exactly_one_drop_one_method=true
          clean_conflict_split_recomputed_live=true
          drop_one_source_dependency_count=$n_srcdep
          drop_one_build_required_count=$n_build
          drop_one_symbol_count=$n_symbol
          drop_one_semantic_count=$n_semantic
          drop_one_composition_count=$n_composition
          structural_fallback_count=$n_fallback
          methods_manifest=methods.tsv
          RESULT
        '';
      }
    ];
  }
