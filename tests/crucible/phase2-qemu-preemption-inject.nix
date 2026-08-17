{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0030-crucible-preemption-inject.patch",
  attrPath ? "checks.crucible.phase2.qemuPreemptionInject",
  taskIds ? ["T-PATCH-24"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  # The prerequisite stack is the series PREFIX before patchName, not every
  # other patch: filtering only patchName out left the suffix (0031+) in the
  # list, so the positive-control replay tried to apply later patches before
  # their own prerequisite (this patch) and rejected on the shared
  # accel/tcg/tcg-accel-ops-rr.c region. Take patches up to patchName, in
  # series order, so `patch --fuzz=0` replays the exact prefix qemu.nix applies.
  previousPatchFiles =
    (builtins.foldl' (
        acc: patch:
          if acc.done || patch == patchName
          then acc // {done = true;}
          else acc // {list = acc.list ++ [patch];}
      ) {
        list = [];
        done = false;
      }
      series.patchFiles)
    .list;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  pluginPackage = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  microtestSource = builtins.readFile ./phase2-qemu-preemption-inject.c;
  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "PATCH-47 export";
        needle = "qemu_plugin_inject_preemption";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "QEMU package applies preemption inject patch";
        needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackage [
      {
        label = "plugin package probes preemption export";
        needle = "qemu_plugin_inject_preemption";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "public preemption export";
        needle = "int qemu_plugin_inject_preemption(uint64_t at_icount";
      }
      {
        label = "vCPU switch kind";
        needle = "QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH";
      }
      {
        label = "interrupt kind";
        needle = "QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT";
      }
      {
        label = "sim precise RR mode gate";
        needle = ''strcmp(current_accel_name(), "sim") == 0'';
      }
      {
        label = "precise icount gate";
        needle = "icount_enabled() == ICOUNT_PRECISE";
      }
      {
        label = "pinned RR quantum gate";
        needle = "icount_crucible_rr_switch_quantum() != 0";
      }
      {
        label = "scheduler ceiling read";
        needle = "crucible_sim_shmem_max_advance_icount()";
      }
      {
        label = "past and ceiling rejection";
        needle = "at_icount < deadline_icount";
      }
      {
        label = "current and ceiling rejection";
        needle = "at_icount < current_icount";
      }
      {
        label = "single pending command";
        needle = "crucible_sim_preemption_command.pending";
      }
      {
        label = "TCG budget clamp";
        needle = "crucible_sim_preemption_clamp_cpu_budget";
      }
      {
        label = "RR application hook";
        needle = "crucible_sim_preemption_apply_due";
      }
      {
        label = "commanded APIC interrupt";
        needle = "crucible_sim_det_ipi_deliver_commanded";
      }
      {
        label = "missed command fails loud";
        needle = "crucible preemption missed commanded icount";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-preemption-inject.c" microtestSource [
      {
        label = "switch cross-run assertion";
        needle = "vcpu_switch_cross_run_icount_match=true";
      }
      {
        label = "interrupt cross-run assertion";
        needle = "interrupt_cross_run_icount_match=true";
      }
      {
        label = "out-of-window assertion";
        needle = "out_of_window_rejected_distinctly=true";
      }
      {
        label = "before-deadline assertion";
        needle = "before_deadline_rejected_distinctly=true";
      }
      {
        label = "budget clamp assertion";
        needle = "preemption_budget_clamped_to_commanded_icount=true";
      }
      {
        label = "stock negative assertion";
        needle = "stock_negative_control=true";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes QEMU preemption injection task check";
        needle = "qemuPreemptionInject = import ./phase2-qemu-preemption-inject.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU preemption injection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-preemption-inject";
      version = "0";
      src = null;

      inherit microtestSource patchSource;
      passAsFile = ["microtestSource" "patchSource"];

      # qemuPackage / referenceQemu are consumed only via explicit paths
      # (`${qemuPackage.src}` for the patched-source positive build and
      # `-I${referenceQemu}/include` for the negative control), never buildDeps:
      # in buildDeps the patched qemu-plugin.h lands on C_INCLUDE_PATH and
      # satisfies the stock-negative compile even under `-I${referenceQemu}`,
      # silently defeating the "stock lacks qemu_plugin_inject_preemption"
      # control. Interpolation keeps both pinned as inputs.
      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
        pkgs.pkg-config
        pkgs.tar
        pkgs.xz
        pkgs.glib
      ];

      phases = [
        {
          name = "run-qemu-preemption-inject-microtest";
          script = ''
            set -eu

            test -f ${referenceQemu}/include/qemu/qemu-plugin.h
            if grep -q 'qemu_plugin_inject_preemption' \
              ${referenceQemu}/include/qemu/qemu-plugin.h
            then
              echo "reference QEMU header unexpectedly declares qemu_plugin_inject_preemption" >&2
              exit 1
            fi

            cat > stock-preemption-negative.c <<'STOCK_NEGATIVE'
            #include <stdint.h>
            #include <qemu/qemu-plugin.h>

            int main(void)
            {
                return qemu_plugin_inject_preemption(
                    1, 1, 2, QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH, 0, 1, 0);
            }
            STOCK_NEGATIVE
            if env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u CPATH \
              cc -std=c11 -Wall -Werror -Werror=implicit-function-declaration \
              -I${referenceQemu}/include $(pkg-config --cflags glib-2.0) \
              -c stock-preemption-negative.c \
              -o stock-preemption-negative.o \
              2> stock-preemption-negative.err
            then
              echo "stock preemption API unexpectedly compiled" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_inject_preemption' stock-preemption-negative.err

            apply_dir="$TMPDIR/qemu-preemption-inject-apply"
            mkdir -p "$apply_dir"
            tar -xf ${qemuPackage.src} -C "$apply_dir"
            cd "$apply_dir/qemu-${qemuPackage.version}"
            for patch in ${builtins.concatStringsSep " " previousPatchFiles}; do
              patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch"
            done
            patch --batch --forward --fuzz=0 -p1 -i "$patchSourcePath"

            cat > patched-preemption-positive.c <<'PATCHED_POSITIVE'
            #include <stdint.h>
            #include <qemu/qemu-plugin.h>

            int main(void)
            {
                int (*inject)(uint64_t, uint64_t, uint64_t, unsigned int,
                              uint32_t, uint32_t, uint32_t) =
                    qemu_plugin_inject_preemption;
                return inject == 0 ||
                    QEMU_PLUGIN_PREEMPTION_KIND_VCPU_SWITCH != 1 ||
                    QEMU_PLUGIN_PREEMPTION_KIND_INTERRUPT_AT != 2;
            }
            PATCHED_POSITIVE
            cc -std=c11 -Wall -Werror \
              -Iinclude $(pkg-config --cflags glib-2.0) \
              -c patched-preemption-positive.c \
              -o patched-preemption-positive.o

            cp "$microtestSourcePath" phase2-qemu-preemption-inject.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              phase2-qemu-preemption-inject.c \
              -o phase2-qemu-preemption-inject

            mkdir -p "$out"
            ./phase2-qemu-preemption-inject > "$out/result"
            cat >> "$out/result" <<RESULT
            check=${attrPath}
            tasks=${taskList}
            gate=gate:patch-microtests
            gate=gate:layer1-injection
            gate=gate:layer0-determinism
            gate=gate:qemu-inert
            patch=${patchName}
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            patch_stack_prerequisites_applied=${builtins.concatStringsSep "," previousPatchFiles}
            real_qemu_patch_apply_clean=true
            patched_header_positive_control=true
            stock_negative_control_symbols_absent=true
            RESULT

            grep -q '^PASS$' "$out/result"
            grep -q '^formal_preemption_export=qemu_plugin_inject_preemption$' "$out/result"
            grep -q '^vcpu_switch_cross_run_icount_match=true$' "$out/result"
            grep -q '^interrupt_cross_run_icount_match=true$' "$out/result"
            grep -q '^out_of_window_rejected_distinctly=true$' "$out/result"
            grep -q '^before_deadline_rejected_distinctly=true$' "$out/result"
            grep -q '^past_icount_rejected_distinctly=true$' "$out/result"
            grep -q '^invalid_window_rejected_distinctly=true$' "$out/result"
            grep -q '^duplicate_pending_rejected_distinctly=true$' "$out/result"
            grep -q '^invalid_kind_rejected_distinctly=true$' "$out/result"
            grep -q '^preemption_budget_clamped_to_commanded_icount=true$' "$out/result"
            grep -q '^preemption_no_clamp_no_defer_on_invalid_window=true$' "$out/result"
            grep -q '^commanded_interrupt_delivered_as_apic_fixed_vector=true$' "$out/result"
            grep -q '^patched_fixture_exercised=true$' "$out/result"
            grep -q '^stock_negative_control=true$' "$out/result"
            grep -q '^real_qemu_patch_apply_clean=true$' "$out/result"
            grep -q '^patched_header_positive_control=true$' "$out/result"
            grep -q '^stock_negative_control_symbols_absent=true$' "$out/result"
          '';
        }
      ];
    }
