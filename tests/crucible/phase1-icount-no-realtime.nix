{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0003-crucible-icount-no-realtime.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-icount-no-realtime.c;
  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failuresFor = label: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${label}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  qemuNixRequirements = [
    {
      label = "icount no-realtime patch wiring";
      needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
    }
  ];

  patchRequirements = [
    {
      label = "icount budget function";
      needle = "static int64_t icount_get_limit(void)";
    }
    {
      label = "precise icount gate";
      needle = "icount_enabled() != ICOUNT_PRECISE";
    }
    {
      label = "sim accelerator gate";
      needle = ''strcmp(current_accel_name(), "sim") != 0'';
    }
    {
      label = "realtime deadline remains in non-precise modes";
      needle = "qemu_clock_deadline_ns_all(QEMU_CLOCK_REALTIME,";
    }
    {
      label = "host-speed independence rationale";
      needle = "host speed/load changes";
    }
  ];

  microtestRequirements = [
    {
      label = "precise mode model";
      needle = "ICOUNT_PRECISE";
    }
    {
      label = "adaptive mode model";
      needle = "ICOUNT_ADAPTATIVE";
    }
    {
      label = "patched icount_get_limit fixture include";
      needle = "#include \"accel/tcg/tcg-accel-ops-icount.c\"";
    }
    {
      label = "sim predicate model";
      needle = "current_accel_name(void)";
    }
    {
      label = "precise realtime clock read assertion";
      needle = "precise_realtime_reads_fast=0";
    }
    {
      label = "patched fixture assertion";
      needle = "patched_icount_get_limit_fixture=true";
    }
    {
      label = "virtual clock read assertion";
      needle = "precise_fast_virtual_reads != 1";
    }
    {
      label = "precise realtime independence assertion";
      needle = "precise_realtime_independent=true";
    }
    {
      label = "synthetic host speed perturbation evidence";
      needle = "synthetic_fast_slow_realtime_deadlines=true";
    }
    {
      label = "sim precise TB-exit budget equality";
      needle = "sim_precise_tb_exit_budget_identical=true";
    }
    {
      label = "non-sim precise realtime assertion";
      needle = "non_sim_precise_realtime_consulted=true";
    }
    {
      label = "adaptive realtime assertion";
      needle = "adaptive_realtime_consulted=true";
    }
    {
      label = "stock negative control";
      needle = "stock_negative_control_realtime_dependent=true";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-icount-no-realtime.c" microtestSource microtestRequirements;
in
  if failures != []
  then throw "crucible phase1 icount no-realtime check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-icount-no-realtime";
      version = "0";
      src = null;

      inherit microtestSource patchSource;
      passAsFile = ["microtestSource" "patchSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
      ];

      phases = [
        {
          name = "run-icount-no-realtime-microtest";
          script = ''
            set -eu

            mkdir -p accel/tcg hw/core qemu system
            : > accel/tcg/tcg-accel-ops.h
            : > accel/tcg/tcg-accel-ops-icount.h
            : > accel/tcg/tcg-accel-ops-rr.h
            : > hw/core/cpu.h
            : > qemu/accel.h
            : > qemu/guest-random.h
            : > qemu/main-loop.h
            : > qemu/osdep.h
            : > system/cpu-timers.h
            : > system/replay.h

            cat > accel/tcg/tcg-accel-ops-icount.c <<'QEMU_FIXTURE'
            #include "qemu/osdep.h"
            #include "system/replay.h"
            #include "system/cpu-timers.h"
            #include "qemu/main-loop.h"
            #include "qemu/guest-random.h"
            #include "hw/core/cpu.h"

            #include "tcg-accel-ops.h"
            #include "tcg-accel-ops-icount.h"
            #include "tcg-accel-ops-rr.h"

            static int64_t icount_get_limit(void)
            {
                int64_t deadline;

                if (replay_mode != REPLAY_MODE_PLAY) {
                    /*
                     * Include all the timers, because they may need an attention.
                     * Too long CPU execution may create unnecessary delay in UI.
                     */
                    deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                                          QEMU_TIMER_ATTR_ALL);
                    /* Check realtime timers, because they help with input processing */
                    deadline = qemu_soonest_timeout(deadline,
                            qemu_clock_deadline_ns_all(QEMU_CLOCK_REALTIME,
                                                       QEMU_TIMER_ATTR_ALL));

                    /*
                     * Maintain prior (possibly buggy) behaviour where if no deadline
                     * was set (as there is no QEMU_CLOCK_VIRTUAL timer) or it is more than
                     * INT32_MAX nanoseconds ahead, we still use INT32_MAX
                     * nanoseconds.
                     */
                    if ((deadline < 0) || (deadline > INT32_MAX)) {
                        deadline = INT32_MAX;
                    }

                    return icount_round(deadline);
                } else {
                    return replay_get_instructions();
                }
            }
            QEMU_FIXTURE

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp "$microtestSourcePath" phase1-icount-no-realtime.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -I . \
              phase1-icount-no-realtime.c \
              -o phase1-icount-no-realtime

            mkdir -p "$out"
            ./phase1-icount-no-realtime > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^patched_icount_get_limit_fixture=true$' "$out/result"
            grep -q '^precise_realtime_reads_fast=0$' "$out/result"
            grep -q '^precise_realtime_reads_slow=0$' "$out/result"
            grep -q '^synthetic_fast_slow_realtime_deadlines=true$' "$out/result"
            grep -q '^sim_precise_tb_exit_budget_identical=true$' "$out/result"
            grep -q '^precise_realtime_independent=true$' "$out/result"
            grep -q '^non_sim_precise_realtime_consulted=true$' "$out/result"
            grep -q '^adaptive_realtime_consulted=true$' "$out/result"
            grep -q '^stock_negative_control_realtime_dependent=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp accel/tcg/tcg-accel-ops-icount.c \
              "$out/tcg-accel-ops-icount.c.patched"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.icountNoRealtime
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-2
            patch=0003-crucible-icount-no-realtime.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            qemu_mode=ICOUNT_PRECISE
            sim_predicate=current_accel_name==sim
            synthetic_fast_slow_realtime_deadlines=true
            sim_precise_tb_exit_budget=identical
            non_sim_precise_realtime_budget=upstream
            realtime_deadline_in_precise_budget=false
            RESULT
          '';
        }
      ];
    }
