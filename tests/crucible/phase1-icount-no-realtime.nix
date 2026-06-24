{
  pkgs,
  lib,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0002-crucible-icount-no-realtime.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-icount-no-realtime.c;

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
      needle = "patch -p1 < \${./qemu-patches/0002-crucible-icount-no-realtime.patch}";
    }
  ];

  patchRequirements = [
    {
      label = "icount budget function";
      needle = "static int64_t icount_get_limit(void)";
    }
    {
      label = "precise icount gate";
      needle = "if (icount_enabled() != ICOUNT_PRECISE) {";
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

            mkdir -p accel/tcg
            cat > accel/tcg/tcg-accel-ops-icount.c <<'QEMU_FIXTURE'
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
              phase1-icount-no-realtime.c \
              -o phase1-icount-no-realtime

            mkdir -p "$out"
            ./phase1-icount-no-realtime > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^patched_icount_get_limit_fixture=true$' "$out/result"
            grep -q '^precise_realtime_reads_fast=0$' "$out/result"
            grep -q '^precise_realtime_reads_slow=0$' "$out/result"
            grep -q '^precise_realtime_independent=true$' "$out/result"
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
            patch=0002-crucible-icount-no-realtime.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_mode=ICOUNT_PRECISE
            realtime_deadline_in_precise_budget=false
            RESULT
          '';
        }
      ];
    }
