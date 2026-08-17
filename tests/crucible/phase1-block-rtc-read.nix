{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0007-crucible-block-rtc-read.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-block-rtc-read.c;
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
      label = "manifest-driven patch wiring";
      needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
    }
  ];

  patchRequirements = [
    {
      label = "sim RTC enable entrypoint";
      needle = "void qemu_rtc_enable_sim_virtual_clock(void)";
    }
    {
      label = "sim accelerator init hook";
      needle = "qemu_rtc_enable_sim_virtual_clock();";
    }
    {
      label = "global RTC clock force";
      needle = "rtc_clock = QEMU_CLOCK_VIRTUAL;";
    }
    {
      label = "qemu_get_timedate substitution";
      needle = "qemu_ref_timedate(crucible_guest_rtc_clock())";
    }
    {
      label = "timedate diff substitution";
      needle = "seconds - qemu_ref_timedate(crucible_guest_rtc_clock())";
    }
    {
      label = "fixed epoch rationale";
      needle = "fixed epoch plus";
    }
  ];

  microtestRequirements = [
    {
      label = "patched RTC fixture include";
      needle = "#include \"system/rtc.c\"";
    }
    {
      label = "configure RTC launch model";
      needle = "configure_fixed_host_rtc";
    }
    {
      label = "sim RTC enable model";
      needle = "qemu_rtc_enable_sim_virtual_clock()";
    }
    {
      label = "sim virtual-clock assertion";
      needle = "sim_rtc_reads_virtual_clock=true";
    }
    {
      label = "direct CMOS virtual-clock assertion";
      needle = "sim_direct_cmos_reads_virtual_clock=true";
    }
    {
      label = "sim host-clock suppression assertion";
      needle = "sim_rtc_host_clock_reads=0";
    }
    {
      label = "fixed epoch assertion";
      needle = "fixed_epoch_plus_virtual_time=true";
    }
    {
      label = "non-sim upstream assertion";
      needle = "non_sim_rtc_reads_host_clock=true";
    }
    {
      label = "non-sim direct CMOS upstream assertion";
      needle = "non_sim_direct_cmos_reads_host_clock=true";
    }
    {
      label = "stock negative control";
      needle = "stock_negative_control_reads_host=true";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-block-rtc-read.c" microtestSource microtestRequirements;
in
  if failures != []
  then throw "crucible phase1 block-rtc-read check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-block-rtc-read";
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
          name = "run-block-rtc-read-microtest";
          script = ''
            set -eu

            mkdir -p accel/tcg hw/rtc include/system qapi qemu qom system
            : > accel/tcg/tcg-accel-ops.h
            : > hw/boards.h
            : > hw/qdev-core.h
            : > hw/rtc/mc146818rtc.h
            : > qapi/qapi-builtin-visit.h
            : > qapi/error.h
            : > qemu/accel.h
            : > qemu/atomic.h
            : > qemu/cutils.h
            : > qemu/error-report.h
            : > qemu/option.h
            : > qemu/osdep.h
            : > qemu/timer.h
            : > qemu/units.h
            : > qom/object.h
            : > system/accel-ops.h
            : > system/replay.h
            : > system/system.h
            : > system/tcg.h

            cat > include/system/rtc.h <<'RTC_HEADER_FIXTURE'
            /*
             * RTC configuration and clock read
             *
             * Copyright (c) 2003-2021 QEMU contributors
             *
             * Permission is hereby granted, free of charge, to any person obtaining a copy
             * of this software and associated documentation files (the "Software"), to deal
             * in the Software without restriction, including without limitation the rights
             * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
             * copies of the Software, and to permit persons to whom the Software is
             * furnished to do so, subject to the following conditions:
             *
             * The above copyright notice and this permission notice shall be included in
             * all copies or substantial portions of the Software.
             *
             * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
             * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
             * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
             * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
             * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
             * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
             * THE SOFTWARE.
             */

            #ifndef SYSTEM_RTC_H
            #define SYSTEM_RTC_H

            /**
             * qemu_get_timedate: Get the current RTC time
             * @tm: struct tm to fill in with RTC time
             * @offset: offset in seconds to adjust the RTC time by before
             *          converting to struct tm format.
             *
             * This function fills in @tm with the current RTC time, as adjusted
             * by @offset (for example, if @offset is 3600 then the returned time/date
             * will be one hour further ahead than the current RTC time).
             *
             * The usual use is by RTC device models, which should call this function
             * to find the time/date value that they should return to the guest
             * when it reads the RTC registers.
             *
             * The behaviour of the clock whose value this function returns will
             * depend on the -rtc command line option passed by the user.
             */
            void qemu_get_timedate(struct tm *tm, time_t offset);

            /**
             * qemu_timedate_diff: Return difference between a struct tm and the RTC
             * @tm: struct tm containing the date/time to compare against
             *
             * Returns the difference in seconds between the RTC clock time
             * and the date/time specified in @tm. For example, if @tm specifies
             * a timestamp one hour further ahead than the current RTC time
             * then this function will return 3600.
             */
            time_t qemu_timedate_diff(struct tm *tm);

            #endif
            RTC_HEADER_FIXTURE

            cat > accel/tcg/tcg-all.c <<'TCG_ALL_FIXTURE'
            #include "qemu/osdep.h"
            #include "qemu/error-report.h"
            #include "qemu/accel.h"
            #include "qemu/atomic.h"
            #include "qapi/qapi-builtin-visit.h"
            #include "qemu/units.h"
            #if defined(CONFIG_USER_ONLY)
            #include "hw/qdev-core.h"
            #else
            #include "hw/boards.h"
            #endif
            #include "system/system.h"
            #include "system/accel-ops.h"
            #include "system/tcg.h"

            typedef struct MachineState MachineState;
            typedef struct TCGState {
                bool mttcg_enabled;
            } TCGState;

            static TCGState test_tcg_state;

            static bool icount_enabled(void)
            {
                return true;
            }

            static void error_report(const char *message)
            {
                (void)message;
            }

            static void *current_accel(void)
            {
                return &test_tcg_state;
            }

            #define TCG_STATE(value) ((TCGState *)(value))
            #define EINVAL 22

            static int tcg_init_machine(MachineState *ms)
            {
                (void)ms;
                return 0;
            }

            static int sim_init_machine(MachineState *ms)
            {
                TCGState *s = TCG_STATE(current_accel());

                if (!icount_enabled()) {
                    error_report("-accel sim requires -icount shift=N");
                    return -EINVAL;
                }

                /* The sim accelerator is deliberately single-threaded. */
                s->mttcg_enabled = false;
                return tcg_init_machine(ms);
            }

            TCG_ALL_FIXTURE

            cat > system/rtc.c <<'QEMU_FIXTURE'
            /*
             * RTC configuration and clock read
             *
             * Copyright (c) 2003-2020 QEMU contributors
             *
             * Permission is hereby granted, free of charge, to any person obtaining a copy
             * of this software and associated documentation files (the "Software"), to deal
             * in the Software without restriction, including without limitation the rights
             * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
             * copies of the Software, and to permit persons to whom the Software is
             * furnished to do so, subject to the following conditions:
             *
             * The above copyright notice and this permission notice shall be included in
             * all copies or substantial portions of the Software.
             *
             * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
             * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
             * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
             * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
             * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
             * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
             * THE SOFTWARE.
             */

            #include "qemu/osdep.h"
            #include "qemu/cutils.h"
            #include "qapi/error.h"
            #include "qemu/error-report.h"
            #include "qemu/option.h"
            #include "qemu/timer.h"
            #include "qom/object.h"
            #include "system/replay.h"
            #include "system/system.h"
            #include "system/rtc.h"
            #include "hw/rtc/mc146818rtc.h"

            static enum {
                RTC_BASE_UTC,
                RTC_BASE_LOCALTIME,
                RTC_BASE_DATETIME,
            } rtc_base_type = RTC_BASE_UTC;
            static time_t rtc_ref_start_datetime;
            static int rtc_realtime_clock_offset; /* used only with QEMU_CLOCK_REALTIME */
            static int rtc_host_datetime_offset = -1; /* valid & used only with
                                                         RTC_BASE_DATETIME */
            QEMUClockType rtc_clock;
            /***********************************************************/
            /* RTC reference time/date access */
            static time_t qemu_ref_timedate(QEMUClockType clock)
            {
                time_t value = qemu_clock_get_ms(clock) / 1000;
                switch (clock) {
                case QEMU_CLOCK_REALTIME:
                    value -= rtc_realtime_clock_offset;
                    /* fall through */
                case QEMU_CLOCK_VIRTUAL:
                    value += rtc_ref_start_datetime;
                    break;
                case QEMU_CLOCK_HOST:
                    if (rtc_base_type == RTC_BASE_DATETIME) {
                        value -= rtc_host_datetime_offset;
                    }
                    break;
                default:
                    g_assert_not_reached();
                }
                return value;
            }

            void qemu_get_timedate(struct tm *tm, time_t offset)
            {
                time_t ti = qemu_ref_timedate(rtc_clock);

                ti += offset;

                switch (rtc_base_type) {
                case RTC_BASE_DATETIME:
                case RTC_BASE_UTC:
                    gmtime_r(&ti, tm);
                    break;
                case RTC_BASE_LOCALTIME:
                    localtime_r(&ti, tm);
                    break;
                }
            }

            time_t qemu_timedate_diff(struct tm *tm)
            {
                time_t seconds;

                switch (rtc_base_type) {
                case RTC_BASE_DATETIME:
                case RTC_BASE_UTC:
                    seconds = mktimegm(tm);
                    break;
                case RTC_BASE_LOCALTIME:
                {
                    struct tm tmp = *tm;
                    tmp.tm_isdst = -1; /* use timezone to figure it out */
                    seconds = mktime(&tmp);
                    break;
                }
                default:
                    abort();
                }

                return seconds - qemu_ref_timedate(QEMU_CLOCK_HOST);
            }

            static void configure_rtc_base_datetime(const char *startdate)
            {
                time_t rtc_start_datetime;
                struct tm tm;

                if (sscanf(startdate, "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon,
                           &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
                    /* OK */
                } else if (sscanf(startdate, "%d-%d-%d",
                                  &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3) {
                    tm.tm_hour = 0;
                    tm.tm_min = 0;
                    tm.tm_sec = 0;
                } else {
                    goto date_fail;
                }
                tm.tm_year -= 1900;
                tm.tm_mon--;
                rtc_start_datetime = mktimegm(&tm);
                if (rtc_start_datetime == -1) {
                date_fail:
                    error_report("invalid datetime format");
                    error_printf("valid formats: "
                                 "'2006-06-17T16:01:21' or '2006-06-17'\n");
                    exit(1);
                }
                rtc_host_datetime_offset = rtc_ref_start_datetime - rtc_start_datetime;
                rtc_ref_start_datetime = rtc_start_datetime;
            }

            void configure_rtc(QemuOpts *opts)
            {
                const char *value;

                /* Set defaults */
                rtc_clock = QEMU_CLOCK_HOST;
                rtc_ref_start_datetime = qemu_clock_get_ms(QEMU_CLOCK_HOST) / 1000;
                rtc_realtime_clock_offset = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) / 1000;

                value = qemu_opt_get(opts, "base");
                if (value) {
                    if (!strcmp(value, "utc")) {
                        rtc_base_type = RTC_BASE_UTC;
                    } else if (!strcmp(value, "localtime")) {
                        rtc_base_type = RTC_BASE_LOCALTIME;
                        replay_add_blocker("-rtc base=localtime");
                    } else {
                        rtc_base_type = RTC_BASE_DATETIME;
                        configure_rtc_base_datetime(value);
                    }
                }
                value = qemu_opt_get(opts, "clock");
                if (value) {
                    if (!strcmp(value, "host")) {
                        rtc_clock = QEMU_CLOCK_HOST;
                    } else if (!strcmp(value, "rt")) {
                        rtc_clock = QEMU_CLOCK_REALTIME;
                    } else if (!strcmp(value, "vm")) {
                        rtc_clock = QEMU_CLOCK_VIRTUAL;
                    } else {
                        error_report("invalid option value '%s'", value);
                        exit(1);
                    }
                }
                value = qemu_opt_get(opts, "driftfix");
                if (value) {
                    if (!strcmp(value, "slew")) {
                        object_register_sugar_prop(TYPE_MC146818_RTC,
                                                   "lost_tick_policy",
                                                   "slew",
                                                   false);
                        if (!object_class_by_name(TYPE_MC146818_RTC)) {
                            warn_report("driftfix 'slew' is not available with this machine");
                        }
                    } else if (!strcmp(value, "none")) {
                        /* discard is default */
                    } else {
                        error_report("invalid option value '%s'", value);
                        exit(1);
                    }
                }
            }
            QEMU_FIXTURE

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp "$microtestSourcePath" phase1-block-rtc-read.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -I . -I include \
              phase1-block-rtc-read.c \
              -o phase1-block-rtc-read

            mkdir -p "$out"
            ./phase1-block-rtc-read > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^patched_qemu_get_timedate_fixture=true$' "$out/result"
            grep -q '^configure_rtc_fixed_epoch_exercised=true$' "$out/result"
            grep -q '^sim_rtc_enable_forces_virtual_clock=true$' "$out/result"
            grep -q '^sim_rtc_reads_virtual_clock=true$' "$out/result"
            grep -q '^sim_direct_cmos_reads_virtual_clock=true$' "$out/result"
            grep -q '^sim_rtc_host_clock_reads=0$' "$out/result"
            grep -q '^sim_rtc_realtime_clock_reads=0$' "$out/result"
            grep -q '^sim_timedate_diff_virtual=true$' "$out/result"
            grep -q '^fixed_epoch_plus_virtual_time=true$' "$out/result"
            grep -q '^non_sim_rtc_reads_host_clock=true$' "$out/result"
            grep -q '^non_sim_direct_cmos_reads_host_clock=true$' "$out/result"
            grep -q '^non_sim_timedate_diff_upstream=true$' "$out/result"
            grep -q '^stock_negative_control_reads_host=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp accel/tcg/tcg-all.c "$out/tcg-all.c.patched"
            cp include/system/rtc.h "$out/rtc.h.patched"
            cp system/rtc.c "$out/rtc.c.patched"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.blockRtcRead
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-8
            patch=0007-crucible-block-rtc-read.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            sim_predicate=sim_init_machine
            guest_realtime_source=fixed_epoch_plus_virtual_clock
            direct_cmos_rtc_source=fixed_epoch_plus_virtual_clock
            non_sim_realtime_source=upstream
            residual_host_clock_read_under_sim=false
            RESULT
          '';
        }
      ];
    }
