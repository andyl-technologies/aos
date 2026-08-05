{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.clockDeadline",
  taskIds ? ["T-PATCH-10" "T-TIME-6"],
  openTaskIds ? [],
  qemuPackage ? null,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  patchName = "0006-crucible-clock-deadline.patch";
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-clock-deadline.c;
  pluginRoot = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginAbiTests =
    builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs
    + builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests/capabilities.rs;
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  schedulerLiveness = import ./phase3-scheduler-liveness.nix {inherit pkgs lib;};
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

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "clock deadline patch wiring";
        needle = "patch -p1 < \${./qemu-patches/0006-crucible-clock-deadline.patch}";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "deadline plugin symbol";
        needle = "qemu_plugin_clock_deadline_ns";
      }
      {
        label = "virtual clock deadline query";
        needle = "qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,";
      }
      {
        label = "absolute virtual clock conversion";
        needle = "qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delta";
      }
      {
        label = "no armed timer documentation";
        needle = "negative value when no virtual-clock timer is armed";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "realtime deadline query";
        needle = "qemu_clock_deadline_ns_all(QEMU_CLOCK_REALTIME";
      }
      {
        label = "host deadline query";
        needle = "qemu_clock_deadline_ns_all(QEMU_CLOCK_HOST";
      }
      {
        label = "realtime current clock query";
        needle = "qemu_clock_get_ns(QEMU_CLOCK_REALTIME";
      }
      {
        label = "host current clock query";
        needle = "qemu_clock_get_ns(QEMU_CLOCK_HOST";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-clock-deadline.c" microtestSource [
      {
        label = "patched fixture include";
        needle = "#include \"plugins/api-system.c\"";
      }
      {
        label = "deadline symbol exercised";
        needle = "qemu_plugin_clock_deadline_ns()";
      }
      {
        label = "absolute deadline assertion";
        needle = "deadline_absolute_time=124456";
      }
      {
        label = "virtual timer queue fixture";
        needle = "struct FakeTimer";
      }
      {
        label = "armed virtual timer fixture";
        needle = "fake_timer_mod(0, 124456)";
      }
      {
        label = "idle guest deadline query fixture";
        needle = "fake_guest_idle()";
      }
      {
        label = "deadline delta assertion";
        needle = "deadline_delta_ns=123456";
      }
      {
        label = "virtual timer armed assertion";
        needle = "virtual_timer_armed=true";
      }
      {
        label = "guest idle assertion";
        needle = "guest_idle_for_deadline_query=true";
      }
      {
        label = "minimum virtual timer selection";
        needle = "min_virtual_timer_selected=true";
      }
      {
        label = "virtual source assertion";
        needle = "deadline_source=QEMU_CLOCK_VIRTUAL";
      }
      {
        label = "realtime source assertion";
        needle = "realtime_deadline_reads=0";
      }
      {
        label = "host source assertion";
        needle = "host_deadline_reads=0";
      }
      {
        label = "realtime clock assertion";
        needle = "realtime_clock_reads=0";
      }
      {
        label = "host clock assertion";
        needle = "host_clock_reads=0";
      }
      {
        label = "no armed timer sentinel assertion";
        needle = "no_armed_timer_sentinel=-1";
      }
      {
        label = "stock negative control";
        needle = "stock_negative_control_deadline_symbol_absent=true";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginRoot [
      {
        label = "deadline module export";
        needle = "pub mod deadline;";
      }
      {
        label = "deadline symbol export";
        needle = "QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi/tests.rs" pluginAbiTests [
      {
        label = "isolated missing deadline capability test";
        needle = "abi_install_full_capability_scaffold_fails_closed_without_exact_deadline";
      }
      {
        label = "missing deadline before later capability resolution";
        needle = "install_required_vcpu_introspection_scaffold_from_qemu_info(\n            &valid_info,\n            QemuTcgThreading::SingleThreadedRoundRobin,\n            None,";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" pluginDeadline [
      {
        label = "required qemu symbol";
        needle = "qemu_plugin_clock_deadline_ns";
      }
      {
        label = "virtual source enum";
        needle = "QemuClockVirtual";
      }
      {
        label = "realtime source rejection";
        needle = "NonVirtualClockSource";
      }
      {
        label = "capability unavailable error";
        needle = "CapabilityUnavailable";
      }
      {
        label = "overshoot fallback forbidden error";
        needle = "OvershootFallbackForbidden";
      }
      {
        label = "no armed timer report";
        needle = "NoArmedTimer";
      }
      {
        label = "overshoot fallback test";
        needle = "exact_deadline_rejects_overshoot_and_correct_fallback";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "exact local event type";
        needle = "pub enum ExactLocalEvent";
      }
      {
        label = "scheduler horizon type";
        needle = "pub struct SchedulerHorizon";
      }
      {
        label = "horizon from exact local event API";
        needle = "pub fn horizon_from_exact_local_event";
      }
      {
        label = "deadline report bridge";
        needle = "pub fn exact_local_event_from_timer_deadline_ns";
      }
      {
        label = "ceil conversion";
        needle = "horizon.to_icount_ceil(self.shift)";
      }
      {
        label = "exact deadline horizon test";
        needle = "exact_local_deadline_selects_scheduler_horizon_and_ceiling";
      }
      {
        label = "no armed timer horizon test";
        needle = "no_armed_timer_uses_network_horizon";
      }
      {
        label = "deadline bridge test";
        needle = "exact_deadline_report_maps_to_scheduler_local_event";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "exact local event export";
        needle = "ExactLocalEvent";
      }
      {
        label = "scheduler horizon export";
        needle = "SchedulerHorizon";
      }
      {
        label = "exact local horizon export";
        needle = "horizon_from_exact_local_event";
      }
      {
        label = "deadline bridge export";
        needle = "exact_local_event_from_timer_deadline_ns";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
      {
        label = "T-TIME-6 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "PATCH-41 upstream absence documented";
        needle = "upstream QEMU's plugin API";
      }
      {
        label = "PATCH-41 exact deadline remains required";
        needle = "capability remains REQUIRED";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes clock-deadline check";
        needle = "clockDeadline = import ./phase1-clock-deadline.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 clock-deadline check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-clock-deadline";
      version = "0";
      src = crucibleSrc;

      inherit microtestSource patchSource;
      passAsFile = ["microtestSource" "patchSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-clock-deadline-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            mkdir -p "$TMPDIR/clock-deadline-fixture/hw/boards" \
              "$TMPDIR/clock-deadline-fixture/include/qemu" \
              "$TMPDIR/clock-deadline-fixture/migration" \
              "$TMPDIR/clock-deadline-fixture/plugins" \
              "$TMPDIR/clock-deadline-fixture/qapi" \
              "$TMPDIR/clock-deadline-fixture/qemu"
            cd "$TMPDIR/clock-deadline-fixture"
            : > hw/boards.h
            : > migration/blocker.h
            : > qapi/error.h
            : > qemu/plugin-memory.h
            : > qemu/plugin.h
            : > qemu/timer.h

            cat > include/qemu/qemu-plugin.h <<'PLUGIN_HEADER_FIXTURE'
            #ifndef QEMU_PLUGIN_H
            #define QEMU_PLUGIN_H

            #include <stddef.h>
            #include <stdint.h>

            #define QEMU_PLUGIN_API

            QEMU_PLUGIN_API
            uint64_t qemu_plugin_crucible_ram_hash(uint64_t *bytes_out);

            QEMU_PLUGIN_API
            void qemu_plugin_crucible_pause_vm(void);

            /**
             * qemu_plugin_scoreboard_new() - alloc a new scoreboard
             *
             * @element_size: size (in bytes) for one entry
             */
            struct qemu_plugin_scoreboard;
            QEMU_PLUGIN_API
            struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size);

            #endif
            PLUGIN_HEADER_FIXTURE

            cat > plugins/api-system.c <<'PLUGIN_API_FIXTURE'
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>

            #include "qapi/error.h"
            #include "migration/blocker.h"
            #include "hw/boards.h"
            #include "qemu/plugin-memory.h"
            #include "qemu/plugin.h"

            #include "qemu/qemu-plugin.h"

            typedef struct CPUState CPUState;
            typedef struct Error Error;
            typedef struct run_on_cpu_data {
                uintptr_t host_ulong;
            } run_on_cpu_data;

            static CPUState *current_cpu;

            #define RUN_ON_CPU_HOST_ULONG(value) \
                ((run_on_cpu_data){.host_ulong = (uintptr_t)(value)})

            struct qemu_plugin_scoreboard { int unused; };

            int64_t qemu_clock_deadline_ns_all(int clock, int attrs);
            int64_t qemu_clock_get_ns(int clock);
            static void qemu_clock_advance_virtual_time(int64_t new_time)
            {
                (void)new_time;
            }
            static void async_run_on_cpu(CPUState *cpu,
                                         void (*fn)(CPUState *, run_on_cpu_data),
                                         run_on_cpu_data data)
            {
                fn(cpu, data);
            }

            struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size)
            {
                (void)element_size;
                return NULL;
            }

            static bool has_control;

            const void *qemu_plugin_request_time_control(void)
            {
                if (!has_control) {
                    has_control = true;
                    return &has_control;
                }
                return NULL;
            }

            static void advance_virtual_time__async(CPUState *cpu, run_on_cpu_data data)
            {
                (void)cpu;
                int64_t new_time = data.host_ulong;
                qemu_clock_advance_virtual_time(new_time);
            }

            void qemu_plugin_update_ns(const void *handle, int64_t new_time)
            {
                if (handle == &has_control) {
                    /* Need to execute out of cpu_exec, so bql can be locked. */
                    async_run_on_cpu(current_cpu,
                                     advance_virtual_time__async,
                                     RUN_ON_CPU_HOST_ULONG(new_time));
                }
            }
            PLUGIN_API_FIXTURE

            cat > stock-clock-deadline-negative.c <<'STOCK_NEGATIVE'
            #include <stddef.h>
            #include <stdint.h>

            struct qemu_plugin_register;
            typedef struct GByteArray GByteArray;

            #include "plugins/api-system.c"

            int main(void)
            {
                return (int)qemu_plugin_clock_deadline_ns();
            }
            STOCK_NEGATIVE
            if cc -std=c11 -Wall -Werror \
              -I include \
              -I . \
              -c stock-clock-deadline-negative.c \
              -o stock-clock-deadline-negative.o \
              2> stock-clock-deadline-negative.err
            then
              echo "stock clock-deadline plugin API unexpectedly compiled" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_clock_deadline_ns' stock-clock-deadline-negative.err

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp "$microtestSourcePath" phase1-clock-deadline.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -I include \
              -I . \
              phase1-clock-deadline.c \
              -o phase1-clock-deadline

            mkdir -p "$out"
            ./phase1-clock-deadline > "$out/clock-deadline-microtest"
            grep -q '^PASS$' "$out/clock-deadline-microtest"
            grep -q '^deadline_source=QEMU_CLOCK_VIRTUAL$' "$out/clock-deadline-microtest"
            grep -q '^deadline_absolute_time=124456$' "$out/clock-deadline-microtest"
            grep -q '^deadline_delta_ns=123456$' "$out/clock-deadline-microtest"
            grep -q '^virtual_timer_armed=true$' "$out/clock-deadline-microtest"
            grep -q '^guest_idle_for_deadline_query=true$' "$out/clock-deadline-microtest"
            grep -q '^min_virtual_timer_selected=true$' "$out/clock-deadline-microtest"
            grep -q '^realtime_deadline_reads=0$' "$out/clock-deadline-microtest"
            grep -q '^host_deadline_reads=0$' "$out/clock-deadline-microtest"
            grep -q '^realtime_clock_reads=0$' "$out/clock-deadline-microtest"
            grep -q '^host_clock_reads=0$' "$out/clock-deadline-microtest"
            grep -q '^no_armed_timer_sentinel=-1$' "$out/clock-deadline-microtest"
            grep -q '^stock_negative_control_deadline_symbol_absent=true$' "$out/clock-deadline-microtest"
            cp "${schedulerLiveness}/result" "$out/scheduler-liveness.result"
            grep -q '^PASS$' "$out/scheduler-liveness.result"
            grep -q '^gate=gate:scheduler-liveness$' "$out/scheduler-liveness.result"

            cd "$TMPDIR"
            cd "$NIX_BUILD_TOP/source/crates"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-clock-deadline-target" \
              -p crucible-qemu-plugin \
              --lib exact_deadline \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-clock-deadline-target" \
              -p crucible-qemu-plugin \
              --lib abi_install_full_capability_scaffold_fails_closed_without_exact_deadline \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-clock-deadline-target" \
              -p crucible \
              --lib scheduler:: \
              -- --test-threads=1

            cp "$patchSourcePath" "$out/${patchName}"
            cp "$TMPDIR/clock-deadline-fixture/plugins/api-system.c" "$out/api-system.c.patched"
            cp "$TMPDIR/clock-deadline-fixture/include/qemu/qemu-plugin.h" \
              "$out/qemu-plugin.h.patched"
            cp "$TMPDIR/clock-deadline-fixture/stock-clock-deadline-negative.err" \
              "$out/stock-negative-control.err"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=partial
            evidence_scope=qemu-export-microtest-and-plugin-reader-model
            gate=gate:layer0-determinism
            gate=gate:scheduler-liveness
            gate=gate:patch-microtests
            patch=0006-crucible-clock-deadline.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            deadline_symbol=qemu_plugin_clock_deadline_ns
            deadline_source=QEMU_CLOCK_VIRTUAL
            deadline_absolute_time=124456
            deadline_delta_ns=123456
            virtual_timer_armed=true
            guest_idle_for_deadline_query=true
            min_virtual_timer_selected=true
            realtime_deadline_source=false
            host_deadline_source=false
            realtime_clock_source=false
            host_clock_source=false
            no_armed_timer_sentinel=-1
            capability_required=true
            missing_capability_fails_closed=true
            install_missing_deadline_isolated=true
            overshoot_and_correct_fallback=false
            patch41_upstream_api_absent_documented=true
            scheduler_liveness_gate_consumed=true
            scheduler_horizon_exact_local_event=true
            scheduler_deadline_bridge=true
            scheduler_deadline_to_icount=ceil
            RESULT
          '';
        }
      ];
    }
