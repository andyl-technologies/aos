{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0029-crucible-vcpu-introspect.patch",
  attrPath ? "checks.crucible.phase2.qemuVcpuIntrospect",
  taskIds ? ["T-PATCH-23"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  pluginPackage = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  microtestSource = builtins.readFile ./phase2-qemu-vcpu-introspect.c;
  taskList = builtins.concatStringsSep "," taskIds;

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

  countOccurrences = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0 || maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.length (
      builtins.filter (index:
        builtins.substring index needleLen haystack == needle)
      indexes
    );

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "T-PATCH-23 checklist complete";
        needle = "- [x] **T-PATCH-23**";
      }
      {
        label = "PATCH-46 register export";
        needle = "qemu_plugin_read_vcpu_regs";
      }
      {
        label = "PATCH-46 cursor export";
        needle = "qemu_plugin_rr_cursor";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "QEMU package applies vCPU introspection patch";
        needle = "patch -p1 < \${./qemu-patches/${patchName}}";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "formal register API declaration";
        needle = "int qemu_plugin_read_vcpu_regs(unsigned int vcpu_index";
      }
      {
        label = "formal cursor API declaration";
        needle = "int qemu_plugin_rr_cursor(struct qemu_plugin_rr_cursor *out)";
      }
      {
        label = "stable canonical register version tag";
        needle = "aos-qemu-vcpu-regs-v1";
      }
      {
        label = "arbitrary vCPU selection";
        needle = "CPUState *cpu = qemu_get_cpu(vcpu_index);";
      }
      {
        label = "short buffer reports required byte count";
        needle = "*out_register_len = offset;";
      }
      {
        label = "register export leaves icount ownership to caller";
        needle = "The aggregate sample icount belongs to the caller's trace sample.";
      }
      {
        label = "cursor current-vCPU read";
        needle = "qemu_plugin_crucible_rr_current_vcpu()";
      }
      {
        label = "cursor quantum read";
        needle = "qemu_plugin_crucible_rr_switch_quantum()";
      }
      {
        label = "cursor boundary fails closed";
        needle = "cursor_position >= rr_switch_quantum";
      }
      {
        label = "register read size mismatch fails closed";
        needle = "(size_t)size != buffer->len";
      }
      {
        label = "cursor current vCPU range check";
        needle = "current_vcpu >= (uint64_t)num_vcpus";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" tracePluginSource [
      {
        label = "trace plugin consumes formal register export";
        needle = "qemu_plugin_read_vcpu_regs(";
      }
      {
        label = "trace plugin consumes formal cursor export";
        needle = "qemu_plugin_rr_cursor(&cursor)";
      }
      {
        label = "trace plugin publishes formal cursor validity";
        needle = "\\\"rr_cursor_valid\\\":%s";
      }
      {
        label = "live cursor evidence is tracked independently, not helper-sourced";
        needle = "last_valid_rr_cursor_available";
      }
      {
        label = "live cursor provenance tag pins live-instruction observation";
        needle = "\"live_instruction\"";
      }
      {
        label = "genesis RR primitive reads are marked authoritative, not a fallback";
        needle = "Authoritative RR genesis-quiescence probe: definition raw-state validation";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackage [
      {
        label = "plugin package probes formal register export";
        needle = "qemu_plugin_read_vcpu_regs";
      }
      {
        label = "plugin package probes formal cursor export";
        needle = "qemu_plugin_rr_cursor";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-vcpu-introspect.c" microtestSource [
      {
        label = "arbitrary vCPU register assertion";
        needle = "arbitrary_vcpu_register_read=true";
      }
      {
        label = "side-effect-free assertion";
        needle = "register_read_side_effect_free=true";
      }
      {
        label = "short-buffer fail-closed assertion";
        needle = "register_short_buffer_fails_closed=true";
      }
      {
        label = "register-size mismatch assertion";
        needle = "register_size_mismatch_rejected=true";
      }
      {
        label = "cursor boundary assertion";
        needle = "rr_cursor_boundary_rejected=true";
      }
      {
        label = "cursor current-vCPU range assertion";
        needle = "rr_cursor_out_of_range_current_vcpu_rejected=true";
      }
      {
        label = "stock negative control assertion";
        needle = "stock_negative_control_symbols_absent=true";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes vCPU introspection task check";
        needle = "qemuVcpuIntrospect = import ./phase2-qemu-vcpu-introspect.nix";
      }
    ]
    # Oracle-independence guard (refined 2026-07-13). The C trace plugin is the
    # independent differential oracle: its LIVE per-instruction RR-cursor
    # evidence (rr_cursor_source=="live_instruction") must be derived by live
    # observation via read_rr_cursor_snapshot()/last_valid_rr_*, NOT by querying
    # the patched-QEMU RR primitives that the Rust control plugin also consumes.
    # The original guard blanket-banned the two primitive strings. That was too
    # broad: record_definition() legitimately reads them ONCE at a pre-execution
    # genesis boundary where no vCPU is current and the qemu_plugin_rr_cursor()
    # aggregate fails closed — pure genesis-quiescence validation, distinct
    # (kind:"definition", rr_state_status key) from and never conflated with the
    # live cursor evidence. The refinement keeps the ban's teeth via an exact
    # occurrence count (any second read would be a live-path helper-source and
    # trips the gate) plus positive needles pinning the live-tracking machinery
    # and the required adjacent authoritative-probe marker in the C source.
    ++ helperCountFailures;

  sanctionedHelperCounts = [
    {
      label = "genesis-only RR current-vCPU primitive read";
      needle = "qemu_plugin_crucible_rr_current_vcpu()";
      sanctioned = 1;
    }
    {
      label = "genesis-only RR cursor-position primitive read";
      needle = "qemu_plugin_crucible_rr_cursor_position()";
      sanctioned = 1;
    }
  ];

  helperCountFailures =
    lib.concatMap (
      probe: let
        actual = countOccurrences probe.needle tracePluginSource;
      in
        lib.optionals (actual != probe.sanctioned) [
          "pkgs/emulation/crucible-qemu-trace-plugin.c: ${probe.label} `${probe.needle}` must appear exactly ${toString probe.sanctioned} time(s) — the sanctioned record_definition() genesis probe — found ${toString actual}. A live cursor-evidence path must source the RR cursor through qemu_plugin_rr_cursor()/read_rr_cursor_snapshot(), never these primitives, to keep the C observer independent of the Rust control plugin."
        ]
    )
    sanctionedHelperCounts;
in
  if failures != []
  then throw "crucible phase2 QEMU vCPU introspection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-vcpu-introspect";
      version = "0";
      src = null;

      inherit microtestSource patchSource;
      passAsFile = ["microtestSource" "patchSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
        pkgs.pkg-config
        pkgs.glib
        qemuPackage
        referenceQemu
      ];

      phases = [
        {
          name = "run-qemu-vcpu-introspect-microtest";
          script = ''
            set -eu

            mkdir -p disas exec include/qemu plugins qemu tcg
            for header in \
              disas/disas.h \
              exec/cpu-common.h \
              exec/gdbstub.h \
              exec/ramblock.h \
              exec/ramlist.h \
              exec/target_page.h \
              exec/translation-block.h \
              exec/translator.h \
              plugins/plugin.h \
              qemu/log.h \
              qemu/main-loop.h \
              qemu/osdep.h \
              qemu/plugin.h \
              tcg/tcg.h
            do
              : > "$header"
            done

            cat > include/qemu/qemu-plugin.h <<'QEMU_HEADER'
            #ifndef QEMU_PLUGIN_H
            #define QEMU_PLUGIN_H
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #define QEMU_PLUGIN_API
            struct qemu_plugin_register;
            struct qemu_plugin_scoreboard;
            typedef uint64_t qemu_plugin_u64;
            typedef struct qemu_plugin_reg_descriptor {
                struct qemu_plugin_register *handle;
                const char *name;
                const char *feature;
            } qemu_plugin_reg_descriptor;
            QEMU_PLUGIN_API
            uint64_t qemu_plugin_icount_raw(void);
            QEMU_PLUGIN_API
            int qemu_plugin_read_register(struct qemu_plugin_register *handle,
                                          GByteArray *buf);
            QEMU_PLUGIN_API
            GArray *qemu_plugin_crucible_get_vcpu_registers(unsigned int vcpu_index);
            QEMU_PLUGIN_API
            int qemu_plugin_crucible_read_vcpu_register(unsigned int vcpu_index,
                                                        struct qemu_plugin_register *handle,
                                                        GByteArray *buf);

            /**
             * qemu_plugin_crucible_rr_current_vcpu() - return the current RR vCPU index
             *
             * Returns UINT64_MAX when no vCPU is current.
             */
            QEMU_PLUGIN_API
            uint64_t qemu_plugin_crucible_rr_current_vcpu(void);
            QEMU_PLUGIN_API
            uint64_t qemu_plugin_crucible_rr_cursor_position(void);
            QEMU_PLUGIN_API
            uint64_t qemu_plugin_crucible_rr_switch_quantum(void);
            QEMU_PLUGIN_API
            struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size);
            QEMU_PLUGIN_API
            uint64_t qemu_plugin_u64_sum(qemu_plugin_u64 entry);
            #endif
            QEMU_HEADER

            cat > plugins/api.c <<'QEMU_API'
            #include "qemu/main-loop.h"
            #include "qemu/plugin.h"
            #include "qemu/log.h"
            #include "tcg/tcg.h"
            #include "exec/gdbstub.h"
            #include "exec/target_page.h"
            #include "exec/translation-block.h"
            #include "exec/translator.h"
            #include "disas/disas.h"
            #include "plugin.h"

            uint64_t qemu_plugin_crucible_rr_current_vcpu(void);

            static GArray *create_register_handles(GArray *gdbstub_regs)
            {
                GArray *find_data = g_array_new(true, true,
                                                sizeof(qemu_plugin_reg_descriptor));

                for (unsigned int i = 0; i < gdbstub_regs->len; i++) {
                    GDBRegDesc *grd = &g_array_index(gdbstub_regs, GDBRegDesc, i);
                    qemu_plugin_reg_descriptor desc;

                    if (!grd->name) {
                        continue;
                    }

                    desc.handle = GINT_TO_POINTER(grd->gdb_reg + 1);
                    desc.name = g_intern_string(grd->name);
                    desc.feature = g_intern_string(grd->feature_name);
                    g_array_append_val(find_data, desc);
                }

                return find_data;
            }

            int qemu_plugin_read_register(struct qemu_plugin_register *reg, GByteArray *buf)
            {
                return gdb_read_register(current_cpu, buf, GPOINTER_TO_INT(reg) - 1);
            }

            #ifndef CONFIG_USER_ONLY
            GArray *qemu_plugin_crucible_get_vcpu_registers(unsigned int vcpu_index)
            {
                CPUState *cpu = qemu_get_cpu(vcpu_index);

                if (!cpu) {
                    return NULL;
                }

                g_autoptr(GArray) regs = gdb_get_register_list(cpu);
                return create_register_handles(regs);
            }

            int qemu_plugin_crucible_read_vcpu_register(unsigned int vcpu_index,
                                                        struct qemu_plugin_register *reg,
                                                        GByteArray *buf)
            {
                CPUState *cpu = qemu_get_cpu(vcpu_index);

                if (!cpu || !reg) {
                    return -1;
                }

                return gdb_read_register(cpu, buf, GPOINTER_TO_INT(reg) - 1);
            }

            uint64_t qemu_plugin_crucible_rr_current_vcpu(void)
            {
                if (!current_cpu) {
                    return UINT64_MAX;
                }

                return (uint64_t)current_cpu->cpu_index;
            }

            #endif

            struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size)
            {
                return plugin_scoreboard_new(element_size);
            }

            uint64_t qemu_plugin_u64_sum(qemu_plugin_u64 entry)
            {
                uint64_t total = 0;
                for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; ++i) {
                    total += qemu_plugin_u64_get(entry, i);
                }
                return total;
            }

            QEMU_API

            test -f ${referenceQemu}/include/qemu/qemu-plugin.h
            if grep -q 'qemu_plugin_read_vcpu_regs' \
              ${referenceQemu}/include/qemu/qemu-plugin.h
            then
              echo "reference QEMU header unexpectedly declares qemu_plugin_read_vcpu_regs" >&2
              exit 1
            fi
            if grep -q 'qemu_plugin_rr_cursor' \
              ${referenceQemu}/include/qemu/qemu-plugin.h
            then
              echo "reference QEMU header unexpectedly declares qemu_plugin_rr_cursor" >&2
              exit 1
            fi

            cat > stock-vcpu-introspect-negative.c <<'STOCK_NEGATIVE'
            #include <stdint.h>
            #include <stddef.h>
            #include <qemu/qemu-plugin.h>

            int main(void)
            {
                size_t len = 0;
                uint64_t retired = 0;
                uint8_t bytes[16];
                struct qemu_plugin_rr_cursor cursor;
                int status = qemu_plugin_read_vcpu_regs(0, bytes, sizeof(bytes), &len, &retired);
                return status + qemu_plugin_rr_cursor(&cursor);
            }
            STOCK_NEGATIVE
            if env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u CPATH \
              cc -std=c11 -Wall -Werror -Werror=implicit-function-declaration \
              -I${referenceQemu}/include $(pkg-config --cflags glib-2.0) \
              -c stock-vcpu-introspect-negative.c \
              -o stock-vcpu-introspect-negative.o \
              2> stock-vcpu-introspect-negative.err
            then
              echo "stock vCPU introspection API unexpectedly compiled" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_read_vcpu_regs' stock-vcpu-introspect-negative.err
            grep -q 'qemu_plugin_rr_cursor' stock-vcpu-introspect-negative.err

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp include/qemu/qemu-plugin.h qemu/qemu-plugin.h
            cp "$microtestSourcePath" phase2-qemu-vcpu-introspect.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -Wno-unused-function -Wno-unused-parameter \
              -I. -Iinclude \
              phase2-qemu-vcpu-introspect.c \
              -o phase2-qemu-vcpu-introspect

            mkdir -p "$out"
            ./phase2-qemu-vcpu-introspect > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^formal_register_export=qemu_plugin_read_vcpu_regs$' "$out/result"
            grep -q '^formal_cursor_export=qemu_plugin_rr_cursor$' "$out/result"
            grep -q '^arbitrary_vcpu_register_read=true$' "$out/result"
            grep -q '^register_read_side_effect_free=true$' "$out/result"
            grep -q '^register_short_buffer_fails_closed=true$' "$out/result"
            grep -q '^register_short_buffer_reports_required_size=true$' "$out/result"
            grep -q '^invalid_vcpu_register_read_rejected=true$' "$out/result"
            grep -q '^register_size_mismatch_rejected=true$' "$out/result"
            grep -q '^rr_cursor_reads_current_vcpu_position_and_quantum=true$' "$out/result"
            grep -q '^rr_cursor_boundary_rejected=true$' "$out/result"
            grep -q '^rr_cursor_zero_quantum_rejected=true$' "$out/result"
            grep -q '^rr_cursor_out_of_range_current_vcpu_rejected=true$' "$out/result"
            grep -q '^rr_cursor_no_current_vcpu_rejected=true$' "$out/result"
            grep -q '^stock_negative_control_symbols_absent=true$' "$out/result"

            nm -D --defined-only ${qemuPackage}/bin/qemu-system-x86_64 \
              > "$out/qemu-system-x86_64.dynamic-symbols"
            grep -E '[[:space:]]qemu_plugin_read_vcpu_regs$' \
              "$out/qemu-system-x86_64.dynamic-symbols"
            grep -E '[[:space:]]qemu_plugin_rr_cursor$' \
              "$out/qemu-system-x86_64.dynamic-symbols"

            cat >> "$out/result" <<RESULT
            check=${attrPath}
            tasks=${taskList}
            gate=gate:patch-microtests
            gate=gate:single-vm-fingerprint
            gate=gate:qemu-inert
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            reference_qemu=${referenceQemu}
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            dynamic_symbol_qemu_plugin_read_vcpu_regs=true
            dynamic_symbol_qemu_plugin_rr_cursor=true
            RESULT
          '';
        }
      ];
    }
