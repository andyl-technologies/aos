{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  patchName ? "0033-crucible-sim-observer.patch",
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;

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

  failures =
    lib.optionals (!(hasInfix "qemu_plugin_register_sim_shmem_observer_cb" patchSource)) [
      "${patchName}: missing observation-only sim-boundary API"
    ]
    ++ lib.optionals (!(hasInfix "crucible_publish_icount_cb(current_icount" patchSource)) [
      "${patchName}: missing scheduler-owned publication paired with observation"
    ]
    ++ lib.optionals (!(hasInfix "crucible_observe_icount_cb(current_icount" patchSource)) [
      "${patchName}: missing post-execution observer dispatch"
    ]
    ++ lib.optionals (!(hasInfix "on_sim_observe_icount, on_sim_observer_max_advance_icount" tracePluginSource)) [
      "crucible-qemu-trace-plugin.c: loaded-QEMU trace does not consume the observer API"
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU sim observer check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-sim-observer";
      version = "0";
      src = null;

      # qemuPackage and referenceQemu are consumed only through explicit
      # `-I${...}/include` flags below, NOT via buildDeps: putting the patched
      # qemuPackage in buildDeps leaks its qemu-plugin.h onto C_INCLUDE_PATH,
      # where it satisfies `#include <qemu-plugin.h>` in the negative-control
      # compile even under `-I${referenceQemu}/include`, so the "stock lacks the
      # sim-observer API" control silently misfires. String interpolation still
      # pins both as build inputs; only their include dirs stay out of the
      # ambient search path so each compile sees exactly the tree it names.
      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.pkg-config
      ];

      phases = [
        {
          name = "compile-sim-observer-plugin-probe";
          script = ''
            set -eu
            cat > observer-probe.c <<'PROBE'
            #include <qemu-plugin.h>
            #include <stdint.h>

            QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

            static void observe(uint64_t current_icount, void *userdata)
            {
              (void)current_icount;
              (void)userdata;
            }

            static uint64_t max_advance(void *userdata)
            {
              (void)userdata;
              return UINT64_MAX;
            }

            QEMU_PLUGIN_EXPORT int
            qemu_plugin_install(qemu_plugin_id_t id,
                                const qemu_info_t *info,
                                int argc,
                                char **argv)
            {
              (void)id;
              (void)info;
              (void)argc;
              (void)argv;
              qemu_plugin_register_sim_shmem_observer_cb(
                  observe, max_advance, 0);
              return 0;
            }
            PROBE

            cflags=$(pkg-config --cflags glib-2.0)
            cc -fPIC -shared -O2 -Wall -Wextra -Werror $cflags \
              -I${qemuPackage}/include observer-probe.c -o observer-probe.so
            if cc -fPIC -shared -O2 -Wall -Wextra -Werror \
              -Werror=implicit-function-declaration $cflags \
              -I${referenceQemu}/include observer-probe.c \
              -o stock-observer-probe.so > stock.stdout 2> stock.stderr; then
              echo "stock QEMU unexpectedly exposed the Crucible sim observer API" >&2
              exit 1
            fi

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            observer_runs_alongside_scheduler_dispatch=true
            observer_boundary=exact-budget-clamped-bql-held
            RESULT
          '';
        }
      ];
    }
