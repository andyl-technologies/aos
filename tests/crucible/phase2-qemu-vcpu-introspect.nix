{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase2.qemuVcpuIntrospect",
  taskIds ? ["T-PATCH-23"],
}: let
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  pluginPackage = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor;

  failures =
    failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" tracePluginSource [
      {
        label = "trace plugin consumes aggregate register export";
        needle = "qemu_plugin_read_vcpu_regs(";
      }
      {
        label = "trace plugin consumes aggregate cursor export";
        needle = "qemu_plugin_rr_cursor(&cursor)";
      }
      {
        label = "trace plugin validates aggregate register schema";
        needle = "canonical_register_schema(";
      }
      {
        label = "trace plugin requires authoritative exact-boundary RR cursor";
        needle = "if (!boundary_rr_cursor_valid)";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackage [
      {
        label = "plugin package probes aggregate register export";
        needle = "qemu_plugin_read_vcpu_regs";
      }
      {
        label = "plugin package probes aggregate cursor export";
        needle = "qemu_plugin_rr_cursor";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes aggregate vCPU introspection check";
        needle = "qemuVcpuIntrospect = import ./phase2-qemu-vcpu-introspect.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU vCPU introspection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-vcpu-introspect";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.glib.dev
        pkgs.glib.tools
        pkgs.grep
        pkgs.pkg-config
        qemuPackage
      ];

      phases = [
        {
          name = "run-qemu-vcpu-introspect-conformance";
          script = ''
            set -eu

            header="${qemuPackage}/include/qemu/qemu-plugin.h"
            test -f "$header"
            grep -q 'qemu_plugin_read_vcpu_regs' "$header"
            grep -q 'qemu_plugin_rr_cursor' "$header"

            cat > aggregate-vcpu-introspection.c <<'PROBE'
            #include <stddef.h>
            #include <stdint.h>
            #include <qemu/qemu-plugin.h>

            int (*read_register_file)(unsigned int, uint8_t *, size_t,
                                      size_t *, uint64_t *) =
                qemu_plugin_read_vcpu_regs;
            int (*read_rr_cursor)(struct qemu_plugin_rr_cursor *) =
                qemu_plugin_rr_cursor;
            PROBE

            cc -std=c11 -Wall -Wextra -Werror \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              -c aggregate-vcpu-introspection.c \
              -o aggregate-vcpu-introspection.o

            mkdir -p "$out"
            nm -D --defined-only ${qemuPackage}/bin/qemu-system-x86_64 \
              > "$out/qemu-system-x86_64.dynamic-symbols"
            grep -E '[[:space:]]qemu_plugin_read_vcpu_regs$' \
              "$out/qemu-system-x86_64.dynamic-symbols"
            grep -E '[[:space:]]qemu_plugin_rr_cursor$' \
              "$out/qemu-system-x86_64.dynamic-symbols"

            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:patch-microtests
            gate=gate:single-vm-fingerprint
            gate=gate:qemu-inert
            atomic_patch=${atomicPatch.file}
            aggregate_register_api=qemu_plugin_read_vcpu_regs
            aggregate_cursor_api=qemu_plugin_rr_cursor
            formal_register_export=qemu_plugin_read_vcpu_regs
            formal_cursor_export=qemu_plugin_rr_cursor
            aggregate_header_probe=true
            aggregate_dynamic_symbols=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
