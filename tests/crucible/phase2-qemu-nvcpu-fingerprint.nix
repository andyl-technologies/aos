{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuNvcpuFingerprint",
  taskIds ? ["T-QEMU-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  nvcpuGuest = import ./phase2-qemu-nvcpu-bios.nix {inherit pkgs;};

  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuGateRoot = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint.rs;
  qemuGateCompare = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/compare.rs;
  qemuGateRun = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/run.rs;
  qemuGateTrace = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/trace.rs;
  qemuGateTypes = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/types.rs;
  qemuGateHook = qemuGateRoot + qemuGateCompare + qemuGateRun + qemuGateTrace + qemuGateTypes;
  qemuGateTraceCli = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-fingerprint.rs;
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  qmpLib = builtins.readFile ../../crates/crucible-qemu/src/qmp.rs;
  qemuGateTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs;
  qemuTraceTest = builtins.readFile ../../crates/crucible-qemu/tests/qemu_trace_fingerprint.rs;
  pluginVcpu = builtins.readFile ../../crates/crucible-qemu-plugin/src/vcpu_introspection.rs;
  qemuTracePlugin = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  nvcpuGuestSource = builtins.readFile ./phase2-qemu-nvcpu-bios.nix;
  pluginIntrospectionCheck = import ./phase2-plugin-vcpu-introspection.nix {inherit pkgs lib;};
  qmpClientCheck = import ./phase2-qemu-qmp-client.nix {inherit pkgs lib;};
  boundaryGate = builtins.readFile ./phase2-qemu-determinism-boundary.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-16 checklist entry";
        needle = "**T-QEMU-16**";
      }
      {
        label = "QEMU-34 all-vCPU register requirement";
        needle = "all N vCPUs' register files";
      }
      {
        label = "QEMU-34 RR cursor requirement";
        needle = "position within `rr_switch_quantum`";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "N-vCPU material export";
        needle = "SingleVmNvcpuFingerprintMaterial";
      }
      {
        label = "N-vCPU contract export";
        needle = "SingleVmNvcpuFingerprintContract";
      }
      {
        label = "QMP topology export";
        needle = "SingleVmQmpVcpuTopology";
      }
      {
        label = "RR cursor export";
        needle = "SingleVmRoundRobinCursor";
      }
      {
        label = "sample digest export";
        needle = "compute_single_vm_sample_rolling_fingerprint";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "plugin N-vCPU protocol snapshot";
        needle = "pub struct PluginNvcpuFingerprintSnapshot";
      }
      {
        label = "plugin register protocol snapshot";
        needle = "pub struct PluginVcpuRegisterSnapshot";
      }
      {
        label = "plugin RR cursor protocol snapshot";
        needle = "pub struct PluginRoundRobinCursorSnapshot";
      }
      {
        label = "plugin snapshot validation error";
        needle = "pub enum PluginNvcpuFingerprintSnapshotError";
      }
      {
        label = "protocol snapshot validates contiguous vCPU set";
        needle = "plugin register set expected vCPU";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/single_vm_fingerprint*.rs" qemuGateHook [
      {
        label = "vCPU register digest type";
        needle = "pub struct SingleVmVcpuRegisterDigest";
      }
      {
        label = "RR cursor type";
        needle = "pub struct SingleVmRoundRobinCursor";
      }
      {
        label = "N-vCPU material type";
        needle = "pub struct SingleVmNvcpuFingerprintMaterial";
      }
      {
        label = "QMP plus plugin material adapter";
        needle = "pub fn from_plugin_introspection_and_qmp";
      }
      {
        label = "adapter consumes validated plugin protocol snapshot";
        needle = "plugin_inputs: &PluginNvcpuFingerprintSnapshot";
      }
      {
        label = "QMP topology type";
        needle = "pub struct SingleVmQmpVcpuTopology";
      }
      {
        label = "launch contract type";
        needle = "pub struct SingleVmNvcpuFingerprintContract";
      }
      {
        label = "scenario N-vCPU constructor";
        needle = "pub fn new_with_nvcpu_contract";
      }
      {
        label = "sample material type";
        needle = "pub struct SingleVmFingerprintSampleMaterial";
      }
      {
        label = "all-vCPU contiguous set validation";
        needle = "N-vCPU fingerprint material must cover exactly vCPUs 0..N";
      }
      {
        label = "scenario vCPU count validation";
        needle = "N-vCPU fingerprint material vCPU count must match scenario -smp N";
      }
      {
        label = "RR cursor bounds validation";
        needle = "round-robin current vCPU must be inside the sampled vCPU set";
      }
      {
        label = "launch RR quantum validation";
        needle = "round-robin switch quantum must match the scenario launch profile";
      }
      {
        label = "rolling digest folds N-vCPU material";
        needle = "sample rolling fingerprint must include canonical N-vCPU material";
      }
      {
        label = "sample digest helper";
        needle = "pub fn compute_single_vm_sample_rolling_fingerprint";
      }
      {
        label = "real QEMU trace importer";
        needle = "pub struct QemuTraceFingerprintImport";
      }
      {
        label = "trace importer rejects incomplete register observations";
        needle = "register arrays must cover exactly the QMP-observed vCPU set";
      }
      {
        label = "trace importer validates the QMP topology";
        needle = "plugin tracked {tracked_vcpus} vCPUs but QMP and launch require";
      }
      {
        label = "trace importer pins plugin-exit logical time";
        needle = "differs from exact horizon";
      }
      {
        label = "trace importer requires plugin exit to be final";
        needle = "record appeared after the terminal plugin stop record";
      }
      {
        label = "trace importer rejects zero component digests";
        needle = ''field `{field}` must be non-zero'';
      }
      {
        label = "first differing sample component enum";
        needle = "pub enum SingleVmFingerprintSampleDifference";
      }
      {
        label = "vCPU register component localization";
        needle = "VcpuRegisterDigest";
      }
      {
        label = "RR cursor component localization";
        needle = "RoundRobinPositionInQuantum";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/qmp.rs" qmpLib [
      {
        label = "typed QMP client";
        needle = "pub struct QmpClient";
      }
      {
        label = "QMP capability negotiation";
        needle = "QMP_CAPABILITIES_COMMAND";
      }
      {
        label = "bounded QMP command timeout";
        needle = "QMP_COMMAND_TIMEOUT";
      }
      {
        label = "typed QMP run-state observation";
        needle = "pub fn query_status";
      }
      {
        label = "typed QMP vCPU topology observation";
        needle = "pub fn query_cpus_fast";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs" qemuGateTest [
      {
        label = "all-vCPU plus RR digest test";
        needle = "gate_single_vm_fingerprint_digest_includes_all_vcpus_and_rr_cursor";
      }
      {
        label = "RR cursor component localization test";
        needle = "gate_single_vm_fingerprint_reports_rr_cursor_component";
      }
      {
        label = "missing vCPU material rejection test";
        needle = "gate_single_vm_fingerprint_rejects_missing_vcpu_material";
      }
      {
        label = "cursor outside sampled vCPUs rejection test";
        needle = "gate_single_vm_fingerprint_rejects_cursor_outside_sampled_vcpus";
      }
      {
        label = "missing launched vCPU rejection test";
        needle = "gate_single_vm_fingerprint_rejects_stream_missing_launched_vcpu";
      }
      {
        label = "wrong RR quantum rejection test";
        needle = "gate_single_vm_fingerprint_rejects_cursor_quantum_drift_from_launch_contract";
      }
      {
        label = "plugin plus QMP adapter test";
        needle = "gate_single_vm_fingerprint_builds_material_from_plugin_and_qmp_inputs";
      }
      {
        label = "adapter test uses protocol snapshot";
        needle = "PluginNvcpuFingerprintSnapshot";
      }
      {
        label = "vCPU register component localization assertion";
        needle = "SingleVmFingerprintSampleDifference::VcpuRegisterDigest { vcpu_id: 1 }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/examples/crucible-qemu-fingerprint.rs" qemuGateTraceCli [
      {
        label = "production trace importer invocation";
        needle = "QemuTraceFingerprintImport::new";
      }
      {
        label = "provisional trace definition";
        needle = "QemuTraceFingerprintDefinition::new";
      }
      {
        label = "production run-twice gate hook invocation";
        needle = "run_single_vm_fingerprint_gate(&mut runner, &scenario)";
      }
      {
        label = "production component localization";
        needle = "first_differing_component=";
      }
      {
        label = "trace-only exact-refinement rejection";
        needle = "instruction-exact rerun and state dumps are unavailable";
      }
      {
        label = "launch and build provenance validation";
        needle = "run provenance ids must be distinct";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/qemu_trace_fingerprint.rs" qemuTraceTest [
      {
        label = "real trace canonicalization test";
        needle = "real_qemu_trace_import_canonicalizes_all_vcpu_rr_ram_and_device_material";
      }
      {
        label = "real trace incompleteness negative test";
        needle = "real_qemu_trace_import_rejects_qmp_topology_or_incomplete_observation";
      }
      {
        label = "real trace vCPU localization test";
        needle = "real_qemu_trace_comparison_localizes_first_vcpu_register_difference";
      }
      {
        label = "logical-time and retired-count separation test";
        needle = "real_qemu_trace_import_accepts_retired_offset_at_exact_observed_horizon";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/vcpu_introspection.rs" pluginVcpu [
      {
        label = "plugin reads N-vCPU inputs";
        needle = "pub fn read_nvcpu_fingerprint_inputs";
      }
      {
        label = "plugin input set";
        needle = "pub struct PluginNvcpuFingerprintInputs";
      }
      {
        label = "plugin converts reader output to protocol snapshot";
        needle = "pub fn to_protocol_snapshot";
      }
      {
        label = "plugin RR cursor";
        needle = "pub struct PluginRoundRobinCursor";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" qemuTracePlugin [
      {
        label = "trace plugin all-vCPU register hashes";
        needle = "register_digests.per_vcpu";
      }
      {
        label = "trace plugin RR current vCPU";
        needle = "qemu_plugin_crucible_rr_current_vcpu";
      }
      {
        label = "trace plugin RR cursor position";
        needle = "qemu_plugin_crucible_rr_cursor_position";
      }
      {
        label = "trace plugin RR quantum";
        needle = "qemu_plugin_crucible_rr_switch_quantum";
      }
      {
        label = "trace plugin requires authoritative exact-boundary RR cursor";
        needle = "if (!boundary_rr_cursor_valid && rr_cursor_required)";
      }
      {
        label = "trace plugin canonical register byte counts";
        needle = "register_file_bytes";
      }
      {
        label = "trace plugin per-vCPU retired counts";
        needle = "register_retired";
      }
      {
        label = "trace plugin versioned schema";
        needle = "crucible.qemu.trace-fingerprint.v6";
      }
      {
        label = "trace plugin register schema hashes";
        needle = "register_schema_digests";
      }
      {
        label = "terminal cursor source";
        needle = "last_executed_instruction";
      }
      {
        label = "same-vCPU cursor reset is not an RR switch";
        needle = "if (rr_current_vcpu == last_rr_current_vcpu)";
      }
      {
        label = "register-readable instruction callbacks";
        needle = "qinsn, on_insn, QEMU_PLUGIN_CB_R_REGS";
      }
      {
        label = "standard FNV-1a 64 offset basis";
        needle = "14695981039346656037ULL";
      }
      {
        label = "order-sensitive device event history";
        needle = "device_event_hash = fnv1a_u64(device_event_hash, event_hash)";
      }
      {
        label = "current serialized device state";
        needle = "qemu_plugin_crucible_device_state_sha256(";
      }
      {
        label = "device-state hash in trace samples";
        needle = "device_state_digest";
      }
      {
        label = "device-state byte count in trace samples";
        needle = "device_state_bytes";
      }
      {
        label = "independent definition-only mode";
        needle = "definition_only=";
      }
      {
        label = "definition mode suppresses translation callbacks";
        needle = "if (!definition_only)";
      }
      {
        label = "definition waits for all configured vCPUs";
        needle = "all_register_sets_initialized()";
      }
      {
        label = "definition record wire kind";
        needle = ''{\"kind\":\"definition\"'';
      }
      {
        label = "definition records pre-execution pause";
        needle = "observed_non_running";
      }
      {
        label = "definition uses completed genesis callback";
        needle = "definition_callback_completed";
      }
      {
        label = "definition has no plugin-exit sampling fallback";
        needle = "genesis definition was incomplete";
      }
      {
        label = "definition records complete genesis RR state";
        needle = "rr_state_status";
      }
      {
        label = "definition records inactive genesis RR cursor explicitly";
        needle = "rr_current_vcpu_present";
      }
      {
        label = "definition records serialized device-state status";
        needle = "device_state_status";
      }
      {
        label = "MMIO read and write values";
        needle = "qemu_plugin_mem_get_value(info)";
      }
      {
        label = "trace-bound launch identity";
        needle = "launch_definition_digest";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-nvcpu-bios.nix" nvcpuGuestSource [
      {
        label = "topology-independent application-processor startup";
        needle = "all excluding self";
      }
      {
        label = "all-vCPU busy workload";
        needle = "ap3_busy:";
      }
      {
        label = "fixed-size reset-vector firmware image";
        needle = "expected 65536";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-determinism-boundary.nix" boundaryGate [
      {
        label = "determinism boundary references N-vCPU check";
        needle = "n_vcpu_fingerprint=checks.crucible.phase2.qemuNvcpuFingerprint";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes N-vCPU fingerprint task check";
        needle = "qemuNvcpuFingerprint = import ./phase2-qemu-nvcpu-fingerprint.nix";
      }
      {
        label = "phase2 exposes typed QMP control check";
        needle = "qemuQmpClient = import ./phase2-qemu-qmp-client.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu N-vCPU fingerprint check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-nvcpu-fingerprint";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
        pkgs.grep
        pkgs.jq
        pkgs.pkg-config
        pkgs.qemu-crucible
        pkgs.crucible-qemu-trace-plugin
        pkgs.rust
        pkgs.sed
        pkgs.socat
      ];

      SMP_GUEST_KERNEL_APPEND = "";
      SMP_GUEST_FIRMWARE = "${nvcpuGuest}/nvcpu-bios.bin";

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
          name = "run-qemu-nvcpu-fingerprint";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cat > "$TMPDIR/qemu-argv-launcher.c" <<'ARGV_LAUNCHER'
            #include <glib.h>
            #include <errno.h>
            #include <inttypes.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>
            #include <unistd.h>

            static void
            hash_u64(GChecksum *checksum, uint64_t value)
            {
              unsigned char encoded[8];

              for (size_t index = 0; index < sizeof(encoded); index++) {
                encoded[sizeof(encoded) - index - 1] = value & 0xffU;
                value >>= 8;
              }
              g_checksum_update(checksum, encoded, sizeof(encoded));
            }

            static void
            hash_framed(GChecksum *checksum, const void *bytes, size_t length)
            {
              hash_u64(checksum, length);
              if (length != 0) {
                g_checksum_update(checksum, bytes, length);
              }
            }

            static void
            hash_segment(GChecksum *checksum,
                         const char *label,
                         const void *bytes,
                         size_t length)
            {
              hash_framed(checksum, label, strlen(label));
              hash_framed(checksum, bytes, length);
            }

            static void
            encode_u64(uint64_t value, unsigned char encoded[8])
            {
              for (size_t index = 0; index < 8; index++) {
                encoded[8 - index - 1] = value & 0xffU;
                value >>= 8;
              }
            }

            static int
            write_prepared_argv(const char *path, char *const child_argv[])
            {
              static const char domain[] = "crucible.qemu.raw-unix-argv.v2";
              GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
              unsigned char encoded[8];
              uint64_t child_argc = 0;
              uint64_t raw_bytes = 0;
              FILE *output;

              if (checksum == NULL) {
                return -1;
              }
              while (child_argv[child_argc] != NULL) {
                const size_t length = strlen(child_argv[child_argc]);

                if (UINT64_MAX - raw_bytes < length || child_argc == UINT64_MAX) {
                  g_checksum_free(checksum);
                  return -1;
                }
                raw_bytes += length;
                child_argc++;
              }
              hash_framed(checksum, domain, sizeof(domain) - 1);
              encode_u64(child_argc, encoded);
              hash_segment(checksum, "argc", encoded, sizeof(encoded));
              for (uint64_t index = 0; index < child_argc; index++) {
                encode_u64(index, encoded);
                hash_segment(checksum, "argv-index", encoded, sizeof(encoded));
                hash_segment(checksum,
                             "argv-value",
                             child_argv[index],
                             strlen(child_argv[index]));
              }

              output = fopen(path, "wb");
              if (output == NULL) {
                g_checksum_free(checksum);
                return -1;
              }
              if (fprintf(output,
                          "{\"schema\":\"crucible.qemu.prepared-process-argv.v1\","
                          "\"process_argv_argc\":%" PRIu64 ","
                          "\"process_argv_raw_bytes\":%" PRIu64 ","
                          "\"process_argv_digest\":\"%s\"}\n",
                          child_argc,
                          raw_bytes,
                          g_checksum_get_string(checksum)) < 0) {
                fclose(output);
                g_checksum_free(checksum);
                return -1;
              }
              if (fclose(output) != 0) {
                g_checksum_free(checksum);
                return -1;
              }
              g_checksum_free(checksum);
              return 0;
            }

            int
            main(int argc, char **argv)
            {
              if (argc < 3) {
                fprintf(stderr, "usage: %s EXPECTED QEMU [ARG...]\n", argv[0]);
                return 2;
              }
              if (write_prepared_argv(argv[1], &argv[2]) != 0) {
                fprintf(stderr, "failed to persist prepared argv evidence\n");
                return 2;
              }
              execv(argv[2], &argv[2]);
              fprintf(stderr, "execv failed: %s\n", strerror(errno));
              return 2;
            }
            ARGV_LAUNCHER
            argv_cflags=$(pkg-config --cflags glib-2.0)
            argv_libs=$(pkg-config --libs glib-2.0)
            cc -O2 -Wall -Wextra -Werror $argv_cflags \
              "$TMPDIR/qemu-argv-launcher.c" $argv_libs \
              -o "$TMPDIR/qemu-argv-launcher"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-nvcpu-fingerprint-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test gate_single_vm_fingerprint \
              --test qemu_trace_fingerprint \
              -- --test-threads=1

            cargo build \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-nvcpu-fingerprint-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --example crucible-qemu-fingerprint

            cd "$TMPDIR"
            qemu_pid=""
            jitter_pids=""
            fingerprint_cli="$TMPDIR/crucible-qemu-nvcpu-fingerprint-target/debug/examples/crucible-qemu-fingerprint"
            argv_launcher="$TMPDIR/qemu-argv-launcher"
            cadence=4000000
            # The reset-vector BIOS starts all APs directly and keeps every
            # vCPU in a register-mutating loop. A 21-million-instruction horizon
            # covers sustained execution while remaining distinct from cadence.
            horizon=21000000
            quantum=4096
            memory_mib=128
            qemu_binary="${pkgs.qemu-crucible}/bin/qemu-system-x86_64"
            trace_plugin="${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so"
            seed="$TMPDIR/nvcpu-seed.bin"
            printf 'crucible-phase2-nvcpu-seed-v1\n' > "$seed"
            qemu_build_digest=$(sha256sum "$qemu_binary" | cut -d ' ' -f 1)
            trace_plugin_build_digest=$(sha256sum "$trace_plugin" | cut -d ' ' -f 1)
            firmware_digest=$(sha256sum "$SMP_GUEST_FIRMWARE" | cut -d ' ' -f 1)
            seed_digest=$(sha256sum "$seed" | cut -d ' ' -f 1)
            guest_image_digest=$(printf '%s\n' \
              "firmware=$firmware_digest" \
              | sha256sum | cut -d ' ' -f 1)
            injected_input_sequence_digest=$(printf '%s\n' \
              'crucible.injected-input-sequence.v1' \
              'events=0' \
              | sha256sum | cut -d ' ' -f 1)
            launch_definition_digest=$(printf '%s\n' \
              'nodefaults=true' 'no_user_config=true' 'display=none' 'monitor=none' \
              'machine=q35' "firmware_digest=$firmware_digest" \
              'accel=sim,thread=single' \
              "icount=shift=0,sleep=off,align=off,rr_switch_quantum=$quantum" \
              'cpu=qemu64,-rdrand,-rdseed' "memory_mib=$memory_mib" 'smp=4' \
              'rtc=base=2026-01-01T00:00:00,clock=vm' 'seed=0x0010c016' \
              "fw_cfg=opt/crucible/seed,seed_digest=$seed_digest" \
              'rng_object=rng-builtin,id=crucible-rng0' \
              'rng_device=virtio-rng-pci,rng=crucible-rng0' \
              "qemu_build_digest=$qemu_build_digest" \
              "trace_plugin_build_digest=$trace_plugin_build_digest" \
              "seed_digest=$seed_digest" \
              "plugin_cadence=$cadence" "plugin_stop_at=$horizon" \
              'plugin_extended=on' 'plugin_mem_events=on' 'plugin_rr_switch_events=on' \
              'plugin_vcpus=4' 'serial_backend=file' 'qmp=unix-server-wait-off' \
              'no_shutdown=true' 'no_reboot=true' \
              | sha256sum | cut -d ' ' -f 1)

            zero_sha256=0000000000000000000000000000000000000000000000000000000000000000
            for digest in \
              "$qemu_build_digest" "$trace_plugin_build_digest" \
              "$firmware_digest" "$seed_digest" \
              "$guest_image_digest" "$injected_input_sequence_digest" \
              "$launch_definition_digest"; do
              printf '%s\n' "$digest" | grep -E -q '^[0-9a-f]{64}$' \
                || { echo "FAIL: invalid N-vCPU launch digest: $digest" >&2; exit 1; }
              [ "$digest" != "$zero_sha256" ] \
                || { echo "FAIL: zero N-vCPU launch digest is not accepted" >&2; exit 1; }
            done

            cleanup_qemu() {
              if [ -n "$qemu_pid" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
                qemu_pid=""
              fi
            }

            stop_jitter() {
              for pid in $jitter_pids; do
                kill "$pid" 2>/dev/null || true
              done
              for pid in $jitter_pids; do
                wait "$pid" 2>/dev/null || true
              done
              jitter_pids=""
            }

            start_jitter() {
              i=0
              while [ "$i" -lt 3 ]; do
                yes > /dev/null &
                jitter_pids="$jitter_pids $!"
                i=$((i + 1))
              done
            }

            fail() {
              echo "FAIL: $*" >&2
              cleanup_qemu
              stop_jitter
              exit 1
            }

            [ -x "$fingerprint_cli" ] || fail "fingerprint importer executable was not built"

            trap 'cleanup_qemu; stop_jitter' EXIT

            qmp_cmd() {
              socket="$1"
              request="$2"
              response="$3"
              response_err="$response.err"

              {
                printf '{"execute":"qmp_capabilities"}\r\n'
                printf '%s\r\n' "$request"
              } | socat -T 1 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

              if [ ! -s "$response" ]; then
                cat "$response_err" >&2
                return 1
              fi

              if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                cat "$response" >&2
                return 1
              fi
              jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
            }

            wait_for_socket() {
              socket="$1"
              waited=0
              while [ "$waited" -lt 600 ]; do
                if [ -S "$socket" ]; then
                  return 0
                fi
                sleep 0.1
                waited=$((waited + 1))
              done
              return 1
            }

            wait_for_stop_at_pause() {
              label="$1"
              qmp_socket="$2"
              allow_prelaunch="''${3:-false}"
              waited=0
              qmp_failures=0
              while [ "$waited" -lt 24000 ]; do
                if qmp_cmd "$qmp_socket" '{"execute":"query-status"}' "$TMPDIR/qmp-status-$label.json"; then
                  qmp_failures=0
                  status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-status-$label.json")
                  case "$status" in
                    paused)
                      return 0
                      ;;
                    prelaunch)
                      if [ "$allow_prelaunch" = true ]; then
                        return 0
                      fi
                      ;;
                    running)
                      ;;
                    *)
                      cat "$TMPDIR/qmp-status-$label.json" >&2
                      return 1
                      ;;
                  esac
                else
                  qmp_failures=$((qmp_failures + 1))
                  if [ "$qmp_failures" -ge 10 ]; then
                    if [ -f "$TMPDIR/qmp-status-$label.json" ]; then
                      cat "$TMPDIR/qmp-status-$label.json" >&2
                    fi
                    return 1
                  fi
                fi
                sleep 0.1
                waited=$((waited + 1))
              done
              return 1
            }

            wait_for_definition_record() {
              trace="$1"
              waited=0
              while [ "$waited" -lt 600 ]; do
                if [ -s "$trace" ] &&
                  jq -e -s '[.[] | select(.kind == "definition")] | length == 1' \
                    "$trace" >/dev/null 2>&1; then
                  return 0
                fi
                sleep 0.1
                waited=$((waited + 1))
              done
              return 1
            }

            run_definition() {
              label=definition
              qmp_socket="$TMPDIR/qmp-nvcpu-definition.sock"
              trace="$TMPDIR/qemu-nvcpu-definition.jsonl"
              prepared_argv="$TMPDIR/prepared-argv-definition.json"
              rm -f "$qmp_socket" "$trace" "$prepared_argv"

              timeout 2400 "$argv_launcher" "$prepared_argv" "$qemu_binary" \
                -nodefaults \
                -no-user-config \
                -display none \
                -monitor none \
                -S \
                -machine q35 \
                -bios "$SMP_GUEST_FIRMWARE" \
                -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off,rr_switch_quantum="$quantum" \
                -cpu qemu64,-rdrand,-rdseed \
                -m "$memory_mib" \
                -smp 4 \
                -rtc base=2026-01-01T00:00:00,clock=vm \
                -seed 0x0010c016 \
                -fw_cfg name=opt/crucible/seed,file="$seed" \
                -object rng-builtin,id=crucible-rng0 \
                -device virtio-rng-pci,rng=crucible-rng0 \
                -chardev file,id=serial0,path="$TMPDIR/serial-definition.log" \
                -serial chardev:serial0 \
                -qmp "unix:$qmp_socket,server=on,wait=off" \
                -plugin "$trace_plugin",out="$trace",definition_only=on,vcpus=4,launch_digest="$launch_definition_digest",qemu_build_digest="$qemu_build_digest",plugin_build_digest="$trace_plugin_build_digest" \
                -no-shutdown \
                -no-reboot &
              qemu_pid="$!"

              wait_for_socket "$qmp_socket" || fail "QMP socket did not appear for the definition preflight"
              wait_for_stop_at_pause "$label" "$qmp_socket" true \
                || fail "definition-only QEMU did not remain non-running before guest execution"
              qmp_cmd "$qmp_socket" '{"execute":"query-cpus-fast"}' "$TMPDIR/qmp-cpus-definition.json" \
                || fail "definition preflight QMP topology query failed"
              jq -e -s '[.[] | select(.return | type == "array")][-1].return | map(."cpu-index") | sort == [0,1,2,3]' \
                "$TMPDIR/qmp-cpus-definition.json" >/dev/null \
                || fail "definition preflight did not report exact CPU indexes 0..3"
              wait_for_definition_record "$trace" \
                || fail "definition preflight genesis callback did not complete"
              qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-definition.json" || true
              wait "$qemu_pid" || fail "definition-only QEMU exited unsuccessfully"
              qemu_pid=""
              jq -e -s \
                --slurpfile prepared "$prepared_argv" \
                --argjson quantum "$quantum" \
                --arg launch_definition_digest "$launch_definition_digest" \
                --arg qemu_build_digest "$qemu_build_digest" \
                --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
                '($prepared[0]) as $argv
                 | length == 1 and (.[0] | (
                  .kind == "definition"
                  and .schema == "crucible.qemu.trace-fingerprint.v6"
                  and .process_argv_status == 0
                  and .process_argv_attestation_version == 2
                  and .process_argv_encoding == "raw-unix-argv-v2"
                  and .process_argv_argc > 0
                  and .process_argv_raw_bytes > 0
                  and (.process_argv_digest | test("^[0-9a-f]{64}$"))
                  and .process_argv_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and $argv.schema == "crucible.qemu.prepared-process-argv.v1"
                  and .process_argv_argc == $argv.process_argv_argc
                  and .process_argv_raw_bytes == $argv.process_argv_raw_bytes
                  and .process_argv_digest == $argv.process_argv_digest
                  and .definition_only == true
                  and .definition_pause_requested == true
                  and .definition_callback_completed == true
                  and .definition_pause_status == 0
                  and .observed_non_running == true
                  and .observed_icount == 0
                  and .retired == 0
                  and .tracked_vcpus == 4
                  and .rr_switch_quantum == $quantum
                  and .rr_state_status == 0
                  and (.rr_current_vcpu_present | type == "boolean")
                  and (.rr_current_vcpu | type == "number")
                  and .rr_current_vcpu >= 0
                  and .rr_current_vcpu < 4
                  and (.rr_current_vcpu_present or .rr_current_vcpu == 0)
                  and .rr_cursor_position == 0
                  and .launch_definition_digest == $launch_definition_digest
                  and .qemu_build_digest == $qemu_build_digest
                  and .trace_plugin_build_digest == $trace_plugin_build_digest
                  and .ram_bytes > 0
                  and .ram_status == 0
                  and (.ram_digest | test("^[0-9a-f]{64}$"))
                  and .ram_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and .device_state_complete == true
                  and .device_state_status == 0
                  and .device_state_schema_status == 0
                  and .device_state_failures == 0
                  and .device_state_bytes > 0
                  and .device_state_sections > 0
                  and (.device_state_digest | test("^[0-9a-f]{64}$"))
                  and .device_state_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and (.device_state_schema_digest | test("^[0-9a-f]{64}$"))
                  and .device_state_schema_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and .sample_register_failures == 0
                  and .register_read_failures == 0
                  and (.register_counts | length) == 4
                  and all(.register_counts[]; . > 0)
                  and (.register_file_bytes | length) == 4
                  and all(.register_file_bytes[]; . > 0)
                  and (.register_digests | length) == 4
                  and all(.register_digests[];
                    test("^[0-9a-f]{64}$")
                    and . != "0000000000000000000000000000000000000000000000000000000000000000")
                  and (.register_schema_digests | length) == 4
                  and all(.register_schema_digests[];
                    test("^[0-9a-f]{64}$")
                    and . != "0000000000000000000000000000000000000000000000000000000000000000")
                ))' "$trace" >/dev/null \
                || fail "definition-only QEMU did not emit one complete paused preflight"
            }

            run_one() {
              label="$1"
              qmp_socket="$TMPDIR/qmp-nvcpu-$label.sock"
              trace="$TMPDIR/qemu-nvcpu-trace-$label.jsonl"
              prepared_argv="$TMPDIR/prepared-argv-$label.json"
              rm -f "$qmp_socket" "$trace" "$prepared_argv"

              timeout 2400 "$argv_launcher" "$prepared_argv" "$qemu_binary" \
                -nodefaults \
                -no-user-config \
                -display none \
                -monitor none \
                -machine q35 \
                -bios "$SMP_GUEST_FIRMWARE" \
                -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off,rr_switch_quantum="$quantum" \
                -cpu qemu64,-rdrand,-rdseed \
                -m "$memory_mib" \
                -smp 4 \
                -rtc base=2026-01-01T00:00:00,clock=vm \
                -seed 0x0010c016 \
                -fw_cfg name=opt/crucible/seed,file="$seed" \
                -object rng-builtin,id=crucible-rng0 \
                -device virtio-rng-pci,rng=crucible-rng0 \
                -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
                -serial chardev:serial0 \
                -qmp "unix:$qmp_socket,server=on,wait=off" \
                -plugin "$trace_plugin",out="$trace",cadence="$cadence",stop_at="$horizon",extended=on,mem_events=on,rr_switch_events=on,vcpus=4,launch_digest="$launch_definition_digest",qemu_build_digest="$qemu_build_digest",plugin_build_digest="$trace_plugin_build_digest" \
                -no-shutdown \
                -no-reboot &
              qemu_pid="$!"

              wait_for_socket "$qmp_socket" || fail "QMP socket did not appear for run $label"
              wait_for_stop_at_pause "$label" "$qmp_socket" \
                || fail "QEMU run $label did not pause at the N-vCPU horizon"
              qmp_cmd "$qmp_socket" '{"execute":"query-cpus-fast"}' "$TMPDIR/qmp-cpus-$label.json" \
                || fail "QMP topology query failed for run $label"
              qmp_vcpus=$(jq -r -s '[.[] | select(.return | type == "array")][-1].return | length' "$TMPDIR/qmp-cpus-$label.json")
              [ "$qmp_vcpus" = 4 ] || fail "QMP reported $qmp_vcpus vCPUs for run $label"
              jq -e -s '[.[] | select(.return | type == "array")][-1].return | map(."cpu-index") | sort == [0,1,2,3]' \
                "$TMPDIR/qmp-cpus-$label.json" >/dev/null \
                || fail "QMP did not report exact CPU indexes 0..3 for run $label"
              qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
              wait "$qemu_pid" || fail "QEMU run $label exited unsuccessfully"
              qemu_pid=""

              if ! jq -e -s \
                --slurpfile prepared "$prepared_argv" \
                --argjson cadence "$cadence" \
                --argjson horizon "$horizon" \
                --argjson quantum "$quantum" \
                --slurpfile definition "$TMPDIR/qemu-nvcpu-definition.jsonl" \
                '
                ([$definition[] | select(.kind == "definition")][0]) as $contract
                | ($prepared[0]) as $argv
                | [ .[] | select((.kind // "sample") == "sample" and .final != true) ] as $samples
                | [ .[] | select(.kind == "rr_switch") ] as $switches
                | [ .[] | select((.kind // "sample") == "sample" and .final == true) ] as $finals
                | ($samples | last) as $horizon_sample
                | ($samples | map(.observed_icount)) == ([range($cadence; $horizon; $cadence)] + [$horizon])
                and all($samples[]; (
                  .schema == "crucible.qemu.trace-fingerprint.v6"
                  and .process_argv_status == 0
                  and .process_argv_attestation_version == 2
                  and .process_argv_encoding == "raw-unix-argv-v2"
                  and .process_argv_argc > 0
                  and .process_argv_raw_bytes > 0
                  and (.process_argv_digest | test("^[0-9a-f]{64}$"))
                  and .process_argv_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and $argv.schema == "crucible.qemu.prepared-process-argv.v1"
                  and .process_argv_argc == $argv.process_argv_argc
                  and .process_argv_raw_bytes == $argv.process_argv_raw_bytes
                  and .process_argv_digest == $argv.process_argv_digest
                  and .launch_definition_digest != null
                  and .qemu_build_digest != null
                  and .trace_plugin_build_digest != null
                  and .tracked_vcpus == 4
                  and .rr_switch_quantum == $quantum
                  and .rr_cursor_valid == true
                  and .rr_cursor_source == "live_instruction"
                  and .memory_events_enabled == true
                  and .device_event_capture == true
                  and .device_event_hash != null
                  and .device_state_complete == true
                  and .device_state_status == 0
                  and .device_state_schema_status == 0
                  and .device_state_failures == 0
                  and .device_state_bytes > 0
                  and .device_state_sections == $contract.device_state_sections
                  and .device_state_schema_digest == $contract.device_state_schema_digest
                  and .observed_icount >= .retired
                  and .memory_events > 0
                  and .ram_bytes > 0
                  and .ram_status == 0
                  and .sample_register_failures == 0
                  and .register_read_failures == 0
                  and (.register_digests | length) == 4
                  and all(.register_digests[];
                    test("^[0-9a-f]{64}$")
                    and . != "0000000000000000000000000000000000000000000000000000000000000000")
                  and (.register_counts | length) == 4
                  and all(.register_counts[]; . > 0)
                  and (.register_file_bytes | length) == 4
                  and all(.register_file_bytes[]; . > 0)
                  and .register_schema_digests == $contract.register_schema_digests
                  and (.register_retired | length) == 4
                  and (.register_retired | add) == .retired
                  and .rr_current_vcpu >= 0
                  and .rr_current_vcpu < 4
                  and .rr_cursor_position >= 0
                  and .rr_cursor_position < .rr_switch_quantum
                  and (.ram_digest | test("^[0-9a-f]{64}$"))
                  and .ram_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and (.device_state_digest | test("^[0-9a-f]{64}$"))
                  and .device_state_digest != "0000000000000000000000000000000000000000000000000000000000000000"
                  and .device_event_hash != "0000000000000000"
                ))
                and ($horizon_sample | (
                  .observed_icount == $horizon
                  and .trigger == "event"
                  and .event_boundary == "horizon-advance"
                  and all(.register_retired[]; . > 0)
                  and .io_events > 0
                ))
                and ($finals | length) == 1
                and ($finals[0] | (
                  .final == true
                  and .stop_requested == true
                  and .stop_at == $horizon
                  and .observed_icount == $horizon
                  and .retired == $horizon_sample.retired
                  and .rr_cursor_valid == true
                  and .rr_cursor_source == "last_executed_instruction"
                  and .process_argv_status == 0
                  and .process_argv_attestation_version == 2
                  and .process_argv_encoding == "raw-unix-argv-v2"
                  and .process_argv_argc == $argv.process_argv_argc
                  and .process_argv_raw_bytes == $argv.process_argv_raw_bytes
                  and .process_argv_digest == $argv.process_argv_digest
                ))
                and ($switches | length) > 0
                and all($switches[]; (
                  .from_vcpu != .to_vcpu
                  and .previous_rr_switch_quantum == $quantum
                  and .rr_switch_quantum == $quantum
                  and .rr_cursor_position >= 0
                  and .rr_cursor_position < $quantum
                ))
              ' "$trace" >/dev/null; then
                jq -c -s --argjson quantum "$quantum" '
                  [ .[] | select((.kind // "sample") == "sample") ] as $samples
                  | [ .[] | select(.kind == "rr_switch") ] as $switches
                  | {
                      samples: [
                        $samples[]
                        | {
                            final: (.final // false),
                            trigger: (.trigger // null),
                            event_boundary: (.event_boundary // null),
                            observed_icount,
                            retired,
                            register_retired,
                            register_counts,
                            register_file_bytes,
                            rr_current_vcpu,
                            rr_cursor_position,
                            memory_events,
                            io_events,
                            device_state_status,
                            device_state_schema_status,
                            device_state_failures,
                            sample_register_failures,
                            register_read_failures
                          }
                      ],
                      rr_switch_count: ($switches | length),
                      invalid_rr_switch_count: (
                        [
                          $switches[]
                          | select(
                              .from_vcpu == .to_vcpu
                              or .previous_rr_switch_quantum != $quantum
                              or .rr_switch_quantum != $quantum
                              or .rr_cursor_position < 0
                              or .rr_cursor_position >= $quantum
                            )
                        ]
                        | length
                      )
                    }
                ' "$trace" >&2
                fail "real QEMU N-vCPU trace $label failed structural assertions"
              fi

              case "$label" in
                a) ordinal=first ;;
                b) ordinal=second ;;
                *) fail "unknown run label $label" ;;
              esac
              jq -n \
                --slurpfile prepared "$prepared_argv" \
                --arg schema 'crucible.qemu.trace-run-provenance.v2' \
                --arg ordinal "$ordinal" \
                --arg run_id "qemu-nvcpu-$label" \
                --arg launch_definition_digest "$launch_definition_digest" \
                --arg qemu_build_digest "$qemu_build_digest" \
                --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
                '($prepared[0]) as $argv
                 | {schema:$schema,ordinal:$ordinal,run_id:$run_id,
                    launch_definition_digest:$launch_definition_digest,
                    qemu_build_digest:$qemu_build_digest,
                    trace_plugin_build_digest:$trace_plugin_build_digest,
                    process_argv_argc:$argv.process_argv_argc,
                    process_argv_raw_bytes:$argv.process_argv_raw_bytes,
                    process_argv_digest:$argv.process_argv_digest}' \
                > "$TMPDIR/provenance-$label.json"
            }

            run_definition
            run_one a
            start_jitter
            run_one b
            stop_jitter

            jq -n \
              --slurpfile trace "$TMPDIR/qemu-nvcpu-definition.jsonl" \
              --slurpfile prepared "$TMPDIR/prepared-argv-definition.json" \
              --arg schema 'crucible.qemu.trace-comparison-contract.v2' \
              --arg node 'qemu-nvcpu-gate' \
              --argjson cadence_icount "$cadence" \
              --argjson horizon_icount "$horizon" \
              --argjson rr_switch_quantum "$quantum" \
              --arg launch_definition_digest "$launch_definition_digest" \
              --arg guest_image_digest "$guest_image_digest" \
              --arg kernel_cmdline "$SMP_GUEST_KERNEL_APPEND" \
              --arg seed_digest "$seed_digest" \
              --arg injected_input_sequence_digest "$injected_input_sequence_digest" \
              --arg qemu_build_digest "$qemu_build_digest" \
              --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
              '([$trace[] | select(.kind == "definition")][0]) as $sample
               | ($prepared[0]) as $argv
               | {schema:$schema,node:$node,cadence_icount:$cadence_icount,horizon_icount:$horizon_icount,
                  rr_switch_quantum:$rr_switch_quantum,baseline_ram_bytes:$sample.ram_bytes,
                  device_state_sections:$sample.device_state_sections,
                  device_state_schema_digest:$sample.device_state_schema_digest,
                  register_counts:$sample.register_counts,
                  register_file_bytes:$sample.register_file_bytes,
                  register_schema_digests:$sample.register_schema_digests,
                  launch_definition_digest:$launch_definition_digest,
                  guest_image_digest:$guest_image_digest,
                  kernel_cmdline:$kernel_cmdline,
                  seed_digest:$seed_digest,
                  injected_input_sequence_digest:$injected_input_sequence_digest,
                  qemu_build_digest:$qemu_build_digest,
                  trace_plugin_build_digest:$trace_plugin_build_digest,
                  process_argv_argc:$argv.process_argv_argc,
                  process_argv_raw_bytes:$argv.process_argv_raw_bytes,
                  process_argv_digest:$argv.process_argv_digest}' \
              > "$TMPDIR/fingerprint-contract.json"

            if ! "$fingerprint_cli" \
              "$TMPDIR/fingerprint-contract.json" \
              "$TMPDIR/qemu-nvcpu-definition.jsonl" \
              "$TMPDIR/qmp-cpus-a.json" "$TMPDIR/provenance-a.json" \
              "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
              "$TMPDIR/qmp-cpus-b.json" "$TMPDIR/provenance-b.json" \
              "$TMPDIR/qemu-nvcpu-trace-b.jsonl" \
              > "$TMPDIR/fingerprint-compare.result"; then
              for label in a b; do
                jq -c --arg label "$label" '
                  select(
                    (.kind // "sample") == "sample"
                    and .final != true
                  )
                  | {
                      run: $label,
                      observed_icount,
                      retired,
                      register_retired,
                      register_digests,
                      rr_current_vcpu,
                      rr_cursor_position,
                      ram_digest,
                      device_state_digest,
                      memory_events,
                      io_events
                    }
                ' "$TMPDIR/qemu-nvcpu-trace-$label.jsonl" >&2
              done
              fail "canonical real-QEMU N-vCPU fingerprint streams differed"
            fi

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .register_digests[1] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              else .
              end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/qemu-nvcpu-trace-mutated.jsonl"
            if "$fingerprint_cli" \
              "$TMPDIR/fingerprint-contract.json" \
              "$TMPDIR/qemu-nvcpu-definition.jsonl" \
              "$TMPDIR/qmp-cpus-a.json" "$TMPDIR/provenance-a.json" \
              "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
              "$TMPDIR/qmp-cpus-b.json" "$TMPDIR/provenance-b.json" \
              "$TMPDIR/qemu-nvcpu-trace-mutated.jsonl" \
              > "$TMPDIR/fingerprint-negative.out" \
              2> "$TMPDIR/fingerprint-negative.err"; then
              fail "mutated vCPU register trace unexpectedly compared equal"
            fi
            last_sample_index=$(((horizon - 1) / cadence))
            previous_icount=$(((horizon - 1) / cadence * cadence))
            grep -q "^first_differing_sample=$last_sample_index\$" "$TMPDIR/fingerprint-negative.err"
            grep -q "^previous_matching_icount=$previous_icount\$" "$TMPDIR/fingerprint-negative.err"
            grep -q "^first_different_icount=$horizon\$" "$TMPDIR/fingerprint-negative.err"
            grep -q '^first_differing_component=vcpu_register_digest\[1\]$' "$TMPDIR/fingerprint-negative.err"
            grep -q "^bisection_window=$previous_icount..$horizon\$" "$TMPDIR/fingerprint-negative.err"

            expect_cli_failure() {
              label="$1"
              qmp_b="$2"
              trace_b="$3"
              expected="$4"
              if "$fingerprint_cli" \
                "$TMPDIR/fingerprint-contract.json" \
                "$TMPDIR/qemu-nvcpu-definition.jsonl" \
                "$TMPDIR/qmp-cpus-a.json" "$TMPDIR/provenance-a.json" \
                "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
                "$qmp_b" "$TMPDIR/provenance-b.json" "$trace_b" \
                > "$TMPDIR/$label.out" 2> "$TMPDIR/$label.err"; then
                fail "$label negative control unexpectedly passed"
              fi
              grep -q "$expected" "$TMPDIR/$label.err" \
                || fail "$label negative control did not report $expected"
            }

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .rr_current_vcpu = ((.rr_current_vcpu + 1) % 4)
                | .vcpu = .rr_current_vcpu
              else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-rr-mutated.jsonl"
            expect_cli_failure rr-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-rr-mutated.jsonl" '^first_differing_component=rr_current_vcpu$'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .register_retired[0] += 1 | .register_retired[1] -= 1
              else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-retired-mutated.jsonl"
            expect_cli_failure retired-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-retired-mutated.jsonl" '^first_differing_component=vcpu_retired_instruction_count\[0\]$'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .ram_digest = "0000000000000000000000000000000000000000000000000000000000000001" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-ram-mutated.jsonl"
            expect_cli_failure ram-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-ram-mutated.jsonl" '^first_differing_component=guest_memory_digest$'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .device_state_digest = "0000000000000000000000000000000000000000000000000000000000000002" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-device-mutated.jsonl"
            expect_cli_failure device-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-device-mutated.jsonl" '^first_differing_component=device_state_digest$'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .register_digests[0] = "0000000000000000000000000000000000000000000000000000000000000000" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-zero-register.jsonl"
            expect_cli_failure zero-register-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-zero-register.jsonl" 'field `register_digests\[0\]` must be non-zero'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .ram_digest = "0000000000000000000000000000000000000000000000000000000000000000" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-zero-ram.jsonl"
            expect_cli_failure zero-ram-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-zero-ram.jsonl" 'field `ram_digest` must be non-zero'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .device_state_digest = "0000000000000000000000000000000000000000000000000000000000000000" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-zero-device.jsonl"
            expect_cli_failure zero-device-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-zero-device.jsonl" 'field `device_state_digest` must be non-zero'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .device_state_schema_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-device-schema-mutated.jsonl"
            expect_cli_failure device-schema-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-device-schema-mutated.jsonl" 'device-state section/schema coverage differs from the independent preflight'

            jq -c --argjson cadence "$cadence" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $cadence)
              then .observed_icount += 1 else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-cadence-mutated.jsonl"
            expect_cli_failure cadence-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-cadence-mutated.jsonl" "periodic sample icount $((cadence + 1)) does not match expected $cadence"

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final == true)
              then .observed_icount = ($horizon + 1) else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-horizon-mutated.jsonl"
            expect_cli_failure horizon-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-horizon-mutated.jsonl" 'differs from exact horizon'

            jq -c --argjson horizon "$horizon" '
              if ((.kind // "sample") == "sample" and .final != true and .observed_icount == $horizon)
              then .ram_bytes += 1 else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-ram-bytes-mutated.jsonl"
            expect_cli_failure ram-bytes-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-ram-bytes-mutated.jsonl" 'guest RAM observation differs from the independent preflight'

            jq -c 'if (.return | type == "array") then .return[3]."cpu-index" = 2 else . end' \
              "$TMPDIR/qmp-cpus-b.json" > "$TMPDIR/qmp-topology-mutated.json"
            expect_cli_failure topology-reject "$TMPDIR/qmp-topology-mutated.json" \
              "$TMPDIR/qemu-nvcpu-trace-b.jsonl" 'QMP CPU indexes must be the exact sorted set'

            mkdir -p "$out"
            cp "$TMPDIR/qemu-nvcpu-definition.jsonl" "$out/qemu-nvcpu-definition.jsonl"
            # The importer fingerprints the exact horizon sample and consumes
            # only stop/cursor fields from the post-QMP terminal record. QMP
            # quit can perturb non-authoritative device bookkeeping, so retain
            # the certified horizon values in the installed diagnostic copy.
            for label in a b; do
              trace="$TMPDIR/qemu-nvcpu-trace-$label.jsonl"
              horizon_device_digest=$(
                jq -r --argjson horizon "$horizon" '
                  select(
                    (.kind // "sample") == "sample"
                    and .final != true
                    and .observed_icount == $horizon
                  )
                  | .device_state_digest
                ' "$trace"
              )
              horizon_diagnostic_extended_fnv=$(
                jq -r --argjson horizon "$horizon" '
                  select(
                    (.kind // "sample") == "sample"
                    and .final != true
                    and .observed_icount == $horizon
                  )
                  | .diagnostic_extended_fnv
                ' "$trace"
              )
              jq -c \
                --arg device_state_digest "$horizon_device_digest" \
                --arg diagnostic_extended_fnv "$horizon_diagnostic_extended_fnv" \
                '
                  if ((.kind // "sample") == "sample" and .final == true)
                  then
                    .device_state_digest = $device_state_digest
                    | .diagnostic_extended_fnv = $diagnostic_extended_fnv
                  else .
                  end
                ' "$trace" > "$out/qemu-nvcpu-trace-$label.jsonl"
            done
            # QMP reports host thread IDs alongside the guest CPU topology.
            # They are runtime allocation details, not fingerprint evidence.
            for label in a b definition; do
              jq -c '
                if (.return | type == "array")
                then .return |= map(del(."thread-id"))
                else .
                end
              ' "$TMPDIR/qmp-cpus-$label.json" > "$out/qmp-cpus-$label.json"
            done
            cp "$TMPDIR/fingerprint-compare.result" "$out/fingerprint-compare.result"
            cp "$TMPDIR/fingerprint-negative.err" "$out/fingerprint-negative.err"
            cp "$TMPDIR/fingerprint-contract.json" "$out/fingerprint-contract.json"
            cp "$TMPDIR/provenance-a.json" "$out/provenance-a.json"
            cp "$TMPDIR/provenance-b.json" "$out/provenance-b.json"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            grep -q '"tracked_vcpus":4' "$out/qemu-nvcpu-trace-a.jsonl"
            grep -q '"rr_switch_quantum":4096' "$out/qemu-nvcpu-trace-a.jsonl"
            grep -q '^PASS$' "$out/fingerprint-compare.result"
            grep -q '^status=partial$' "$out/fingerprint-compare.result"
            grep -q '^definition_status=canonical-preflight-pinned$' "$out/fingerprint-compare.result"
            grep -q '^comparison=canonical-rust-stream$' "$out/fingerprint-compare.result"
            grep -q '^gate_hook=run_single_vm_fingerprint_gate$' "$out/fingerprint-compare.result"
            grep -q '^first_differing_component=vcpu_register_digest\[1\]$' "$out/fingerprint-negative.err"
            plugin_result="${pluginIntrospectionCheck}/result"
            qmp_result="${qmpClientCheck}/result"
            grep -q '^PASS$' "$plugin_result"
            grep -q '^protocol_snapshot=crucible-protocol::PluginNvcpuFingerprintSnapshot$' "$plugin_result"
            grep -q '^PASS$' "$qmp_result"
            cat > "$out/result" <<'RESULT'
            PASS
            status=partial
            check=${attrPath}
            provisional_tasks=${taskList}
            hook=crucible-qemu::run_single_vm_fingerprint_gate
            nvcpu_fingerprint=all-vcpus-plus-rr-cursor
            register_scope=all-vcpus-ascending
            rr_cursor=current-vcpu-position-and-quantum
            rolling_digest=canonical-N-vCPU-material
            mismatch_localization=first-differing-icount-window-and-component
            localization_scope=coarse-trace-window
            instruction_exact_refinement=false
            plugin_introspection=checks.crucible.phase2.qemuPluginVcpuIntrospection
            qmp_control=checks.crucible.phase2.qemuQmpClient
            real_qemu_runs=two-bounded-sim-smp4-stop-at-traces
            real_qemu_adversary=second-run-host-cpu-load
            real_qemu_importer=crucible-qemu-fingerprint
            real_qemu_comparison=canonical-rust-stream
            real_qemu_gate_hook=run_single_vm_fingerprint_gate
            qmp_topology=both-runs-exact-sorted-cpu-index-0-through-3
            guest_fixture=reset-vector-broadcast-init-sipi-sipi-busy-smp-bios
            guest_entropy_path=fixed-qemu-seed
            guest_entropy_seal=fw-cfg-plus-seeded-rng-builtin-no-rdrand-rdseed
            firmware_artifact_digest_bound=true
            guest_horizon=21000000-non-cadence
            all_vcpus_retired_at_horizon=true
            live_device_io_observed=true
            zero_observation_hashes_rejected=true
            exact_horizon_authoritative=true
            plugin_exit_semantics=bounded-post-stop-request-teardown-observation
            plugin_exit_pause_overshoot_bound=zero-exact-horizon
            plugin_exit_is_final_record=true
            run_provenance=distinct-ordinals-plus-prepared-argv-and-canonical-launch-and-build-digests
            launch_identity=complete-canonical-guest-visible-options-plus-artifact-digests
            canonical_guest_visible_launch_material_complete=true
            process_argv_expectation=independent-pre-exec-raw-unix-argv-v2
            actual_argv_hash_complete=true
            observation_contract_source=independent-definition-only-qemu-preflight
            independent_observation_contract=true
            fingerprint_definition=canonical-periodic-and-event-boundary-trace-v6
            periodic_cadence=4000000-real-smp-guest
            live_rr_switch_observation=distinct-vcpu-events-report-configured-quantum
            postprocessing_negative_controls=register,rr,retired,ram,device,device-schema,zero-register,zero-ram,zero-device,cadence,horizon,ram-bytes,topology
            live_perturbation_controls=second-run-host-cpu-load
            device_component_scope=current-non-ram-qemu-vmstate
            component_digest_strength=sha256
            device_schema_contract=registered-non-ram-vmstate-sections
            event_boundary_sampling=horizon-advance-live;frame-and-fault-model-only
            full_device_state_complete=true
            integrated_fixed_configuration_runner=false
            related_phase0_spike_source_check=checks.crucible.phase0.s11MultiVcpuFingerprint
            RESULT
          '';
        }
      ];
    }
