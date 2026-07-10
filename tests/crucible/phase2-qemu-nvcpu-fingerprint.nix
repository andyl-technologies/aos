{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuNvcpuFingerprint",
  taskIds ? ["T-QEMU-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

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
  phase0S11 = builtins.readFile ./phase0-s11.nix;
  pluginIntrospectionCheck = import ./phase2-plugin-vcpu-introspection.nix {inherit pkgs lib;};
  qmpClientCheck = import ./phase2-qemu-qmp-client.nix {inherit pkgs lib;};
  boundaryGate = builtins.readFile ./phase2-qemu-determinism-boundary.nix;
  defaultChecks = builtins.readFile ./default.nix;

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

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

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
        needle = "register_hashes.per_vcpu";
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
        label = "trace plugin canonical register byte counts";
        needle = "register_file_bytes";
      }
      {
        label = "trace plugin per-vCPU retired counts";
        needle = "register_retired";
      }
      {
        label = "trace plugin versioned schema";
        needle = "crucible.qemu.trace-fingerprint.v2";
      }
      {
        label = "trace plugin register schema hashes";
        needle = "register_schema_hashes";
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
        label = "MMIO read and write values";
        needle = "qemu_plugin_mem_get_value(info)";
      }
      {
        label = "trace-bound launch identity";
        needle = "launch_definition_digest";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s11.nix" phase0S11 [
      {
        label = "real QEMU multi-vCPU fingerprint spike";
        needle = "spike=multi-vcpu-rr-sim-tcg-fingerprint";
      }
      {
        label = "real QEMU per-vCPU register assertion";
        needle = "register_count_assertion=nonempty_per_vcpu";
      }
      {
        label = "real QEMU S11 binds external QEMU identity";
        needle = ''qemu_build_digest=$(sha256sum "$QEMU"'';
      }
      {
        label = "real QEMU S11 binds external plugin identity";
        needle = ''trace_plugin_build_digest=$(sha256sum "$PLUGIN"'';
      }
      {
        label = "real QEMU S11 executes zero-provenance rejection";
        needle = "zero S11 provenance digest is not accepted";
      }
      {
        label = "real QEMU S11 compares trace and external QEMU identity";
        needle = ''.qemu_build_digest == $qemu_build_digest'';
      }
      {
        label = "real QEMU S11 compares trace and external plugin identity";
        needle = ''.trace_plugin_build_digest == $trace_plugin_build_digest'';
      }
      {
        label = "real QEMU RR cursor diff localization";
        needle = "\"rr_cursor_position\"";
      }
      {
        label = "real QEMU no fallback";
        needle = "fallback=smp1_not_needed";
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
        pkgs.grep
        pkgs.jq
        pkgs.qemu-crucible
        pkgs.crucible-qemu-trace-plugin
        pkgs.rust
        pkgs.sed
        pkgs.socat
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
            cadence=4093
            horizon=8186
            quantum=4096
            qemu_binary="${pkgs.qemu-crucible}/bin/qemu-system-x86_64"
            trace_plugin="${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so"
            qemu_build_digest=$(sha256sum "$qemu_binary" | cut -d ' ' -f 1)
            trace_plugin_build_digest=$(sha256sum "$trace_plugin" | cut -d ' ' -f 1)
            launch_definition_digest=$(printf '%s\n' \
              'machine=q35' 'accel=sim,thread=single' 'icount=shift=0,sleep=off,align=off,rr_switch_quantum=4096' \
              'cpu=qemu64' 'memory_mib=64' 'smp=4' 'seed=0x0010c016' \
              "$qemu_build_digest" "$trace_plugin_build_digest" \
              | sha256sum | cut -d ' ' -f 1)

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
              waited=0
              qmp_failures=0
              while [ "$waited" -lt 600 ]; do
                if qmp_cmd "$qmp_socket" '{"execute":"query-status"}' "$TMPDIR/qmp-status-$label.json"; then
                  qmp_failures=0
                  status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-status-$label.json")
                  case "$status" in
                    paused)
                      return 0
                      ;;
                    running | prelaunch)
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

            run_one() {
              label="$1"
              qmp_socket="$TMPDIR/qmp-nvcpu-$label.sock"
              trace="$TMPDIR/qemu-nvcpu-trace-$label.jsonl"
              rm -f "$qmp_socket" "$trace"

              qemu-system-x86_64 \
                -nodefaults \
                -no-user-config \
                -display none \
                -monitor none \
                -machine q35 \
                -accel sim,thread=single \
                -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
                -cpu qemu64 \
                -m 64 \
                -smp 4 \
                -rtc base=2026-01-01T00:00:00,clock=vm \
                -seed 0x0010c016 \
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

              jq -e -s '
                [ .[] | select((.kind // "sample") == "sample" and .final != true) ] as $samples
                | [ .[] | select(.kind == "rr_switch") ] as $switches
                | ($samples | map(.retired)) == [4093, 8186]
                and all($samples[]; (
                  .schema == "crucible.qemu.trace-fingerprint.v2"
                  and .launch_definition_digest != null
                  and .qemu_build_digest != null
                  and .trace_plugin_build_digest != null
                  and .tracked_vcpus == 4
                  and .rr_switch_quantum == 4096
                  and .rr_cursor_valid == true
                  and .rr_cursor_source == "live_instruction"
                  and .memory_events_enabled == true
                  and .device_event_capture == true
                  and .device_event_hash != null
                  and .memory_events > 0
                  and .io_events > 0
                  and .ram_bytes > 0
                  and .sample_register_failures == 0
                  and .register_read_failures == 0
                  and (.register_hashes | length) == 4
                  and (.register_counts | length) == 4
                  and all(.register_counts[]; . > 0)
                  and (.register_file_bytes | length) == 4
                  and all(.register_file_bytes[]; . > 0)
                  and (.register_schema_hashes | length) == 4
                  and (.register_retired | length) == 4
                  and (.register_retired | add) == .retired
                  and .rr_current_vcpu >= 0
                  and .rr_current_vcpu < 4
                  and .rr_cursor_position >= 0
                  and .rr_cursor_position < .rr_switch_quantum
                ))
                and any(.[]; (
                  (.kind // "sample") == "sample"
                  and .final == true
                  and .stop_requested == true
                  and .retired == 8186
                  and .rr_cursor_valid == true
                  and .rr_cursor_source == "last_executed_instruction"
                ))
                and ($switches | length) > 0
                and all($switches[]; (
                  .from_vcpu != .to_vcpu
                  and .previous_rr_switch_quantum == 4096
                  and .rr_switch_quantum == 4096
                  and .rr_cursor_position >= 0
                  and .rr_cursor_position < 4096
                ))
              ' "$trace" >/dev/null \
                || fail "real QEMU N-vCPU trace $label failed structural assertions"

              case "$label" in
                a) ordinal=first ;;
                b) ordinal=second ;;
                *) fail "unknown run label $label" ;;
              esac
              jq -n \
                --arg schema 'crucible.qemu.trace-run-provenance.v1' \
                --arg ordinal "$ordinal" \
                --arg run_id "qemu-nvcpu-$label" \
                --arg launch_definition_digest "$launch_definition_digest" \
                --arg qemu_build_digest "$qemu_build_digest" \
                --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
                '{schema:$schema,ordinal:$ordinal,run_id:$run_id,launch_definition_digest:$launch_definition_digest,qemu_build_digest:$qemu_build_digest,trace_plugin_build_digest:$trace_plugin_build_digest}' \
                > "$TMPDIR/provenance-$label.json"
            }

            run_one a
            start_jitter
            run_one b
            stop_jitter

            jq -n \
              --slurpfile trace "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
              --arg schema 'crucible.qemu.trace-comparison-contract.v1' \
              --arg node 'qemu-nvcpu-gate' \
              --argjson cadence_icount "$cadence" \
              --argjson horizon_icount "$horizon" \
              --argjson rr_switch_quantum "$quantum" \
              --arg launch_definition_digest "$launch_definition_digest" \
              --arg qemu_build_digest "$qemu_build_digest" \
              --arg trace_plugin_build_digest "$trace_plugin_build_digest" \
              '([$trace[] | select((.kind // "sample") == "sample" and .final != true)][0]) as $sample
               | {schema:$schema,node:$node,cadence_icount:$cadence_icount,horizon_icount:$horizon_icount,
                  rr_switch_quantum:$rr_switch_quantum,baseline_ram_bytes:$sample.ram_bytes,
                  register_counts:$sample.register_counts,
                  register_file_bytes:$sample.register_file_bytes,
                  register_schema_hashes:$sample.register_schema_hashes,
                  launch_definition_digest:$launch_definition_digest,
                  qemu_build_digest:$qemu_build_digest,
                  trace_plugin_build_digest:$trace_plugin_build_digest}' \
              > "$TMPDIR/fingerprint-contract.json"

            "$fingerprint_cli" \
              "$TMPDIR/fingerprint-contract.json" \
              "$TMPDIR/qmp-cpus-a.json" "$TMPDIR/provenance-a.json" \
              "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
              "$TMPDIR/qmp-cpus-b.json" "$TMPDIR/provenance-b.json" \
              "$TMPDIR/qemu-nvcpu-trace-b.jsonl" \
              > "$TMPDIR/fingerprint-compare.result" \
              || fail "canonical real-QEMU N-vCPU fingerprint streams differed"

            jq -c '
              if ((.kind // "sample") == "sample" and .final != true and .retired == 8186)
              then .register_hashes[1] = "00000000000000ff"
              else .
              end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/qemu-nvcpu-trace-mutated.jsonl"
            if "$fingerprint_cli" \
              "$TMPDIR/fingerprint-contract.json" \
              "$TMPDIR/qmp-cpus-a.json" "$TMPDIR/provenance-a.json" \
              "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
              "$TMPDIR/qmp-cpus-b.json" "$TMPDIR/provenance-b.json" \
              "$TMPDIR/qemu-nvcpu-trace-mutated.jsonl" \
              > "$TMPDIR/fingerprint-negative.out" \
              2> "$TMPDIR/fingerprint-negative.err"; then
              fail "mutated vCPU register trace unexpectedly compared equal"
            fi
            grep -q '^first_differing_sample=1$' "$TMPDIR/fingerprint-negative.err"
            grep -q '^previous_matching_icount=4093$' "$TMPDIR/fingerprint-negative.err"
            grep -q '^first_different_icount=8186$' "$TMPDIR/fingerprint-negative.err"
            grep -q '^first_differing_component=vcpu_register_digest\[1\]$' "$TMPDIR/fingerprint-negative.err"
            grep -q '^bisection_window=4093..8186$' "$TMPDIR/fingerprint-negative.err"

            expect_cli_failure() {
              label="$1"
              qmp_b="$2"
              trace_b="$3"
              expected="$4"
              if "$fingerprint_cli" \
                "$TMPDIR/fingerprint-contract.json" \
                "$TMPDIR/qmp-cpus-a.json" "$TMPDIR/provenance-a.json" \
                "$TMPDIR/qemu-nvcpu-trace-a.jsonl" \
                "$qmp_b" "$TMPDIR/provenance-b.json" "$trace_b" \
                > "$TMPDIR/$label.out" 2> "$TMPDIR/$label.err"; then
                fail "$label negative control unexpectedly passed"
              fi
              grep -q "$expected" "$TMPDIR/$label.err" \
                || fail "$label negative control did not report $expected"
            }

            jq -c '
              if ((.kind // "sample") == "sample" and (.retired == 8186 or .final == true))
              then .rr_current_vcpu = ((.rr_current_vcpu + 1) % 4)
              else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-rr-mutated.jsonl"
            expect_cli_failure rr-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-rr-mutated.jsonl" '^first_differing_component=rr_current_vcpu$'

            jq -c '
              if ((.kind // "sample") == "sample" and .final != true and .retired == 8186)
              then .register_retired[0] += 1 | .register_retired[1] -= 1
              else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-retired-mutated.jsonl"
            expect_cli_failure retired-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-retired-mutated.jsonl" '^first_differing_component=vcpu_retired_instruction_count\[0\]$'

            jq -c '
              if ((.kind // "sample") == "sample" and .final != true and .retired == 8186)
              then .ram_hash = "00000000000000fe" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-ram-mutated.jsonl"
            expect_cli_failure ram-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-ram-mutated.jsonl" '^first_differing_component=guest_memory_digest$'

            jq -c '
              if ((.kind // "sample") == "sample" and .final != true and .retired == 8186)
              then .device_event_hash = "00000000000000fd" else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-device-mutated.jsonl"
            expect_cli_failure device-mismatch "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-device-mutated.jsonl" '^first_differing_component=device_state_digest$'

            jq -c '
              if ((.kind // "sample") == "sample" and .final != true and .retired == 4093)
              then .retired = 4094 else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-cadence-mutated.jsonl"
            expect_cli_failure cadence-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-cadence-mutated.jsonl" 'periodic sample icount 4094 does not match expected 4093'

            jq -c '
              if ((.kind // "sample") == "sample" and .final == true)
              then .retired = 8187 else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-horizon-mutated.jsonl"
            expect_cli_failure horizon-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-horizon-mutated.jsonl" 'exact configured horizon'

            jq -c '
              if ((.kind // "sample") == "sample" and .final != true and .retired == 8186)
              then .ram_bytes += 1 else . end
            ' "$TMPDIR/qemu-nvcpu-trace-b.jsonl" > "$TMPDIR/trace-ram-bytes-mutated.jsonl"
            expect_cli_failure ram-bytes-reject "$TMPDIR/qmp-cpus-b.json" \
              "$TMPDIR/trace-ram-bytes-mutated.jsonl" 'guest RAM observation differs from the run-A baseline'

            jq -c 'if (.return | type == "array") then .return[3]."cpu-index" = 2 else . end' \
              "$TMPDIR/qmp-cpus-b.json" > "$TMPDIR/qmp-topology-mutated.json"
            expect_cli_failure topology-reject "$TMPDIR/qmp-topology-mutated.json" \
              "$TMPDIR/qemu-nvcpu-trace-b.jsonl" 'QMP CPU indexes must be the exact sorted set'

            mkdir -p "$out"
            cp "$TMPDIR/qemu-nvcpu-trace-a.jsonl" "$out/qemu-nvcpu-trace-a.jsonl"
            cp "$TMPDIR/qemu-nvcpu-trace-b.jsonl" "$out/qemu-nvcpu-trace-b.jsonl"
            cp "$TMPDIR/qmp-cpus-a.json" "$out/qmp-cpus-a.json"
            cp "$TMPDIR/qmp-cpus-b.json" "$out/qmp-cpus-b.json"
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
            grep -q '^definition_status=provisional$' "$out/fingerprint-compare.result"
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
            run_provenance=distinct-ordinals-plus-trace-bound-launch-and-build-digests
            actual_argv_hash_complete=false
            observation_contract_source=first-run-baseline
            independent_observation_contract=false
            fingerprint_definition=provisional-periodic-trace-v2
            periodic_cadence=4093-off-rr-quantum-boundary
            live_rr_switch_observation=distinct-vcpu-events-report-configured-quantum
            postprocessing_negative_controls=register,rr,retired,ram,device,cadence,horizon,ram-bytes,topology
            live_perturbation_controls=second-run-host-cpu-load
            device_component_scope=ordered-cpu-mmio-read-write-history
            event_boundary_sampling=false
            full_device_state_complete=false
            integrated_fixed_configuration_runner=false
            related_phase0_spike_source_check=checks.crucible.phase0.s11MultiVcpuFingerprint
            RESULT
          '';
        }
      ];
    }
