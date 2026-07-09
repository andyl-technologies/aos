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
  qemuGateTypes = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/types.rs;
  qemuGateHook = qemuGateRoot + qemuGateCompare + qemuGateRun + qemuGateTypes;
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  qmpLib = builtins.readFile ../../crates/crucible-qemu/src/qmp.rs;
  qemuGateTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_single_vm_fingerprint.rs;
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
        label = "T-QEMU-16 checklist complete";
        needle = "- [x] **T-QEMU-16**";
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
    ]
    ++ failuresFor "tests/crucible/phase0-s11.nix" phase0S11 [
      {
        label = "real QEMU multi-vCPU fingerprint spike";
        needle = "spike=multi-vcpu-rr-tcg-fingerprint";
      }
      {
        label = "real QEMU per-vCPU register assertion";
        needle = "register_count_assertion=nonempty_per_vcpu";
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
              -- --test-threads=1

            cd "$TMPDIR"
            qemu_pid=""
            qmp_socket="$TMPDIR/qmp-nvcpu.sock"
            trace="$TMPDIR/qemu-nvcpu-trace.jsonl"
            rm -f "$qmp_socket" "$trace"

            cleanup_qemu() {
              if [ -n "$qemu_pid" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
                qemu_pid=""
              fi
            }

            fail() {
              echo "FAIL: $*" >&2
              cleanup_qemu
              exit 1
            }

            trap cleanup_qemu EXIT

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
              waited=0
              qmp_failures=0
              while [ "$waited" -lt 600 ]; do
                if qmp_cmd "$qmp_socket" '{"execute":"query-status"}' "$TMPDIR/qmp-status.json"; then
                  qmp_failures=0
                  status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$TMPDIR/qmp-status.json")
                  case "$status" in
                    paused)
                      return 0
                      ;;
                    running | prelaunch)
                      ;;
                    *)
                      cat "$TMPDIR/qmp-status.json" >&2
                      return 1
                      ;;
                  esac
                else
                  qmp_failures=$((qmp_failures + 1))
                  if [ "$qmp_failures" -ge 10 ]; then
                    if [ -f "$TMPDIR/qmp-status.json" ]; then
                      cat "$TMPDIR/qmp-status.json" >&2
                    fi
                    return 1
                  fi
                fi
                sleep 0.1
                waited=$((waited + 1))
              done
              return 1
            }

            qemu-system-x86_64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel sim \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
              -cpu qemu64 \
              -m 64 \
              -smp 4 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c016 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -plugin "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so",out="$trace",cadence=4096,stop_at=4096,extended=on,mem_events=off,rr_switch_events=off,vcpus=4 \
              -no-shutdown \
              -no-reboot &
            qemu_pid="$!"

            wait_for_socket "$qmp_socket" || fail "QMP socket did not appear"
            wait_for_stop_at_pause || fail "QEMU did not pause at the N-vCPU stop_at horizon"
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit.json" || true
            wait "$qemu_pid" || fail "QEMU exited unsuccessfully"
            qemu_pid=""

            jq -e -s '
              def terminal_stop_sample:
                .final == true and .stop_requested == true;

              [ .[] | select((.kind // "sample") == "sample") ] as $samples
              | ($samples | length) >= 2
              and all($samples[]; (
                .tracked_vcpus == 4
                and (
                  if terminal_stop_sample then
                    .rr_switch_quantum == 0
                    and .rr_cursor_valid == false
                  else
                    .rr_switch_quantum == 4096
                    and .rr_cursor_valid == true
                  end
                )
                and .sample_register_failures == 0
                and .register_read_failures == 0
                and (.register_hashes | type == "array")
                and (.register_hashes | length) == 4
                and (.register_counts | type == "array")
                and (.register_counts | length) == 4
                and all(.register_counts[]; . > 0)
                and (.rr_current_vcpu | type == "number")
                and (.rr_cursor_position | type == "number")
              ))
              and all($samples[] | select(.final != true); (
                .rr_current_vcpu >= 0
                and .rr_current_vcpu < 4
                and .rr_cursor_position >= 0
                and .rr_cursor_position < .rr_switch_quantum
              ))
              and any($samples[]; .final != true and .retired == 4096)
              and any($samples[]; .final == true)
            ' "$trace" >/dev/null \
              || fail "real QEMU N-vCPU trace failed structural assertions"

            mkdir -p "$out"
            cp "$trace" "$out/qemu-nvcpu-trace.jsonl"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            grep -q '"tracked_vcpus":4' "$out/qemu-nvcpu-trace.jsonl"
            grep -q '"rr_switch_quantum":4096' "$out/qemu-nvcpu-trace.jsonl"
            plugin_result="${pluginIntrospectionCheck}/result"
            qmp_result="${qmpClientCheck}/result"
            grep -q '^PASS$' "$plugin_result"
            grep -q '^protocol_snapshot=crucible-protocol::PluginNvcpuFingerprintSnapshot$' "$plugin_result"
            grep -q '^PASS$' "$qmp_result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            hook=crucible-qemu::run_single_vm_fingerprint_gate
            nvcpu_fingerprint=all-vcpus-plus-rr-cursor
            register_scope=all-vcpus-ascending
            rr_cursor=current-vcpu-position-and-quantum
            rolling_digest=canonical-N-vCPU-material
            mismatch_localization=first-differing-icount-window-and-component
            plugin_introspection=checks.crucible.phase2.qemuPluginVcpuIntrospection
            qmp_control=checks.crucible.phase2.qemuQmpClient
            real_qemu_smoke=bounded-sim-smp4-stop_at-trace
            related_phase0_spike_source_check=checks.crucible.phase0.s11MultiVcpuFingerprint
            RESULT
          '';
        }
      ];
    }
