{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuRrQuantumIcount",
  taskIds ? ["T-PATCH-21"],
}: let
  patchName = "0002-crucible-rr-fingerprint-helpers.patch";
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  phase0S11 = builtins.readFile ./phase0-s11.nix;
  rrFingerprintHelpersSource = builtins.readFile ./phase1-rr-fingerprint-helpers.nix;
  icountNoRealtimeSource = builtins.readFile ./phase1-icount-no-realtime.nix;
  qemuMultiVcpuLaunchSource = builtins.readFile ./phase2-qemu-multi-vcpu-launch.nix;
  defaultChecks = builtins.readFile ./default.nix;

  rrFingerprintHelpers = import ./phase1-rr-fingerprint-helpers.nix {
    inherit pkgs lib;
    qemuPackage = pkgs.qemu-crucible;
  };
  icountNoRealtime = import ./phase1-icount-no-realtime.nix {
    inherit pkgs lib;
    qemuPackage = pkgs.qemu-crucible;
  };
  qemuMultiVcpuLaunch = import ./phase2-qemu-multi-vcpu-launch.nix {inherit pkgs lib;};
  qemuNvcpuFingerprint = import ./phase2-qemu-nvcpu-fingerprint.nix {inherit pkgs lib;};
  simS11 = import ./phase0-s11.nix {
    inherit pkgs lib;
    accelerator = "sim";
    cadence = 4096;
    requireGuestPass = false;
    stopAt = 16384;
    memoryMib = 128;
    vcpuCount = 2;
  };

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
    failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "T-PATCH-21 checklist complete";
        needle = "- [x] **T-PATCH-21**";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "RR switch quantum option";
        needle = ''qemu_opt_get_number(opts, "rr_switch_quantum", 0)'';
      }
      {
        label = "node-icount per-vCPU budget clamp";
        needle = "return MIN(limit, (int64_t)rr_switch_quantum);";
      }
      {
        label = "RR switch quantum sim guard";
        needle = ''strcmp(current_accel_name(), "sim") != 0'';
      }
      {
        label = "non-sim quantum helper inertness";
        needle = "return 0;";
      }
      {
        label = "RR cursor export";
        needle = "uint64_t icount_crucible_rr_cursor_position(CPUState *cpu)";
      }
      {
        label = "current RR vCPU export";
        needle = "qemu_plugin_crucible_rr_current_vcpu";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" tracePluginSource [
      {
        label = "RR switch event rows";
        needle = ''\"kind\":\"rr_switch\"'';
      }
      {
        label = "RR switch event counter";
        needle = "rr_switch_events++";
      }
      {
        label = "per-vCPU retired event counts";
        needle = "per_vcpu_retired";
      }
      {
        label = "per-vCPU delta event counts";
        needle = "per_vcpu_delta";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s11.nix" phase0S11 [
      {
        label = "S11 accelerator parameter";
        needle = ''accelerator ? "tcg,thread=single"'';
      }
      {
        label = "S11 sim accelerator override";
        needle = "ACCELERATOR = accelerator;";
      }
      {
        label = "S11 launch uses accelerator override";
        needle = ''-accel "$ACCELERATOR"'';
      }
      {
        label = "S11 diffs full trace across jittered run";
        needle = ''diff -u "$TMPDIR/trace-a.jsonl" "$TMPDIR/trace-b.jsonl"'';
      }
      {
        label = "S11 localizes RR current-vCPU mismatches";
        needle = ''rr_current_vcpu'';
      }
      {
        label = "S11 localizes RR cursor mismatches";
        needle = ''rr_cursor_position'';
      }
      {
        label = "S11 result records aggregate icount stream equality";
        needle = "aggregate_icount_stream_match=true";
      }
      {
        label = "S11 extracts explicit RR switch trace";
        needle = ''select(.kind == "rr_switch")'';
      }
      {
        label = "S11 extracts per-vCPU delta trace";
        needle = "per_vcpu_delta";
      }
      {
        label = "S11 records RR switch event count";
        needle = ''rr_switch_events="$rr_switch_events_a"'';
      }
      {
        label = "S11 diffs explicit RR switch trace";
        needle = "RR switch trace mismatch";
      }
      {
        label = "S11 diffs per-vCPU delta trace";
        needle = "per-vCPU icount-delta trace mismatch";
      }
      {
        label = "S11 result records explicit RR switch trace equality";
        needle = "rr_switch_trace_match=true";
      }
      {
        label = "S11 result records per-vCPU delta trace equality";
        needle = "per_vcpu_delta_trace_match=true";
      }
      {
        label = "S11 bounded sim stop_at support";
        needle = ''run_horizon="$run_horizon"'';
      }
    ]
    ++ failuresFor "tests/crucible/phase1-rr-fingerprint-helpers.nix" rrFingerprintHelpersSource [
      {
        label = "RR budget pinned result";
        needle = "rr_budget_pinned=true";
      }
      {
        label = "stock unpinned RR budget negative control";
        needle = "stock_negative_control_rr_budget_unpinned=true";
      }
      {
        label = "pinned RR switch trace evidence";
        needle = "rr_switch_trace_pinned_under_host_jitter=true";
      }
      {
        label = "sim-gated RR quantum evidence";
        needle = "rr_switch_quantum_sim_gated=true";
      }
      {
        label = "non-sim stock budget evidence";
        needle = "non_sim_rr_switch_quantum_uses_stock_budget=true";
      }
      {
        label = "adaptive RR switch trace negative control";
        needle = "adaptive_rr_switch_trace_negative_control=red";
      }
      {
        label = "configured non-sim RR switch trace negative control";
        needle = "patched_non_sim_rr_switch_trace_negative_control=red";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-icount-no-realtime.nix" icountNoRealtimeSource [
      {
        label = "adaptive realtime negative control";
        needle = "adaptive_realtime_consulted=true";
      }
      {
        label = "stock realtime dependency negative control";
        needle = "stock_negative_control_realtime_dependent=true";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-multi-vcpu-launch.nix" qemuMultiVcpuLaunchSource [
      {
        label = "ascending vCPU rotation evidence";
        needle = "rr_vcpu_rotation=ascending-vcpu-id";
      }
      {
        label = "MTTCG rejection evidence";
        needle = "rejects_mttcg=true";
      }
      {
        label = "unpinned RR quantum rejection evidence";
        needle = "rejects_unpinned_rr_switch_quantum=true";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes RR quantum icount task check";
        needle = "qemuRrQuantumIcount = import ./phase2-qemu-rr-quantum-icount.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU RR quantum icount check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-rr-quantum-icount";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "aggregate-qemu-rr-quantum-icount";
          script = ''
            set -eu

            require_line() {
              result="$1"
              line="$2"
              grep -Fxq "$line" "$result" || {
                echo "dependency missing evidence: $line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            mkdir -p "$out"

            rr_result="${rrFingerprintHelpers}/result"
            require_line "$rr_result" "PASS"
            require_line "$rr_result" "patch=${patchName}"
            require_line "$rr_result" "rr_switch_quantum_configured=true"
            require_line "$rr_result" "rr_budget_pinned=true"
            require_line "$rr_result" "rr_switch_quantum_sim_gated=true"
            require_line "$rr_result" "non_sim_rr_switch_quantum_uses_stock_budget=true"
            require_line "$rr_result" "rr_switch_trace_pinned_under_host_jitter=true"
            require_line "$rr_result" "adaptive_rr_switch_trace_negative_control=red"
            require_line "$rr_result" "patched_non_sim_rr_switch_trace_negative_control=red"
            require_line "$rr_result" "stock_negative_control_rr_budget_unpinned=true"
            cp "$rr_result" "$out/rr-fingerprint-helpers.result"

            icount_result="${icountNoRealtime}/result"
            require_line "$icount_result" "PASS"
            require_line "$icount_result" "synthetic_fast_slow_realtime_deadlines=true"
            require_line "$icount_result" "sim_precise_tb_exit_budget=identical"
            require_line "$icount_result" "adaptive_realtime_consulted=true"
            require_line "$icount_result" "stock_negative_control_realtime_dependent=true"
            cp "$icount_result" "$out/icount-no-realtime.result"

            launch_result="${qemuMultiVcpuLaunch}/result"
            require_line "$launch_result" "PASS"
            require_line "$launch_result" "smp_multi_vcpu_test=4"
            require_line "$launch_result" "rr_switch_quantum=content-addressed-node-icount"
            require_line "$launch_result" "rr_vcpu_rotation=ascending-vcpu-id"
            require_line "$launch_result" "rejects_mttcg=true"
            require_line "$launch_result" "rejects_unpinned_rr_switch_quantum=true"
            cp "$launch_result" "$out/qemu-multi-vcpu-launch.result"

            nvcpu_result="${qemuNvcpuFingerprint}/result"
            require_line "$nvcpu_result" "PASS"
            require_line "$nvcpu_result" "rr_cursor=current-vcpu-position-and-quantum"
            require_line "$nvcpu_result" "real_qemu_smoke=bounded-sim-smp4-stop_at-trace"
            cp "$nvcpu_result" "$out/qemu-nvcpu-fingerprint.result"

            s11_result="${simS11}/result"
            require_line "$s11_result" "PASS"
            require_line "$s11_result" "accelerator=sim"
            require_line "$s11_result" "vcpus=2"
            require_line "$s11_result" "rr_switch_quantum=4096"
            require_line "$s11_result" "cadence=4096"
            require_line "$s11_result" "run_horizon=plugin-stop_at-16384"
            require_line "$s11_result" "require_guest_pass=0"
            require_line "$s11_result" "host_adversary=jitter-load"
            require_line "$s11_result" "extended_fingerprint_match=true"
            require_line "$s11_result" "aggregate_icount_stream_match=true"
            require_line "$s11_result" "rr_switch_trace_match=true"
            require_line "$s11_result" "per_vcpu_delta_trace_match=true"
            grep -q '^rr_switch_events=' "$s11_result"
            require_line "$s11_result" "first_differing_component=none"
            cp "$s11_result" "$out/s11-sim-multi-vcpu-fingerprint.result"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:patch-microtests
            gate=gate:single-vm-fingerprint
            patch=${patchName}
            accelerator=sim
            vcpus=2
            rr_switch_quantum=4096
            rr_switch_boundary=node-icount
            rr_vcpu_rotation=ascending-vcpu-id
            cross_run_switch_icount_trace_match=true
            cross_run_per_vcpu_delta_trace_match=true
            sim_s11_trace_source=checks.crucible.phase0.s11MultiVcpuFingerprint(accelerator=sim,stop_at=16384)
            rr_budget_pinned=true
            rr_switch_trace_pinned_under_host_jitter=true
            adaptive_realtime_quantum_negative_control=red
            adaptive_rr_switch_trace_negative_control=red
            patched_non_sim_rr_switch_trace_negative_control=red
            non_sim_rr_switch_quantum_uses_stock_budget=true
            stock_unpinned_rr_budget_negative_control=red
            rejects_mttcg=true
            rejects_unpinned_rr_switch_quantum=true
            nvcpu_fingerprint_rr_cursor=covered
            RESULT
          '';
        }
      ];
    }
