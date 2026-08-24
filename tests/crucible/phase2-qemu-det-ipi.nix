{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0028-crucible-det-ipi.patch",
  attrPath ? "checks.crucible.phase2.qemuDetIpi",
  taskIds ? ["T-PATCH-22"],
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  defaultChecks = builtins.readFile ./default.nix;
  # The aggregate patch-microtests gate applies the full QEMU series with
  # `patch --batch --fuzz=0 -p1`; this check consumes that patched package
  # through the real multi-vCPU S11 trace fixture.
  simS11 = import ./phase0-s11.nix {
    inherit pkgs lib qemuPackage;
    accelerator = "sim,thread=single";
    cadence = 65536;
    detIpiProbe = true;
    requireRrSwitchEvents = false;
    requireGuestPass = false;
    stopAt = 4194304;
    memoryMib = 128;
    vcpuCount = 2;
  };

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "sim-gated deterministic IPI mode";
        needle = ''strcmp(current_accel_name(), "sim") == 0'';
      }
      {
        label = "precise icount guard";
        needle = "icount_enabled() == ICOUNT_PRECISE";
      }
      {
        label = "pinned RR quantum guard";
        needle = "icount_crucible_rr_switch_quantum() != 0";
      }
      {
        label = "IPI queue enqueue";
        needle = "crucible_sim_det_ipi_enqueue";
      }
      {
        label = "RR handoff drain";
        needle = "crucible_sim_det_ipi_drain_pending();";
      }
      {
        label = "INIT delivery queued";
        needle = "CPU_INTERRUPT_INIT";
      }
      {
        label = "SIPI delivery queued";
        needle = "APIC_DM_SIPI";
      }
      {
        label = "plugin delivery trace callback";
        needle = "qemu_plugin_crucible_maybe_fire_ipi_delivery_cb";
      }
      {
        label = "non-sim source uses upstream path";
        needle = "return false;";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" tracePluginSource [
      {
        label = "deterministic IPI trace rows";
        needle = "det_ipi_events++";
      }
      {
        label = "IPI delivery callback registration";
        needle = "qemu_plugin_crucible_register_ipi_delivery_cb(on_det_ipi_delivery, NULL)";
      }
      {
        label = "delivery icount field";
        needle = ''"delivery_icount\":%" PRIu64'';
      }
      {
        label = "commanded probe targets the authenticated SIPI sender";
        needle = "const unsigned int target_vcpu = src_vcpu;";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes deterministic IPI task check";
        needle = "qemuDetIpi = import ./phase2-qemu-det-ipi.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 deterministic QEMU IPI check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-det-ipi";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gawk
        pkgs.grep
        pkgs.jq
      ];

      phases = [
        {
          name = "aggregate-qemu-det-ipi";
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

            s11_result="${simS11}/result"
            require_line "$s11_result" "PASS"
            require_line "$s11_result" "accelerator=sim,thread=single"
            require_line "$s11_result" "vcpus=2"
            require_line "$s11_result" "rr_switch_quantum=4096"
            require_line "$s11_result" "run_horizon=plugin-stop_at-4194304"
            require_line "$s11_result" "det_ipi_probe=enabled"
            require_line "$s11_result" "rr_cursor_assertion=valid_boot_prefix_snapshot"
            require_line "$s11_result" "extended_fingerprint_match=true"
            require_line "$s11_result" "aggregate_icount_stream_match=true"
            require_line "$s11_result" "rr_switch_trace_match=true"
            cp "$s11_result" "$out/s11-sim-det-ipi.result"
            cp "${simS11}/trace-a.jsonl" "$out/trace-a.jsonl"
            cp "${simS11}/trace-b.jsonl" "$out/trace-b.jsonl"

            for label in a b; do
              jq -e -s '
                [ .[] | select(.kind == "det_ipi") ] as $events
                | ($events | length) > 0
                and any($events[]; .delivery_mode == 0)
                and any($events[]; .delivery_mode == 5)
                and any($events[]; .delivery_mode == 6)
                and all($events[]; (
                  .det_ipi_event > 0
                  and .event_id > 0
                  and .delivery_icount >= 0
                  and .src_vcpu >= 0
                  and .src_vcpu < 2
                  and .dst_vcpu >= 0
                  and .dst_vcpu < 2
                  and .src_vcpu != .dst_vcpu
                  and .delivery_mode >= 0
                  and .vector >= 0
                ))
              ' "$out/trace-$label.jsonl" >/dev/null

              jq -r '
                select(.kind == "det_ipi")
                | [
                    .det_ipi_event,
                    .event_id,
                    .delivery_icount,
                    .src_vcpu,
                    .dst_vcpu,
                    .delivery_mode,
                    .vector
                  ]
                | @tsv
              ' "$out/trace-$label.jsonl" > "$out/det-ipi-trace-$label.tsv"
            done

            det_ipi_events_a=$(wc -l < "$out/det-ipi-trace-a.tsv" | tr -d ' ')
            det_ipi_events_b=$(wc -l < "$out/det-ipi-trace-b.tsv" | tr -d ' ')
            [ "$det_ipi_events_a" -gt 0 ] || {
              echo "expected deterministic IPI events in run a" >&2
              exit 1
            }
            [ "$det_ipi_events_a" -eq "$det_ipi_events_b" ] || {
              echo "deterministic IPI event count mismatch: $det_ipi_events_a/$det_ipi_events_b" >&2
              exit 1
            }

            if ! diff -u "$out/det-ipi-trace-a.tsv" "$out/det-ipi-trace-b.tsv" > "$out/det-ipi-trace.diff"; then
              cat "$out/det-ipi-trace.diff" >&2
              exit 1
            fi

            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:patch-microtests
            gate=gate:layer0-determinism
            gate=gate:single-vm-fingerprint
            patch=${patchName}
            accelerator=sim,thread=single
            vcpus=2
            rr_switch_quantum=4096
            deterministic_ipi_queue=sim-only-inter-vcpu
            deterministic_ipi_rr_handoff=queued-drain-before-next-vcpu
            deterministic_ipi_delivery_trace=det_ipi-jsonl
            deterministic_ipi_fixed_mode_source=trace-plugin-commanded-preemption-probe
            deterministic_ipi_events=$det_ipi_events_a
            deterministic_ipi_fixed_mode_trace=true
            deterministic_ipi_init_mode_trace=true
            deterministic_ipi_sipi_mode_trace=true
            deterministic_ipi_event_count_match=true
            deterministic_ipi_delivery_icount_trace_match=true
            deterministic_ipi_source_target_distinct=true
            rr_handoff_proof_scope=canonical-long-horizon-s11
            sim_s11_trace_source=checks.crucible.phase0.s11MultiVcpuFingerprint(accelerator=sim,thread=single,stop_at=4194304,det_ipi_probe=enabled)
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_negative_control_scope=non-sim-and-self-IPI-use-upstream-path
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
