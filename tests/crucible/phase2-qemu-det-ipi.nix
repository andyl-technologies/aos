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
        qemuPackage
        pkgs.crucible-qemu-trace-plugin
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
                [ .[] | select(.kind == "det_ipi") ]
                | sort_by(.det_ipi_event) as $events
                | ($events | length) == 3
                and ([ $events[].det_ipi_event ] == [1, 2, 3])
                and ([ $events[].event_id ] == [1, 2, 3])
                and ($events[0].delivery_mode == 5)
                and ($events[0].vector == 4294967295)
                and ($events[1].delivery_mode == 6)
                and ($events[1].vector == 16)
                and ($events[2].delivery_mode == 0)
                and ($events[2].vector == 81)
                and ($events[0].src_vcpu == $events[1].src_vcpu)
                and ($events[0].dst_vcpu == $events[1].dst_vcpu)
                and ($events[2].src_vcpu == $events[1].dst_vcpu)
                and ($events[2].dst_vcpu == $events[1].src_vcpu)
                and ($events[0].delivery_icount == $events[1].delivery_icount)
                and ($events[1].delivery_icount == $events[2].delivery_icount)
                and all($events[]; (
                  .delivery_icount >= 0
                  and .src_vcpu >= 0
                  and .src_vcpu < 2
                  and .dst_vcpu >= 0
                  and .dst_vcpu < 2
                  and .src_vcpu != .dst_vcpu
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

            # Ordinary TCG has no deterministic IPI queue or RR cursor. Run
            # the same probe against executing firmware with extended
            # fingerprinting disabled, then require the callback stream to
            # remain empty. This isolates accelerator fallback from S11's
            # sim-only register-capture and stop-boundary assertions.
            non_sim_trace="$TMPDIR/non-sim-trace.jsonl"
            non_sim_log="$TMPDIR/non-sim-qemu.log"
            non_sim_launch="$TMPDIR/non-sim-launch.txt"
            trace_plugin="${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so"
            qemu_binary="${qemuPackage}/bin/qemu-system-x86_64"
            printf '%s\n' \
              'machine=q35' \
              'accelerator=tcg,thread=single' \
              'icount=shift=0,sleep=off,align=off' \
              'vcpus=2' \
              'det_ipi_probe=on' \
              > "$non_sim_launch"
            launch_digest=$(sha256sum "$non_sim_launch" | gawk '{ print $1 }')
            qemu_digest=$(sha256sum "$qemu_binary" | gawk '{ print $1 }')
            plugin_digest=$(sha256sum "$trace_plugin" | gawk '{ print $1 }')
            plugin_arg="$trace_plugin,out=$non_sim_trace,cadence=65536,extended=off,mem_events=off,vcpus=2,det_ipi_probe=on,launch_digest=$launch_digest,qemu_build_digest=$qemu_digest,plugin_build_digest=$plugin_digest"

            set +e
            timeout -k 1 3 "$qemu_binary" \
              -L "${qemuPackage}/share/qemu" \
              -nodefaults \
              -no-user-config \
              -display none \
              -machine q35 \
              -accel tcg,thread=single \
              -icount shift=0,sleep=off,align=off \
              -cpu qemu64 \
              -m 64 \
              -smp 2 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -monitor none \
              -serial none \
              -no-reboot \
              -plugin "$plugin_arg" \
              > "$non_sim_log" 2>&1
            non_sim_status=$?
            set -e
            [ "$non_sim_status" -eq 124 ] || {
              cat "$non_sim_log" >&2
              echo "ordinary-TCG negative exited unexpectedly: $non_sim_status" >&2
              exit 1
            }
            test -s "$non_sim_trace"
            jq -e -s '
              ([ .[] | select(.kind == "det_ipi") ] | length) == 0
              and any(.[]; ((.kind // "sample") == "sample") and .retired > 0)
            ' "$non_sim_trace" >/dev/null
            cp "$non_sim_trace" "$out/non-sim-trace.jsonl"
            cp "$non_sim_log" "$out/non-sim-qemu.log"

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
            deterministic_ipi_causal_triple=init-sipi-commanded-fixed
            deterministic_ipi_commanded_vector=81
            deterministic_ipi_commanded_reverse_path=true
            deterministic_ipi_causal_delivery_icount_match=true
            rr_handoff_proof_scope=canonical-long-horizon-s11
            sim_s11_trace_source=checks.crucible.phase0.s11MultiVcpuFingerprint(accelerator=sim,thread=single,stop_at=4194304,det_ipi_probe=enabled)
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_negative_control_scope=executed-non-sim-fallback
            stock_negative_control_det_ipi_events=0
            stock_negative_control_guest_execution=true
            stock_negative_control_trace_source=ordinary-tcg-firmware(det_ipi_probe=enabled,extended=off)
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
