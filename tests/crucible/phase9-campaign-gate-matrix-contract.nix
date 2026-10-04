{
  pkgs,
  attrPath ? "checks.crucible.phase9.gates.campaignGateMatrixContract",
}: let
  authenticator = ./_phase9-campaign-gate-matrix-authenticate.sh;
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-gate-matrix-contract";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed];
    phases = [
      {
        name = "check-campaign-gate-matrix-binding";
        script = ''
          set -eu
          . ${authenticator}
          . ${./_phase9-campaign-mode-frame.sh}

          write_result() {
            destination="$1"
            gate="$2"
            mode="$3"
            identity="$4"
            toplevel="$5"
            executor="$6"
            cat > "$destination" <<RESULT
          PASS
          gate=$gate
          campaign_mode=$mode
          campaign_configuration_identity=$identity
          campaign_toplevel=$toplevel
          executor_derivation=$executor
          RESULT
          }

          write_result good gate:campaign-model disabled disabled-id /system-disabled /executor-disabled
          authenticate_campaign_matrix_raw_result \
            good gate:campaign-model disabled disabled-id /system-disabled /executor-disabled

          write_result crossed-mode gate:campaign-model enabled enabled-id /system-enabled /executor-enabled
          if authenticate_campaign_matrix_raw_result \
              crossed-mode gate:campaign-model disabled disabled-id \
              /system-disabled /executor-disabled; then
            echo "cross-mode raw result was accepted" >&2
            exit 1
          fi

          write_result crossed-gate gate:license-boundary disabled disabled-id /system-disabled /executor-disabled
          if authenticate_campaign_matrix_raw_result \
              crossed-gate gate:campaign-model disabled disabled-id \
              /system-disabled /executor-disabled; then
            echo "cross-gate raw result was accepted" >&2
            exit 1
          fi

          cat > malformed-transcript <<'TRANSCRIPT'
          CAMPAIGN_GATE_RESULT_END
          CAMPAIGN_GATE_RESULT_BEGIN
          PASS
          gate=gate:campaign-model
          campaign_mode=disabled
          campaign_configuration_identity=disabled-id
          campaign_toplevel=/system-disabled
          executor_derivation=/executor-disabled
          TRANSCRIPT
          if extract_campaign_matrix_raw_result malformed-transcript malformed-result; then
            echo "out-of-order campaign gate result frame was accepted" >&2
            exit 1
          fi

          cat > ordered-mode-frame <<'FRAME'
          MODE_BEGIN
          identity
          transcript
          MODE_END
          FRAME
          extract_campaign_mode_frame \
            ordered-mode-frame MODE_BEGIN MODE_END 2 ordered-mode-payload
          test "$(wc -l < ordered-mode-payload | tr -d ' ')" -eq 2

          for malformed in end-before-begin trailing-open duplicate-begin; do
            case "$malformed" in
              end-before-begin)
                printf '%s\n' MODE_END MODE_BEGIN identity transcript > "$malformed"
                ;;
              trailing-open)
                printf '%s\n' MODE_BEGIN identity transcript > "$malformed"
                ;;
              duplicate-begin)
                printf '%s\n' MODE_BEGIN MODE_BEGIN identity transcript MODE_END > "$malformed"
                ;;
            esac
            if extract_campaign_mode_frame \
                "$malformed" MODE_BEGIN MODE_END 2 "$malformed.payload"; then
              echo "$malformed mode frame was accepted" >&2
              exit 1
            fi
            if extract_campaign_mode_result_frame \
                "$malformed" MODE_BEGIN MODE_END "$malformed.result"; then
              echo "$malformed result frame was accepted" >&2
              exit 1
            fi
          done

          cat > perf-disabled <<'RESULT'
          PASS
          gate=gate:perf-bench
          metric_direct_restore_to_runnable_us=125
          metric_delta_restore_to_runnable_us=95
          metric_restore_latency_source=descriptor-restore-through-cont-ack
          RESULT
          cat > perf-enabled <<'RESULT'
          PASS
          gate=gate:perf-bench
          metric_direct_restore_to_runnable_us=140
          metric_delta_restore_to_runnable_us=101
          metric_restore_latency_source=descriptor-restore-through-cont-ack
          RESULT
          normalize_campaign_matrix_semantic_result \
            gate:perf-bench perf-disabled perf-disabled.semantic
          normalize_campaign_matrix_semantic_result \
            gate:perf-bench perf-enabled perf-enabled.semantic
          cmp perf-disabled.semantic perf-enabled.semantic

          sed 's/metric_delta_restore_to_runnable_us=101/metric_delta_restore_to_runnable_us=unbounded/' \
            perf-enabled > perf-invalid
          if normalize_campaign_matrix_semantic_result \
              gate:perf-bench perf-invalid perf-invalid.semantic; then
            echo "invalid restore metric was normalized" >&2
            exit 1
          fi

          sed '/metric_restore_latency_source=/d' perf-enabled > perf-missing-semantic
          normalize_campaign_matrix_semantic_result \
            gate:perf-bench perf-missing-semantic perf-missing-semantic.result
          if cmp perf-disabled.semantic perf-missing-semantic.result; then
            echo "non-observational perf evidence was stripped" >&2
            exit 1
          fi

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          cross_mode_substitution=rejected
          cross_gate_substitution=rejected
          out_of_order_frame=rejected
          specialized_mode_frames=ordered-bounded-terminal
          specialized_result_frames=ordered-nonempty-terminal
          typed_perf_observations=bounded-and-normalized
          non_observational_perf_evidence=preserved
          RESULT
        '';
      }
    ];
  }
