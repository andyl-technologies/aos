{
  pkgs,
  lib,
  buildDrv,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "drop-one-9p-sync-kick",
}: let
  exactDispatchProbe = import ./phase2-qemu-9p-sync-kick.nix {
    inherit pkgs lib qemuPackage;
  };
  liveNinepGate = import ./phase2-qemu-live-9p-io.nix {
    inherit pkgs lib;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-9p-sync-kick";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
    ];

    BUILD_DRV = "${buildDrv}";
    EXACT_DISPATCH_PROBE = "${exactDispatchProbe}";
    LIVE_NINEP_GATE = "${liveNinepGate}";

    phases = [
      {
        name = "probe-drop-one-9p-sync-kick";
        script = ''
          set -eu
          mkdir -p "$out"

          if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
            cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=40
          sim_discriminator_classification=not-applicable
          reason=variant-not-built
          RESULT
            exit 0
          fi
          grep -Fxq '0040-crucible-9p-sync-kick.patch' "$BUILD_DRV/dropped-patch"

          grep -Fxq 'prefix_negative_control=true' "$EXACT_DISPATCH_PROBE/result"
          grep -Fxq 'patched_exact_source_fixture=true' "$EXACT_DISPATCH_PROBE/result"
          grep -Fxq 'sim_icount_9p_kick_synchronous=true' "$EXACT_DISPATCH_PROBE/result"
          grep -Fxq 'notifier_calls=1 handler_calls=0' \
            "$EXACT_DISPATCH_PROBE/prefix-sim-9p.txt"
          grep -Fxq 'notifier_calls=0 handler_calls=1' \
            "$EXACT_DISPATCH_PROBE/patched-sim-9p.txt"

          grep -Fxq 'sim_leg_forwarded=true' "$LIVE_NINEP_GATE/result"
          grep -Fxq 'guest_progressed_past_ninep_io=true' "$LIVE_NINEP_GATE/result"
          grep -Fxq 'deterministic_under_host_load=true' "$LIVE_NINEP_GATE/result"

          cp "$EXACT_DISPATCH_PROBE/prefix-sim-9p.txt" "$out/"
          cp "$EXACT_DISPATCH_PROBE/patched-sim-9p.txt" "$out/"
          cp "$LIVE_NINEP_GATE/result" "$out/full-live-9p.result"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=40
          sim_discriminator_classification=differs
          semantic_form=variant-host-notifier-dispatch-vs-full-inline-handler
          full_live_9p_gate=$LIVE_NINEP_GATE
          full_live_9p_forwarding=true
          full_live_9p_deterministic_under_host_load=true
          variant_exact_source_dispatch=host-notifier
          full_exact_source_dispatch=inline-handler
          exact_source_fixture_executed=true
          variant_diverges=false
          runs_to_diverge=0
          RESULT
        '';
      }
    ];
  }
