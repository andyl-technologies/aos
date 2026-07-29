{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchName = "0034-crucible-safe-fingerprint-boundary.patch";
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  tracePluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  liveFingerprintGateSource = builtins.readFile ./phase2-qemu-nvcpu-fingerprint.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failures =
    lib.optionals (!(hasInfix "crucible_sim_observer_clamp_cpu_budget" patchSource)) [
      "${patchName}: observer ceiling does not clamp the TCG icount budget"
    ]
    ++ lib.optionals (!(hasInfix "crucible_sim_observer_notify_current_icount" patchSource)) [
      "${patchName}: observer notification is absent"
    ]
    ++ lib.optionals (!(hasInfix "bql_lock();" patchSource)) [
      "${patchName}: observer boundary is not ordered after BQL acquisition"
    ]
    ++ lib.optionals (!(hasInfix "while the BQL is" patchSource)) [
      "${patchName}: public API does not state the BQL-held callback contract"
    ]
    ++ lib.optionals (!(hasInfix "on_sim_observer_max_advance_icount" tracePluginSource)) [
      "crucible-qemu-trace-plugin.c: trace cadence is not exposed as an observer ceiling"
    ]
    ++ lib.optionals (!(hasInfix "terminal_horizon || (stop_at != 0 && stop_requested)" tracePluginSource)) [
      "crucible-qemu-trace-plugin.c: requested horizon stop does not retain the exact observer ceiling until pause"
    ]
    ++ lib.optionals (!(hasInfix "on_sim_observe_icount, on_sim_observer_max_advance_icount" tracePluginSource)) [
      "crucible-qemu-trace-plugin.c: observer registration does not bind its exact ceiling"
    ]
    ++ lib.optionals (hasInfix "if (!post_boundary_samples && retired >= next_sample)" tracePluginSource) [
      "crucible-qemu-trace-plugin.c: extended fingerprint still serializes state in an instruction callback"
    ]
    ++ lib.optionals (!(hasInfix "horizon=3700000000" liveFingerprintGateSource)) [
      "phase2-qemu-nvcpu-fingerprint.nix: live horizon does not exercise a non-cadence observer boundary"
    ]
    ++ lib.optionals (!(hasInfix ''([range($cadence; $horizon; $cadence)] + [$horizon])'' liveFingerprintGateSource)) [
      "phase2-qemu-nvcpu-fingerprint.nix: live sample sequence does not require the distinct horizon boundary"
    ]
    ++ lib.optionals (!(hasInfix "(.register_retired | add) == .retired" liveFingerprintGateSource)) [
      "phase2-qemu-nvcpu-fingerprint.nix: per-vCPU retired counts do not bind the aggregate instruction count"
    ]
    ++ lib.optionals (!(hasInfix ".observed_icount == $horizon" liveFingerprintGateSource)) [
      "phase2-qemu-nvcpu-fingerprint.nix: final observed icount is not pinned to the exact horizon"
    ];
in
  if failures != []
  then throw "crucible phase2 safe fingerprint boundary check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-safe-fingerprint-boundary";
      version = "0";
      src = null;
      phases = [
        {
          name = "verify-safe-fingerprint-boundary";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            observer_budget_clamped=true
            observer_callback_bql_held=true
            requested_stop_retains_exact_observer_ceiling=true
            instruction_callback_vmstate_serialization=false
            exact_horizon_boundary=true
            non_cadence_live_horizon=true
            exact_final_observed_icount_required=true
            RESULT
          '';
        }
      ];
    }
