{pkgs}: let
  source = builtins.readFile ./phase0-parallelism.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-multi-vm-parallelism";
    version = "0";
    src = null;

    inherit source;
    passAsFile = ["source"];

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
    ];

    phases = [
      {
        name = "run-multi-vm-parallelism";
        script = ''
          set -eu

          cp "$sourcePath" phase0-parallelism.c
          cc -std=c11 -O2 -Wall -Wextra -Werror phase0-parallelism.c -o phase0-parallelism

          mkdir -p "$out"
          ./phase0-parallelism > "$out/result"
          grep -q '^PASS$' "$out/result"
          grep -q '^scenario=conservative-lookahead-cost-model$' "$out/result"
          grep -q '^topology=uniform-full-mesh$' "$out/result"
          grep -q '^host_core_parallelism_kind=modeled$' "$out/result"
          grep -q '^vm_nodes=4$' "$out/result"
          grep -q '^host_cores=4$' "$out/result"
          grep -q '^simulated_horizon_vt=1048576$' "$out/result"
          grep -q '^min_link_latency_floor=512$' "$out/result"
          grep -q '^sync_cost_units=48$' "$out/result"
          grep -q '^dispatch_cost_units=2$' "$out/result"
          grep -q '^target_parallelism_x1000=3500$' "$out/result"
          grep -q '^declared_zero_latency_rejected=1$' "$out/result"
          grep -q '^declared_subfloor_latency_rejected=1$' "$out/result"
          grep -q '^subfloor_fault_input_latency=128$' "$out/result"
          grep -q '^subfloor_fault_effective_latency=512$' "$out/result"
          grep -q '^raised_fault_input_latency=2048$' "$out/result"
          grep -q '^raised_fault_effective_latency=2048$' "$out/result"
          grep -q '^unfloored_latency_64_parallelism_x1000=2133$' "$out/result"
          grep -q '^monotonic_parallelism=1$' "$out/result"
          grep -q '^halving_sync_frequency=1$' "$out/result"
          grep -q '^sample_0_latency=512$' "$out/result"
          grep -q '^sample_0_lookahead=512$' "$out/result"
          grep -q '^sample_0_windows=2048$' "$out/result"
          grep -q '^sample_0_busy_units=4194304$' "$out/result"
          grep -q '^sample_0_makespan_units=1163264$' "$out/result"
          grep -q '^sample_0_parallelism_x1000=3605$' "$out/result"
          grep -q '^sample_1_latency=1024$' "$out/result"
          grep -q '^sample_1_lookahead=1024$' "$out/result"
          grep -q '^sample_1_windows=1024$' "$out/result"
          grep -q '^sample_1_busy_units=4194304$' "$out/result"
          grep -q '^sample_1_makespan_units=1105920$' "$out/result"
          grep -q '^sample_1_parallelism_x1000=3792$' "$out/result"
          grep -q '^sample_2_latency=2048$' "$out/result"
          grep -q '^sample_2_lookahead=2048$' "$out/result"
          grep -q '^sample_2_windows=512$' "$out/result"
          grep -q '^sample_2_busy_units=4194304$' "$out/result"
          grep -q '^sample_2_makespan_units=1077248$' "$out/result"
          grep -q '^sample_2_parallelism_x1000=3893$' "$out/result"
          grep -q '^sample_3_latency=4096$' "$out/result"
          grep -q '^sample_3_lookahead=4096$' "$out/result"
          grep -q '^sample_3_windows=256$' "$out/result"
          grep -q '^sample_3_busy_units=4194304$' "$out/result"
          grep -q '^sample_3_makespan_units=1062912$' "$out/result"
          grep -q '^sample_3_parallelism_x1000=3946$' "$out/result"
          grep -q '^floor_parallelism_x1000=3605$' "$out/result"
          grep -q '^modeled_recommended_latency=1024$' "$out/result"
          grep -q '^modeled_recommended_parallelism_x1000=3792$' "$out/result"
          grep -q '^max_latency_parallelism_x1000=3946$' "$out/result"
          grep -q '^floor_vs_unfloored_subfloor_ratio_x1000=1690$' "$out/result"
          cp phase0-parallelism.c "$out/source.c"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 multi-VM lookahead parallelism spike";
    };
  }
