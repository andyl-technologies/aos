{pkgs}: let
  source = builtins.readFile ./phase0-s4-shmem-visibility.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s4-shmem-visibility";
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
        name = "run-s4-shmem-visibility";
        script = ''
          set -eu

          cp "$sourcePath" phase0-s4-shmem-visibility.c
          cc -std=c11 -O2 -Wall -Wextra -Werror phase0-s4-shmem-visibility.c -o phase0-s4-shmem-visibility

          mkdir -p "$out"
          timeout 120 ./phase0-s4-shmem-visibility > "$out/result"
          grep -q '^PASS$' "$out/result"
          grep -q '^spike=producer-consumer-shmem-visibility$' "$out/result"
          grep -q '^check=checks.crucible.phase0.s4ShmemVisibility$' "$out/result"
          grep -q '^model=shmem_scheduler_node_double$' "$out/result"
          grep -q '^shared_memory=MAP_SHARED$' "$out/result"
          grep -q '^ring_ordering=release_acquire_spsc$' "$out/result"
          grep -q '^source_nodes=2$' "$out/result"
          grep -q '^consumer_nodes=1$' "$out/result"
          grep -q '^rings=2$' "$out/result"
          grep -q '^frames_per_source=16$' "$out/result"
          grep -q '^total_frames=32$' "$out/result"
          grep -q '^delivery_groups=8$' "$out/result"
          grep -q '^run_x_skew=producer_publish_path$' "$out/result"
          grep -q '^run_y_skew=consumer_poll_path$' "$out/result"
          grep -q '^delivery_rule=delivery_icount_lte_current_icount$' "$out/result"
          grep -q '^tie_break_key=delivery_icount_src_node_seq$' "$out/result"
          grep -q '^consumer_ceiling=delivery_icount_minus_1_until_group_present$' "$out/result"
          grep -q '^producer_skew_ceiling_wait_observed=true$' "$out/result"
          grep -q '^consumer_skew_early_peek_observed=true$' "$out/result"
          grep -q '^arrival_order_differs=true$' "$out/result"
          grep -q '^publish_order_unique_nonzero=true$' "$out/result"
          grep -q '^visibility_vectors_match=true$' "$out/result"
          grep -q '^visibility_icounts_equal_delivery_icount=true$' "$out/result"
          grep -q '^injection_order_match=true$' "$out/result"
          grep -q '^arrival_order_negative_control_failed=true$' "$out/result"
          grep -q '^late_enqueue_negative_control_failed=true$' "$out/result"
          grep -q '^late_delivery_failures=0$' "$out/result"
          grep -q '^early_delivery_failures=0$' "$out/result"
          grep -q '^late_enqueue_failures=0$' "$out/result"
          grep -q '^fallback_adopted=false$' "$out/result"
          grep -q '^scope=phase0_shmem_visibility_discipline_not_qemu_device_injection$' "$out/result"
          grep -q '^s4_complete=true$' "$out/result"
          cp phase0-s4-shmem-visibility.c "$out/source.c"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S4 shared-memory visibility discipline spike";
    };
  }
