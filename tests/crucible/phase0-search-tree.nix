{pkgs}: let
  source = builtins.readFile ./phase0-search-tree.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-search-tree-growth";
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
        name = "run-search-tree-growth";
        script = ''
          set -eu

          cp "$sourcePath" phase0-search-tree.c
          cc -std=c11 -O2 -Wall -Wextra -Werror phase0-search-tree.c -o phase0-search-tree

          mkdir -p "$out"
          ./phase0-search-tree > "$out/result"
          grep -q '^PASS$' "$out/result"
          grep -q '^scenario=pending-message-fault-temporal-graph$' "$out/result"
          grep -q '^replicas=4$' "$out/result"
          grep -q '^pending_message_slots=14$' "$out/result"
          grep -q '^max_faults=4$' "$out/result"
          grep -q '^search_depth_limit=4$' "$out/result"
          grep -q '^raw_depth_limit=5$' "$out/result"
          grep -q '^checkpoint_bytes=192$' "$out/result"
          grep -q '^raw_branching_proxy=46812255$' "$out/result"
          grep -q '^bounded_seen_nodes=351$' "$out/result"
          grep -q '^bounded_accepted_nodes=351$' "$out/result"
          grep -q '^bounded_expanded_nodes=102$' "$out/result"
          grep -q '^bounded_raw_edges=1009$' "$out/result"
          grep -q '^bounded_reduced_edges=823$' "$out/result"
          grep -q '^partial_order_skipped_edges=0$' "$out/result"
          grep -q '^symmetry_skipped_edges=186$' "$out/result"
          grep -q '^dedup_hits=35$' "$out/result"
          grep -q '^frontier_pruned=687$' "$out/result"
          grep -q '^frontier_dropped=438$' "$out/result"
          grep -q '^frontier_replaced=249$' "$out/result"
          grep -q '^bounded_max_frontier=64$' "$out/result"
          grep -q '^frontier_budget=64$' "$out/result"
          grep -q '^uncapped_seen_nodes=66349$' "$out/result"
          grep -q '^uncapped_expanded_nodes=66349$' "$out/result"
          grep -q '^uncapped_max_frontier=12512$' "$out/result"
          grep -q '^uncapped_frontier_pruned=0$' "$out/result"
          grep -q '^accepted_coverage_bits=47$' "$out/result"
          grep -q '^expanded_coverage_bits=47$' "$out/result"
          grep -q '^uncapped_expanded_coverage_bits=48$' "$out/result"
          grep -q '^required_accepted_coverage_bits=32$' "$out/result"
          grep -q '^required_expanded_coverage_bits=24$' "$out/result"
          grep -q '^estimated_store_bytes=67392$' "$out/result"
          grep -q '^store_budget_bytes=196608$' "$out/result"
          grep -q '^dedup_compression_ratio_x1000=133368247$' "$out/result"
          grep -q '^seen_saturated=0$' "$out/result"
          cp phase0-search-tree.c "$out/source.c"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 search-tree growth spike";
    };
  }
