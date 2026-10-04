{sourceGate, ...}: let
  runTests = filter: ''
    cargo test --frozen --offline -p terrane-core --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';
in {
  tree-boundaries = sourceGate "tree-boundaries" ''
    cd crates
    ${runTests "tree_builder::tests::tree_boundaries"}
    printf 'PASS: canonical full-key boundaries, balanced levels, exact summaries, and node caps\n' > "$out/result"
  '';

  tree-history-independence = sourceGate "tree-history-independence" ''
    cd crates
    ${runTests "tree_history_independence"}
    ${runTests "tree_builder::batch_tests::tree_history_independence_batches_overlapping_sparse_edits -- --exact"}
    ${runTests "tree_builder::batch_tests::tree_history_independence_preserves_distant_subtrees_and_atomic_validation -- --exact"}
    ${runTests "tree_builder::batch_tests::tree_history_independence_accounts_for_actual_boundary_work -- --exact"}
    printf 'PASS: persistent batched edits, deterministic replay, measured boundary work, and subtree reuse\n' > "$out/result"
  '';
}
