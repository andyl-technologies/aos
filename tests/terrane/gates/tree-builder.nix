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
    printf 'PASS: persistent edits, deterministic replay, history independence, and subtree reuse\n' > "$out/result"
  '';
}
