{sourceGate}: let
  tests = [
    "reference_local_reconciliation_preserves_complete_fields"
    "reference_local_reconciliation_rejects_independent_malformed_wires"
    "reference_local_reconciliation_applies_limits_before_retaining_fields"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test reconciliation_vectors ${name} -- --exact \
      > "$TMPDIR/reconciliation-model-test.log" 2>&1; then
      cat "$TMPDIR/reconciliation-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/reconciliation-model-test.log"
  '';
in
  sourceGate "reconciliation-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/reconciliation_vectors.py || ! test -f ../tests/terrane/reconciliation-models.rs; then
      printf 'The registered local reconciliation codec and independent field models remain pending.\n' >&2
      exit 1
    fi
    python3 ../tests/terrane/reconciliation_vectors.py --self-check > "$out/reference-result"
    python3 ../tests/terrane/reconciliation_vectors.py --emit > ../tests/terrane/reconciliation-reference.md
    python3 ../tests/terrane/reconciliation_vectors.py --check ../tests/terrane/reconciliation-reference.md >> "$out/reference-result"
    cp ../tests/terrane/reconciliation-reference.md "$out/reference.md"
    cp ../tests/terrane/reconciliation-models.rs terrane-core/tests/reconciliation_vectors.rs
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test reconciliation_vectors -- -D warnings
    printf 'PASS: ordinary local reconciliation fields and three exact pure codec groups\n' > "$out/result"
  ''
