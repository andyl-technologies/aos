{sourceGate}: let
  names = [
    "mixed_selection_keeps_legacy_parent_and_recorded_candidate"
    "mixed_selection_keeps_recorded_one_inert_names"
    "mixed_selection_requires_recorded_ancestor_mapping"
    "mixed_selection_refuses_conflicting_view_or_root"
    "mixed_selection_distinguishes_shared_root_view_contexts"
    "mixed_disclosure_finishes_with_legacy_dependency"
    "mixed_disclosure_finishes_with_recorded_one_dependency"
    "mixed_disclosure_refuses_scope_mode_substitution"
  ];
  selectors = map (name: "provenance::tests::mixed_interpretations::${name}") names;
in
  # Per-view interpretation is ordinary configuration. Successful disclosure
  # still requires the existing complete history and original-scope verifier.
  sourceGate "mixed-view-interpretation" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib -- --list \
      > "$TMPDIR/mixed-view-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/mixed-view-tests.txt" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! cargo test --frozen --offline -p terrane-core --lib "$test_name" -- --exact \
        > "$TMPDIR/mixed-view-test.log" 2>&1; then
        cat "$TMPDIR/mixed-view-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/mixed-view-test.log" "[\"$test_name\"]"
    done
    cargo build --frozen --offline -p terrane-core --no-default-features --lib
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    RUSTDOCFLAGS='-D warnings -D missing_docs' cargo doc --frozen --offline \
      -p terrane-core --no-deps --document-private-items
    printf 'PASS: eight exact per-view interpretation cases and strict portable Core checks\n' \
      > "$out/result"
  ''
