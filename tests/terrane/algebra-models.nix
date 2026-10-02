{sourceGate}: let
  tests = [
    "published_overlay_models_preserve_order_and_optional_domain_presence"
    "published_graft_models_preserve_complete_entry_replacement_and_arguments"
    "published_merge_models_preserve_operand_policy_and_inert_trust_fields"
    "published_negative_recipe_wires_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test algebra_vectors ${name} -- --exact \
      > "$TMPDIR/algebra-model-test.log" 2>&1; then
      cat "$TMPDIR/algebra-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/algebra-model-test.log"
  '';
in
  sourceGate "algebra-format-vectors" ''
    cd crates
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/algebra_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/algebra_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test algebra_vectors -- -D warnings
    printf 'PASS: seventeen published recipe models and four exact public-model groups\n' > "$out/result"
  ''
