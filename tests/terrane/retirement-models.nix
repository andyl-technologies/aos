{sourceGate}: let
  tests = [
    "reference_retirement_authorization_models_preserve_alternative_fields"
    "reference_retirement_preparation_models_preserve_nested_plan_fields"
    "reference_retirement_operation_models_preserve_phase_and_pointer_fields"
    "reference_retirement_pass_models_preserve_complete_observation_fields"
    "reference_retirement_fence_models_preserve_nested_record_fields"
    "reference_retirement_owner_models_preserve_disjoint_selection_fields"
    "reference_negative_retirement_wires_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test retirement_vectors ${name} -- --exact \
      > "$TMPDIR/retirement-model-test.log" 2>&1; then
      cat "$TMPDIR/retirement-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/retirement-model-test.log"
  '';
in
  sourceGate "retirement-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/retirement-models.rs || ! test -d ../tests/terrane/retirement_models; then
      printf 'Independent retirement record field models remain pending implementation.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/retirement_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/retirement_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/retirement-reference.md
    cp ../tests/terrane/retirement-reference.md "$out/reference.md"
    cp ../tests/terrane/retirement-models.rs terrane-core/tests/retirement_vectors.rs
    cp -r ../tests/terrane/retirement_models terrane-core/tests/retirement_models
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test retirement_vectors -- -D warnings
    printf 'PASS: independent record field models and seven exact owning-codec groups\n' > "$out/result"
  ''
