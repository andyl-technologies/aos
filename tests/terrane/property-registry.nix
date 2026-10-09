{sourceGate}: let
  tests = [
    "gc::publication::evidence::cbor::tests::guard::property_revisions_preserve_legacy_and_bind_index_roots_exactly"
    "gc::publication::evidence::cbor::tests::guard::property_revision_vocabulary_mismatches_refuse"
    "gc::publication::evidence::validation::policy::tests::later_property_names_remain_inert_under_their_recorded_revision"
    "gc::publication::evidence::cbor::tests::lineage::enclosing_lineage_preserves_recorded_inert_property_names"
    "gc::publication::evidence::validation::policy::private_registry_tests::property_and_attribute_revisions_bind_structural_index_names_exactly"
    "gc::publication::evidence::validation::policy::private_registry_tests::legacy_semantic_contexts_preserve_inert_index_carriers"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact \
      > "$TMPDIR/property-registry-test.log" 2>&1; then
      cat "$TMPDIR/property-registry-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/property-registry-test.log"
  '';
in
  sourceGate "property-registry" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: immutable property revisions and inert later-name fences\n' > "$out/result"
  ''
