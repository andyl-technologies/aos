{sourceGate, ...}: let
  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact > "$TMPDIR/test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed" not in output)' "$TMPDIR/test.log"
  '';
in {
  identity-idempotence = sourceGate "identity-idempotence" ''
    cd crates
    ${runTest "identity::tests::chunk_identity_matches_both_golden_vectors"}
    ${runTest "identity::tests::every_immutable_kind_has_a_distinct_registered_domain"}
    ${runTest "identity::tests::a_second_profile_cannot_reinterpret_initial_identities"}
    printf 'PASS: registered domains and profile-bound identities\n' > "$out/result"
  '';

  descriptor-strict = sourceGate "descriptor-strict" ''
    cd crates
    ${runTest "identity::tests::descriptor_rejects_mismatched_fields_and_bytes"}
    printf 'PASS: descriptor algorithm, domain, size, and digest validation\n' > "$out/result"
  '';
}
