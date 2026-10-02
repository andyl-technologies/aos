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
    ${runTest "identity::descriptor::tests::published_descriptor_codec_preserves_bytes_and_model"}
    ${runTest "identity::descriptor::tests::descriptor_codec_roundtrips_every_domain_and_size_boundary"}
    ${runTest "identity::descriptor::tests::descriptor_codec_rejects_unknown_fields_and_noncanonical_shapes"}
    ${runTest "identity::descriptor::tests::descriptor_codec_rejects_oversized_headers_before_owned_allocation"}
    ${runTest "identity::descriptor::tests::descriptor_codec_bounds_follow_the_actual_configured_profile"}
    printf 'PASS: descriptor algorithm, domain, size, and digest validation\n' > "$out/result"
  '';
}
