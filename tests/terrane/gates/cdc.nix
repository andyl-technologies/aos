{sourceGate, ...}: let
  # Cargo's ordinary name filters allow empty success; every gate must exercise
  # a matching test, even after test modules are reorganized.
  runTests = ''
    run_tests() {
      if cargo test --frozen --offline "$@" > test-output 2>&1; then
        :
      else
        cat test-output >&2
        return 1
      fi
      cat test-output
      if ! python3 -c 'import re, pathlib, sys; sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed", pathlib.Path("test-output").read_text()))'; then
        printf 'gate filter executed no tests\n' >&2
        exit 1
      fi
    }
  '';
in {
  object-identity-from-manifest = sourceGate "object-identity-from-manifest" ''
    cd crates
    ${runTests}
    run_tests -p terrane-core manifest::tests
    printf 'PASS: canonical manifests and identity from known chunk references\n' > "$out/result"
  '';

  cdc-boundaries = sourceGate "cdc-boundaries" ''
    cd crates
    ${runTests}
    run_tests -p terrane-core chunking::tests
    run_tests -p terrane codec::tests::admission_requires_identity_size_and_first_nonfinal_boundary
    printf 'PASS: seeded FastCDC boundaries and profile edge cases\n' > "$out/result"
  '';

  chunk-codec = sourceGate "chunk-codec" ''
    cd crates
    ${runTests}
    run_tests -p terrane-core codec::tests
    run_tests -p terrane codec::tests
    run_tests -p terrane --no-default-features --features tokio,surface-sdk --lib guard::read::dictionary_tests::registered_dictionary_codecs_round_trip_through_guarded_content -- --exact
    run_tests -p terrane --no-default-features --features tokio,surface-sdk --lib guard::read::dictionary_tests::dictionary_dependency_validation_precedes_plaintext_exposure -- --exact
    run_tests -p terrane --no-default-features --features tokio,surface-sdk --lib ref_advance::disclosure_tests::disclosure_dictionary_dependencies_preserve_registered_codecs_and_verified_lengths -- --exact
    printf 'PASS: chunk envelope, frame, dictionary, and receiver checks\n' > "$out/result"
  '';

  chunk-bomb-cap = sourceGate "chunk-bomb-cap" ''
    cd crates
    ${runTests}
    run_tests -p terrane codec::tests::rejects_bomb_header_truncated_frame_and_trailing_frame
    run_tests -p terrane codec::tests::bounded_decoder_rejects_a_frame_with_false_content_size
    printf 'PASS: declared length and bounded decompression\n' > "$out/result"
  '';

  zstd-concat = sourceGate "zstd-concat" ''
    cd crates
    ${runTests}
    run_tests -p terrane codec::tests::same_codec_frames_concatenate_to_object_plaintext
    run_tests -p terrane codec::tests::dictionary_frames_require_the_same_verified_dictionary
    printf 'PASS: independently encoded frames concatenate in manifest order\n' > "$out/result"
  '';
}
