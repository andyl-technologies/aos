{
  sourceGate,
  nativeSdkGate,
  ...
}: let
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

  runNativeTest = name:
    import ../_native-cases.nix {
      label = "cdc-" + builtins.hashString "sha256" name;
      selectors = [name];
      enterCrates = false;
    };
in {
  object-identity-from-manifest = sourceGate "object-identity-from-manifest" ''
    cd crates
    ${runTests}
    run_tests -p terrane-format manifest::tests
    printf 'PASS: canonical manifests and identity from known chunk references\n' > "$out/result"
  '';

  cdc-boundaries = nativeSdkGate "cdc-boundaries" ''
    cd crates
    ${runTests}
    run_tests -p terrane-format chunking::tests
    run_tests -p terrane-sdk codec::tests::admission_requires_identity_size_and_first_nonfinal_boundary
    run_tests -p terrane-sdk --lib codec::tests::object_final_chunks_require_the_first_boundary_while_dictionaries_remain_standalone -- --exact
    run_tests -p terrane-sdk --lib derived::tests::object_boundary_tests::derived_object_reads_reject_a_final_chunk_with_an_earlier_boundary -- --exact
    ${runNativeTest "bucket::manifest_tests::manifest_admission_rechecks_nonfinal_context_after_inventory_only_import"}
    ${runNativeTest "bucket::manifest_tests::canonical_final::manifest_admission_rejects_a_final_chunk_with_an_earlier_boundary"}
    printf 'PASS: seeded FastCDC boundaries and profile edge cases\n' > "$out/result"
  '';

  chunk-codec = nativeSdkGate "chunk-codec" ''
    cd crates
    ${runTests}
    run_tests -p terrane-format codec::tests
    run_tests -p terrane-sdk codec::tests
    ${runNativeTest "guard::read::dictionary_tests::registered_dictionary_codecs_round_trip_through_guarded_content"}
    ${runNativeTest "guard::read::dictionary_tests::dictionary_dependency_validation_precedes_plaintext_exposure"}
    ${runNativeTest "ref_advance::disclosure_tests::disclosure_dictionary_dependencies_preserve_registered_codecs_and_verified_lengths"}
    printf 'PASS: chunk envelope, frame, dictionary, and receiver checks\n' > "$out/result"
  '';

  chunk-bomb-cap = sourceGate "chunk-bomb-cap" ''
    cd crates
    ${runTests}
    run_tests -p terrane-sdk codec::tests::rejects_bomb_header_truncated_frame_and_trailing_frame
    run_tests -p terrane-sdk codec::tests::bounded_decoder_rejects_a_frame_with_false_content_size
    run_tests -p terrane-sdk --lib codec::tests::public_decoder_rejects_false_content_sizes_for_both_compressed_codecs -- --exact
    printf 'PASS: declared length and bounded decompression\n' > "$out/result"
  '';

  zstd-concat = sourceGate "zstd-concat" ''
    cd crates
    ${runTests}
    run_tests -p terrane-sdk codec::tests::same_codec_frames_concatenate_to_object_plaintext
    run_tests -p terrane-sdk codec::tests::dictionary_frames_require_the_same_verified_dictionary
    printf 'PASS: independently encoded frames concatenate in manifest order\n' > "$out/result"
  '';
}
