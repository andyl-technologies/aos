{sourceGate, ...}: {
  cdc-boundaries = sourceGate "cdc-boundaries" ''
    cd crates
    cargo test --frozen --offline -p terrane-core chunking::tests
    cargo test --frozen --offline -p terrane codec::tests::admission_requires_identity_size_and_first_nonfinal_boundary
    printf 'PASS: seeded FastCDC boundaries and profile edge cases\n' > "$out/result"
  '';

  chunk-codec = sourceGate "chunk-codec" ''
    cd crates
    cargo test --frozen --offline -p terrane-core codec::tests
    cargo test --frozen --offline -p terrane codec::tests
    printf 'PASS: chunk envelope, frame, dictionary, and receiver checks\n' > "$out/result"
  '';

  chunk-bomb-cap = sourceGate "chunk-bomb-cap" ''
    cd crates
    cargo test --frozen --offline -p terrane codec::tests::rejects_bomb_header_truncated_frame_and_trailing_frame
    cargo test --frozen --offline -p terrane codec::tests::bounded_decoder_rejects_a_frame_with_false_content_size
    printf 'PASS: declared length and bounded decompression\n' > "$out/result"
  '';

  zstd-concat = sourceGate "zstd-concat" ''
    cd crates
    cargo test --frozen --offline -p terrane codec::tests::same_codec_frames_concatenate_to_object_plaintext
    cargo test --frozen --offline -p terrane codec::tests::dictionary_frames_require_the_same_verified_dictionary
    printf 'PASS: independently encoded frames concatenate in manifest order\n' > "$out/result"
  '';
}
