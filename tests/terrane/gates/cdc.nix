{
  sourceGate,
  ...
}: {
  cdc-boundaries = sourceGate "cdc-boundaries" ''
    cd crates
    cargo test --frozen --offline -p terrane-core chunking::tests
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
    printf 'PASS: declared length and bounded decompression\n' > "$out/result"
  '';

  zstd-concat = sourceGate "zstd-concat" ''
    cd crates
    cargo test --frozen --offline -p terrane codec::tests::same_codec_frames_concatenate_to_object_plaintext
    printf 'PASS: independently encoded frames concatenate in manifest order\n' > "$out/result"
  '';
}
