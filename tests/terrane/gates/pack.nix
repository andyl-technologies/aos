{sourceGate, ...}: let
  runTests = filter: ''
    cargo test --frozen --offline -p terrane --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';

  testGate = name: filter:
    sourceGate name ''
      cd crates
      ${runTests filter}
      printf 'PASS: ${name}\n' > "$out/result"
    '';
in {
  pack-header = sourceGate "pack-header" ''
    cd crates
    ${runTests "pack::tests::pack_header_"}
    cargo test --frozen --offline -p terrane-core --lib pack_format::tests > "$TMPDIR/core-test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/core-test.log"
    printf 'PASS: native headers and portable complete pack/shard/bundle formats\n' > "$out/result"
  '';
  pack-id-unique = testGate "pack-id-unique" "pack::tests::pack_id_";
  pack-index-sorted = testGate "pack-index-sorted" "pack::tests::pack_index_is_sorted_";
  pack-index-consistent = testGate "pack-index-consistent" "pack::tests::pack_index_rejects_";
  pack-kind-domain = testGate "pack-kind-domain" "pack::tests::pack_meta_separation_";
  pack-footer-crc = testGate "pack-footer-crc" "pack::tests::pack_footer_crc_";
  pack-scan-recovery = testGate "pack-scan-recovery" "pack::tests::pack_scan_recovery_";
  pack-self-describing = sourceGate "pack-self-describing" ''
    cd crates
    ${runTests "pack::tests::pack_self_describing_"}
    ${runTests "pack::tests::pack_native_codecs_"}
    printf 'PASS: embedded indexes and verified native body codecs\n' > "$out/result"
  '';
  pack-single-writer = testGate "pack-single-writer" "pack::tests::pack_single_writer_";
  pack-tree-locality = testGate "pack-tree-locality" "pack::tests::pack_tree_locality_";
  pack-meta-separation = testGate "pack-meta-separation" "pack::tests::pack_meta_separation_";
  pack-idx-object = testGate "pack-idx-object" "pack::tests::pack_self_describing_";
  index-shard-generations = testGate "index-shard-generations" "pack::tests::index_shard_generations_";
  index-tombstones = testGate "index-tombstones" "pack::tests::index_tombstones_";
  index-rebuild = testGate "index-rebuild" "pack::tests::index_rebuild_";
  bundle-verify = testGate "bundle-verify" "pack::tests::bundle_verify_";
}
