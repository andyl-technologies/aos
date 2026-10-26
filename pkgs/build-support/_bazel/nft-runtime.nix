##! Declares the packaged nft executable embedded in the native handler.
{
  runCommand,
  nftables,
}:
runCommand "aos-bazel-nft-runtime" {} ''
  mkdir -p "$out"
  cat > "$out/executable.env" <<'ENVIRONMENT'
  AOS_NFT_EXECUTABLE=${nftables}/sbin/nft
  ENVIRONMENT
  cat > "$out/BUILD.bazel" <<'BUILD'
  exports_files(["executable.env"], visibility = ["//visibility:public"])
  BUILD
  touch "$out/REPO.bazel"
''
