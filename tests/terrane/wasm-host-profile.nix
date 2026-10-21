# Cross-compiles portable host bindings; native std filesystem qualification is separate.
{
  pkgs,
  sourceGateWithInputs,
}:
sourceGateWithInputs {
  extraBuildDeps = [pkgs.llvm];
  preserveArtifactBytes = true;
}
"wasm-host-profile" ''
  cd crates
  export CC_wasm32_unknown_unknown="${pkgs.llvm}/bin/clang"
  export AR_wasm32_unknown_unknown="${pkgs.llvm}/bin/llvm-ar"
  cargo build --frozen --offline --release --target wasm32-unknown-unknown \
    -p terrane-sdk --lib --no-default-features --features wasm \
    --message-format=json > "$out/build.jsonl"
  python3 ../tests/terrane/wasm_host_profile_proof.py
  printf 'PASS: actual wasm32 format and SDK host-binding library artifacts (compilation only)\n' \
    > "$out/result"
''
