# Qualifies structural metadata and inode policy, independently of FUSE mounts.
{
  pkgs,
  sourceGateWithInputs,
}: let
  sourceGate = sourceGateWithInputs {
    preserveArtifactBytes = true;
    runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
    nukeRefsKeep = [pkgs.terrane.src];
  };
in
  sourceGate "structural-index" ''
    cd crates
    cargo test --frozen --offline -p terrane-linux --no-default-features \
      --features surface-fuse --lib --no-run --message-format=json > "$out/build.jsonl"
    python3 ../tests/terrane/structural_index_proof.py
    printf '%s\n' PASS > "$out/result"
  ''
