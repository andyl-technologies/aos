# Build only the reviewed boundary-pair emitter from the declared auxiliary source.
{ pkgs }:
let
  native = pkgs.aos-hub;
  evidence = native.passthru.evidenceSources;
in
assert builtins.length evidence == 2;
pkgs.mkCargoPackage {
  pname = "aos-pack-memory-fixture";
  version = "0.1.0";
  src = native.src;
  cargoRoot = "crates";
  cargoDeps = builtins.elemAt evidence 1;
  cargoFlags = "-p aos-registry-surface --example pack_memory_fixture";
  buildDeps = [ pkgs.perl pkgs.pkg-config ];
  installBins = false;
  doCheck = false;

  postInstall = ''
    selected="$NIX_BUILD_TOP/pack-fixture-executable"
    jq -r '
      select(.reason == "compiler-artifact"
        and .target.name == "pack_memory_fixture"
        and .target.kind == ["example"]
        and .profile.test == false)
      | .executable // empty
    ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u > "$selected"
    test "$(wc -l < "$selected")" -eq 1
    IFS= read -r executable < "$selected"
    test -f "$executable" && test -x "$executable"
    mkdir -p "$out/bin"
    install -m 755 "$executable" "$out/bin/aos-pack-memory-fixture"
  '';

  passthru = {
    commonFilteredSourceStorePath = toString native.src;
  };
  meta.description = "Fixture-only current pack graph boundary-pair emitter";
}
