##! Exposes source-built browser binding tools and their immutable runtime closure.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-bazel-wasm-tools";
  version = "1";
  src = null;
  sharedBuildCache = false;
  buildDeps = [pkgs.jq];
  outputChecks.out = {};
  exportReferencesGraph.wasm = [pkgs.wasm-bindgen-cli];
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s ${pkgs.wasm-bindgen-cli}/bin/wasm-bindgen "$out/bin/wasm-bindgen"
        jq -cS '{schema: 1, closure: [.wasm[] | {path, narHash}] | sort_by(.path)}' \
          "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
        cat > "$out/BUILD.bazel" <<'BUILD'
        exports_files(["bin/wasm-bindgen", "closure.json"], visibility = ["//visibility:public"])
        BUILD
        touch "$out/REPO.bazel"
      '';
    }
  ];
}
