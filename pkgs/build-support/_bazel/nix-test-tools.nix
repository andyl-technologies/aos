##! Declares the source-built Nix suite used by isolated selected-store tests.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-bazel-nix-test-tools";
  version = "1";
  src = null;
  sharedBuildCache = false;
  buildDeps = [pkgs.jq];
  outputChecks.out = {};
  exportReferencesGraph.tools = [pkgs.nix];
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s ${pkgs.nix}/bin/nix-store "$out/bin/nix-store"
        jq -cS '{schema: 1, closure: [.tools[] | {path, narHash}] | sort_by(.path)}' \
          "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
        cat > "$out/BUILD.bazel" <<'BUILD'
        exports_files(["bin/nix-store", "closure.json"], visibility = ["//visibility:public"])
        BUILD
        touch "$out/REPO.bazel"
      '';
    }
  ];
}
