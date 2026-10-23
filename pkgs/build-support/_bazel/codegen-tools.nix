##! Declares the source-built protobuf compiler and its immutable runtime closure.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-bazel-codegen-tools";
  version = "1";
  src = null;
  sharedBuildCache = false;
  buildDeps = [pkgs.jq];
  outputChecks.out = {};
  exportReferencesGraph.codegen = [pkgs.protobuf];
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s ${pkgs.protobuf}/bin/protoc "$out/bin/protoc"
        ln -s ${pkgs.protobuf}/include "$out/include"
        jq -cS '{schema: 1, closure: [.codegen[] | {path, narHash}] | sort_by(.path)}' \
          "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
        cat > "$out/BUILD.bazel" <<'BUILD'
        exports_files(["bin/protoc"], visibility = ["//visibility:public"])

        filegroup(
            name = "protoc_files",
            srcs = glob(["include/**/*.proto"]) + ["closure.json"],
            visibility = ["//visibility:public"],
        )
        BUILD
        touch "$out/REPO.bazel"
      '';
    }
  ];
}
