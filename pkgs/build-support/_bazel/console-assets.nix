##! Exposes the verified browser package as explicit service generator inputs.
{
  pkgs,
  build,
}: let
  console = pkgs.mkAosBazelPackage {
    pname = "aos-hub-console";
    version = "0.1.0";
    inherit build;
    packageLabel = "//crates/hub/aos-hub-console:browser_dist";
  };
in
  pkgs.mkDerivation {
    pname = "aos-bazel-console-assets";
    version = "1";
    src = null;
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    passthru.bazelBuild = build;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          ln -s ${console}/hub-console.js "$out/hub-console.js"
          ln -s ${console}/hub-console_bg.wasm "$out/hub-console_bg.wasm"
          ln -s ${console}/hub-console.css "$out/hub-console.css"
          ln -s ${console}/nix-support/bazel-package.json "$out/manifest.json"
          cat > "$out/BUILD.bazel" <<'BUILD'
          package(default_visibility = ["//visibility:public"])

          filegroup(
              name = "javascript",
              srcs = ["hub-console.js"],
              tags = ["aos-license:apache-host"],
          )

          filegroup(
              name = "wasm",
              srcs = ["hub-console_bg.wasm"],
              tags = ["aos-license:apache-host"],
          )

          filegroup(
              name = "stylesheet",
              srcs = ["hub-console.css"],
              tags = ["aos-license:apache-host"],
          )

          exports_files(["manifest.json"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
