##! Executes target/execution build-script profiles with a real libm dependency.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  prefix = "//tools/bazel/qualification/build-script-profile:";
  configurations = ["default" "release" "editor" "wasm"];
  candidate = name: let
    workspace = pkgs.mkAosBazelWorkspace ({
        root = ../../..;
        sourceDirectories = [
          "tools/bazel/toolchains"
          "tools/bazel/rules"
          "tools/bazel/metadata"
          "tools/bazel/qualification/build-script-profile"
        ];
        repositories =
          pkgs.aosBazelRepositories
          // {"aos_aos_cli_tests_crates__libm-0.2.16" = pkgs.aosBazelRustRepositories.aos-cli-tests."aos_aos_cli_tests_crates__libm-0.2.16";};
        rustcFlags =
          if name == "editor"
          then ["-Copt-level=0" "-Cdebuginfo=2"]
          else ["-Copt-level=s" "-Cdebuginfo=0"];
        execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0"];
        cargoProfile =
          if name == "release"
          then "release"
          else "debug";
        analysisTargets = ["${prefix}library"];
        batch = true;
        jobs = 2;
      }
      // pkgs.lib.optionalAttrs (name == "wasm") {
        targetPlatform = "//tools/bazel/toolchains:wasm32";
      });
  in
    pkgs.mkAosBazelBuild {
      pname = "aos-bazel-build-script-profile-${name}";
      inherit workspace;
      targets = ["${prefix}library"];
      retainActionGraph = true;
      sharedBuildCache = false;
    };
  builds = pkgs.lib.genAttrs configurations candidate;
  inputs = pkgs.writeTextFile {
    name = "aos-bazel-build-script-profile-builds.json";
    text = builtins.toJSON (builtins.mapAttrs (_: toString) builds);
  };
  verifierInputs = builtins.path {
    path = ../tests;
    name = "aos-bazel-build-script-profile-verifier-inputs";
    filter = path: type:
      type
      == "regular"
      && builtins.elem (baseNameOf path) [
        "compiler_wrapper.py"
        "reconstruct_compiler_inputs.py"
        "retain_compiler_inputs.py"
        "verify_cache.py"
        "verify_compiler_options.py"
        "verify_static_runtime.py"
      ];
  };
in {
  inherit builds;
  check = pkgs.runCommand "aos-bazel-qualified-build-script-profiles" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${verifierInputs}
    ${pkgs.python3}/bin/python3 ${./build_script_profiles.py} \
      --builds ${inputs} --output "$out/evidence.json"
  '';
}
