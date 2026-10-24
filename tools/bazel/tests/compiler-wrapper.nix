##! Compares indirect input reconstruction with the pinned source-built wrapper.
{
  system ? builtins.currentSystem,
  pkgs ? (import ../../.. {inherit system;}).pkgs,
}: let
  rules = pkgs.aosBazelModules.rules_rust;
  tinyjson = pkgs.aosBazelRepositories."rules_rust++i+rules_rust_tinyjson";
  helpers = builtins.path {
    path = ./.;
    name = "aos-bazel-wrapper-evidence-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["compiler_wrapper.py" "verify_compiler_wrapper.py"];
  };
in
  pkgs.runCommand "aos-bazel-compiler-wrapper-conformance" {
    buildDeps = [pkgs.rust pkgs.python3];
    sharedBuildCache = false;
  } ''
    rustc --edition=2018 --crate-type=rlib --crate-name=tinyjson \
      ${tinyjson}/src/lib.rs -o libtinyjson.rlib
    rustc --edition=2018 --crate-name=process_wrapper \
      ${rules}/util/process_wrapper/main.rs \
      --extern tinyjson="$PWD/libtinyjson.rlib" -o process_wrapper
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${helpers}/verify_compiler_wrapper.py \
      --wrapper "$PWD/process_wrapper" --output "$out/conformance.json"
  ''
