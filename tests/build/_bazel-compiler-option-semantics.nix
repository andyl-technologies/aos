##! Checks option evidence against native source-built rustc behavior.
{pkgs}: let
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-compiler-option-semantics-tools";
    filter = path: type:
      type
      == "directory"
      || builtins.elem (baseNameOf path) [
        "verify_compiler_option_semantics.py"
        "verify_compiler_options.py"
        "verify_cache.py"
        "reconstruct_compiler_inputs.py"
        "retain_compiler_inputs.py"
        "compiler_wrapper.py"
        "verify_static_runtime.py"
      ];
  };
in
  pkgs.runCommand "aos-bazel-compiler-option-semantics" {
    buildDeps = [pkgs.python3 pkgs.rust];
  } ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
      ${scripts}/verify_compiler_option_semantics.py \
      --rustc ${pkgs.rust}/bin/rustc --output "$out/evidence.json"
  ''
