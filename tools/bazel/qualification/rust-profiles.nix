##! Requires native test parity and complete selected Rust profile inventories.
{
  pkgs,
  pname,
  build,
  cargo,
  parity,
}: let
  verifier = builtins.path {
    path = ./.;
    name = "aos-bazel-family-profile-verifier";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["rust_profiles.py" "test_rust_profiles.py"];
  };
  dependencies = builtins.path {
    path = ../tests;
    name = "aos-bazel-family-profile-inputs";
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
in
  pkgs.runCommand pname {buildDeps = [pkgs.python3 parity];} ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${verifier}:${dependencies}
    ${pkgs.python3}/bin/python3 -m unittest discover -s ${verifier} -p 'test_*.py'
    ${pkgs.python3}/bin/python3 ${verifier}/rust_profiles.py \
      --build ${build} --cargo ${cargo} --output "$out/evidence.json"
  ''
