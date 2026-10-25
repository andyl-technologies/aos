##! Requires native test parity and complete selected Rust profile inventories.
{
  pkgs,
  pname,
  build,
  cargo,
  parity,
  compareStrip ? false,
  compareNativeDefaults ? false,
  externalRepositoryPrefix ? null,
}: let
  arguments =
    pkgs.lib.optional compareStrip "--compare-strip"
    ++ pkgs.lib.optionals (externalRepositoryPrefix != null) ["--external-repository-prefix" externalRepositoryPrefix]
    ++ pkgs.lib.optionals compareNativeDefaults ["--native-defaults" "${nativeDefaultsSemantics}/evidence.json"];
  stripSemantics = import ./strip-semantics.nix {inherit pkgs;};
  nativeDefaultsSemantics = import ./profile-semantics.nix {inherit pkgs;};
  verifier = builtins.path {
    path = ./.;
    name = "aos-bazel-family-profile-verifier";
    filter = path: type:
      type
      == "regular"
      && builtins.elem (baseNameOf path) [
        "rust_profiles.py"
        "rust_external_profiles.py"
        "native_compiler_units.py"
        "build_script_profiles.py"
        "test_rust_profiles.py"
        "test_rust_external_profiles.py"
      ];
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
  pkgs.runCommand pname {
    buildDeps =
      [pkgs.python3 parity]
      ++ pkgs.lib.optional compareStrip stripSemantics
      ++ pkgs.lib.optional compareNativeDefaults nativeDefaultsSemantics;
  } ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${verifier}:${dependencies}
    ${pkgs.python3}/bin/python3 -m unittest discover -s ${verifier} -p 'test_*.py'
    ${pkgs.python3}/bin/python3 ${verifier}/rust_profiles.py \
      --build ${build} --cargo ${cargo} --output "$out/evidence.json" \
      ${pkgs.lib.escapeShellArgs arguments}
    ${pkgs.lib.optionalString compareStrip ''
      cp ${stripSemantics}/evidence.json "$out/strip-semantics.json"
    ''}
    ${pkgs.lib.optionalString compareNativeDefaults ''
      cp ${nativeDefaultsSemantics}/evidence.json "$out/profile-semantics.json"
    ''}
  ''
