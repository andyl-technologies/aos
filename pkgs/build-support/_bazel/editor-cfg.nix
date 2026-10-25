##! Binds editor cfg discovery to the declared compiler and native query profile.
{
  pkgs,
  toolchains,
  flags,
}: let
  inputs = builtins.toJSON {
    compiler = "${toolchains}/bin/rustc";
    target = pkgs.stdenv.hostPlatform.config;
    inherit flags;
  };
in
  pkgs.writeTextFile {
    name = "aos-bazel-editor-cfg.py";
    text = ''
      import importlib.util
      import json

      specification = importlib.util.spec_from_file_location("editor_cfg", ${builtins.toJSON "${../../../tools/bazel/metadata/editor_cfg.py}"})
      adapter = importlib.util.module_from_spec(specification)
      specification.loader.exec_module(adapter)
      inputs = json.loads(${builtins.toJSON inputs})
      adapter.main(${builtins.toJSON "${../../../tools/bazel/metadata/export_rust_project.py}"}, **inputs)
    '';
  }
