##! Exercises requested-command coverage without waiving incomplete capture.
{pkgs}: let
  tools = builtins.path {
    path = ../tests;
    name = "aos-compiler-trace-tools";
    filter = path: type:
      type
      == "directory"
      || builtins.elem (builtins.baseNameOf path) [
        "compiler_wrapper.py"
        "inspect_compiler_execution.py"
        "reconstruct_compiler_inputs.py"
        "retain_compiler_inputs.py"
        "verify_cache.py"
        "verify_compiler_options.py"
        "verify_static_runtime.py"
      ];
  };
in
  pkgs.runCommand "aos-bazel-compiler-trace-conformance" {
    buildDeps = [pkgs.python3 pkgs.rust pkgs.cc pkgs.binutils pkgs.strace];
  } ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${tools}
    ${pkgs.python3}/bin/python3 ${./compiler_trace.py} \
      --strace ${pkgs.strace}/bin/strace \
      --rustc ${pkgs.rust}/bin/rustc --rustc-unwrapped ${pkgs.rust}/bin/rustc.unwrapped \
      --cc ${pkgs.cc}/bin/cc --gcc ${pkgs.gccUnwrapped}/bin/gcc \
      --linker ${pkgs.binutils}/bin/ld --output "$out"
  ''
