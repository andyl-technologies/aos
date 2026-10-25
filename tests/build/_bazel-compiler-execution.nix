##! Retains observed Cargo compiler execution and the declared toolchain closure.
{
  pkgs,
  cargo,
  pname ? "aos-bazel-compiler-execution-inspection",
}: let
  toolNames = [
    "compiler_wrapper.py"
    "inspect_compiler_execution.py"
    "reconstruct_compiler_inputs.py"
    "retain_compiler_inputs.py"
    "test_compiler_execution.py"
    "verify_cache.py"
    "verify_compiler_options.py"
    "verify_static_runtime.py"
  ];
  tools = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-compiler-execution-tools";
    filter = path: type:
      type == "directory" || builtins.elem (builtins.baseNameOf path) toolNames;
  };
  compilerClosure = (pkgs.lib.build.closureInfo {inherit pkgs;}) {
    rootPaths = [pkgs.rust pkgs.cc pkgs.gccUnwrapped pkgs.binutils];
    pname = "${pname}-toolchain-closure";
  };
  inputs = {
    schema_version = 1;
    cargo = toString cargo;
    toolchain_closure = toString compilerClosure;
    rustc = "${pkgs.rust}/bin/rustc.unwrapped";
    gcc = "${pkgs.gccUnwrapped}/bin/gcc";
    linker = "${pkgs.binutils}/bin/ld";
  };
in
  pkgs.runCommand pname {
    buildDeps = [pkgs.python3];
  } ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1
    ${pkgs.python3}/bin/python3 -m unittest discover \
      -s ${tools} -p test_compiler_execution.py -v > "$out/parser-tests.log" 2>&1
    ${pkgs.python3}/bin/python3 ${tools}/inspect_compiler_execution.py \
      --trace ${cargo}/compiler-exec.log \
      --cargo-arguments ${cargo}/compiler-arguments.jsonl \
      --rustc ${inputs.rustc} --gcc ${inputs.gcc} --linker ${inputs.linker} \
      --output "$out/execution.json"
    cp ${compilerClosure}/inventory.json "$out/toolchain-closure.json"
    printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON inputs)} > "$out/inputs.json"
  ''
