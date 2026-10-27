##! Extends native execution tools with a source-built Linux target toolchain.
{
  pkgs,
  targetPackages,
  nativeToolchains ? pkgs.aosBazelToolchains,
}: let
  execution = pkgs.stdenv.hostPlatform;
  target = targetPackages.stdenv.hostPlatform;
  executionCpu =
    if execution.isx86_64
    then "x86_64"
    else "aarch64";
  targetCpu =
    if target.isx86_64
    then "x86_64"
    else "aarch64";
  triple = target.config;
  rust = targetPackages.rust.passthru.buildTool;
  # Public target packages contain target-hosted executables. Compilation
  # must use the scheduler-hosted cross tools owned by the target stdenv.
  gcc = targetPackages.stdenv.gcc;
  cc = targetPackages.stdenv.cc;
  binutils = targetPackages.stdenv.binutils;
  glibc = targetPackages.stdenv.glibc;
  gccRuntime = targetPackages.stdenv.gccRuntime;
  includes = [
    "${glibc.dev}/include"
    "${gcc}/lib/gcc/${triple}/${gcc.version}/include"
    "${gcc}/lib/gcc/${triple}/${gcc.version}/include-fixed"
    "${gcc}/include/c++/${gcc.version}"
    "${gcc}/include/c++/${gcc.version}/${triple}"
    "${gcc}/${triple}/include/c++/${gcc.version}"
    "${gcc}/${triple}/include/c++/${gcc.version}/${triple}"
  ];
  tools = {
    gcc = "${cc}/bin/cc";
    cpp = "${cc}/bin/cc";
    ld = "${cc}/bin/cc";
    ar = "${binutils}/bin/ar";
    nm = "${binutils}/bin/nm";
    objcopy = "${binutils}/bin/objcopy";
    objdump = "${binutils}/bin/objdump";
    strip = "${binutils}/bin/strip";
    dwp = "${binutils}/bin/dwp";
    gcov = "${gcc}/bin/gcov";
  };
  buildFile =
    builtins.replaceStrings
    ["@EXEC_TRIPLE@" "@EXEC_CPU@" "@TARGET_TRIPLE@" "@TARGET_CPU@" "@RUST_VERSION@" "@GCC_RUNTIME@" "@INCLUDE_DIRECTORIES@" "@TOOL_PATHS@"]
    [execution.config executionCpu triple targetCpu rust.version (toString gccRuntime) (builtins.toJSON includes) (builtins.toJSON tools)]
    (builtins.readFile ../../../tools/bazel/toolchains/BUILD.cross.bazel);
in
  if
    !(execution.isLinux
      && target.isLinux
      && targetPackages.stdenv.isCross
      && execution.config != target.config
      && (target.isx86_64 || target.isAarch64))
  then throw "Bazel Linux cross toolchains require distinct supported execution and target platforms"
  else
    pkgs.mkDerivation {
      pname = "aos-bazel-cross-toolchains-${target.system}";
      version = "1";
      src = null;
      sharedBuildCache = false;
      buildDeps = [pkgs.jq];
      exportReferencesGraph.compilers = [rust cc gcc binutils glibc.dev gccRuntime nativeToolchains];
      outputChecks.out = {};
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/cross/bin"
            for entry in ${nativeToolchains}/*; do
              name="''${entry##*/}"
              case "$name" in
                BUILD.bazel|nix-support) ;;
                *) ln -s "$entry" "$out/$name" ;;
              esac
            done
            ln -s ${rust}/bin/rustc.unwrapped "$out/cross/bin/rustc"
            ln -s ${rust}/bin/rustdoc.unwrapped "$out/cross/bin/rustdoc"
            ln -s ${rust}/lib "$out/cross/lib"
            ln -s ${gcc} "$out/cross/gcc"
            ln -s ${binutils} "$out/cross/binutils"
            ln -s ${glibc} "$out/cross/sysroot"
            ln -s ${glibc.dev} "$out/cross/sysroot-dev"
            ln -s ${gccRuntime} "$out/cross/gcc-runtime"
            jq -cS '{schema: 1, closure: [.compilers[] | {path, narHash}] | sort_by(.path)}' \
              "$NIX_ATTRS_JSON_FILE" > "$out/cross/closure.json"
            cat ${nativeToolchains}/BUILD.bazel > "$out/BUILD.bazel"
            cat >> "$out/BUILD.bazel" <<'BUILD'
            ${buildFile}
            BUILD
          '';
        }
      ];
    }
