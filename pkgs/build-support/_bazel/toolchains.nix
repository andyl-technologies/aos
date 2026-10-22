##! Native Linux Bazel toolchains with realized compiler-closure identities.
{
  pkgs,
  lib,
}: {
  rust ? pkgs.rust,
  cc ? pkgs.cc,
  gcc ? pkgs.gccUnwrapped,
  binutils ? pkgs.binutils,
  glibc ? pkgs.glibc,
  gccRuntime ? pkgs.gcc-libs,
  identity ? "native",
}: let
  platform = pkgs.stdenv.hostPlatform;
  triple = platform.config;
  cpu =
    if platform.isx86_64
    then "x86_64"
    else "aarch64";
  includeDirectories = [
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
    ["@TRIPLE@" "@CPU@" "@RUST_VERSION@" "@GCC_RUNTIME@" "@INCLUDE_DIRECTORIES@" "@TOOL_PATHS@"]
    [triple cpu rust.version (toString gccRuntime) (builtins.toJSON includeDirectories) (builtins.toJSON tools)]
    (builtins.readFile ../../../tools/bazel/toolchains/BUILD.toolchains.bazel);
in
  if pkgs.stdenv.isCross || !platform.isLinux || !(platform.isx86_64 || platform.isAarch64)
  then throw "mkAosBazelToolchains: native x86_64/aarch64 Linux is qualified first; this platform has no adapter yet"
  else
    pkgs.mkDerivation {
      pname = "aos-bazel-toolchains";
      version = "1";
      src = null;
      sharedBuildCache = false;
      buildDeps = [pkgs.jq];
      outputChecks.out = {};
      exportReferencesGraph.compilers = [rust cc gcc binutils glibc.dev gccRuntime pkgs.bash pkgs.python3];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            ln -s ${rust}/bin/rustc.unwrapped "$out/bin/rustc"
            ln -s ${rust}/bin/rustdoc.unwrapped "$out/bin/rustdoc"
            ln -s ${rust}/bin/cargo "$out/bin/cargo"
            ln -s ${rust}/lib "$out/lib"
            ln -s ${cc}/bin/cc "$out/bin/cc"
            ln -s ${binutils}/bin/ar "$out/bin/ar"
            ln -s ${pkgs.python3}/bin/python3 "$out/bin/python3"
            ln -s ${pkgs.bash}/bin/bash "$out/bin/bash"
            ln -s ${gcc} "$out/gcc"
            ln -s ${binutils} "$out/binutils"
            ln -s ${glibc} "$out/sysroot"
            ln -s ${glibc.dev} "$out/sysroot-dev"
            ln -s ${gccRuntime} "$out/gcc-runtime"
            cat > "$out/paths.bzl" <<'TOOLS'
            AOS_TOOLS = struct(
                bash = "${pkgs.bash}/bin/bash",
                python = "${pkgs.python3}/bin/python3",
            )
            TOOLS
            jq -cS --arg identity ${lib.escapeShellArg identity} \
              '{schema: 1, identity: $identity, closure: [.compilers[] | {path, narHash}] | sort_by(.path)}' \
              "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
            cat > "$out/BUILD.bazel" <<'BUILD'
            ${buildFile}
            BUILD
            touch "$out/REPO.bazel"
          '';
        }
      ];
    }
