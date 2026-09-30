##! Linux-hosted Bazel C++ toolchain for Darwin Workers runtime binaries.
{
  buildPackages,
  stdenv,
  lib,
}: let
  compiler = stdenv.cc;
  llvm = buildPackages.llvm;
  cpu =
    if stdenv.hostPlatform.isAarch64
    then "darwin_arm64"
    else "darwin_x86_64";
  cpuConstraint =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "x86_64";
  triple = stdenv.hostPlatform.config;
  llvmMajor = builtins.head (lib.splitString "." llvm.version);
in
  buildPackages.mkDerivation {
    pname = "workerd-darwin-bazel-toolchain";
    version = "1";
    targetPlatform = stdenv.hostPlatform;
    runtimeDeps = [compiler llvm stdenv.sdk stdenv.darwinRuntimes];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          touch "$out/REPO.bazel"
          mkdir -p "$out/bin"
          cat > "$out/bin/compiler" <<'COMPILER'
          #!${buildPackages.bash}/bin/bash
          set -eu
          compiling=false
          c_source=false
          cxx_source=false
          for argument in "$@"; do
            case "$argument" in
              -c|-S|-E|-M|-MM|-fsyntax-only) compiling=true ;;
              *.c|*.m|*.s|*.S) c_source=true ;;
              *.cc|*.cp|*.cpp|*.cxx|*.C|*.mm) cxx_source=true ;;
            esac
          done
          if [ "$compiling" = true ] && [ "$c_source" = true ] && [ "$cxx_source" = false ]; then
            exec ${compiler}/bin/cc "$@"
          fi
          exec ${compiler}/bin/c++ "$@"
          COMPILER

          # The source-built LLVM tool handles Darwin libtool arguments and
          # response files without requiring Apple's downloaded build tools.
          ln -s ${llvm}/bin/llvm-libtool-darwin "$out/bin/ar"
          chmod +x "$out/bin/compiler"

          cat > "$out/BUILD.bazel" <<BUILD
          load("@rules_cc//cc:defs.bzl", "cc_toolchain")
          load("@rules_cc//cc/private/toolchain:unix_cc_toolchain_config.bzl", "cc_toolchain_config")

          package(default_visibility = ["//visibility:public"])

          platform(
              name = "target-platform",
              constraint_values = ["@platforms//cpu:${cpuConstraint}", "@platforms//os:osx"],
          )

          filegroup(name = "empty")

          cc_toolchain(
              name = "compiler",
              toolchain_identifier = "aos-${triple}",
              toolchain_config = ":config",
              all_files = ":empty",
              ar_files = ":empty",
              as_files = ":empty",
              compiler_files = ":empty",
              dwp_files = ":empty",
              linker_files = ":empty",
              objcopy_files = ":empty",
              strip_files = ":empty",
              supports_param_files = 1,
          )

          toolchain(
              name = "registered-toolchain",
              exec_compatible_with = ["@platforms//cpu:x86_64", "@platforms//os:linux"],
              target_compatible_with = ["@platforms//cpu:${cpuConstraint}", "@platforms//os:osx"],
              toolchain = ":compiler",
              toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
          )

          cc_toolchain_config(
              name = "config",
              cpu = "${cpu}",
              compiler = "clang",
              toolchain_identifier = "aos-${triple}",
              host_system_name = "${stdenv.buildPlatform.config}",
              target_system_name = "${triple}",
              target_libc = "macosx",
              abi_version = "darwin",
              abi_libc_version = "darwin",
              builtin_sysroot = "${stdenv.sdk}",
              cxx_builtin_include_directories = [
                  "${stdenv.darwinRuntimes}/include/c++/v1",
                  "${stdenv.cc}/lib/clang/aos-darwin/include",
                  "${stdenv.sdk}/usr/include",
                  "${stdenv.sdk}/System/Library/Frameworks",
                  "${llvm}/lib/clang/${llvmMajor}/include",
              ],
              tool_paths = {
                  "gcc": "$out/bin/compiler",
                  "cpp": "$out/bin/compiler",
                  "ld": "$out/bin/compiler",
                  "ar": "$out/bin/ar",
                  "nm": "${llvm}/bin/llvm-nm",
                  "objcopy": "${llvm}/bin/llvm-objcopy",
                  "objdump": "${llvm}/bin/llvm-objdump",
                  "strip": "${llvm}/bin/llvm-strip",
                  "dwp": "${llvm}/bin/llvm-dwp",
                  "gcov": "${llvm}/bin/llvm-cov",
              },
              dbg_compile_flags = ["-g"],
              opt_compile_flags = ["-O2", "-DNDEBUG"],
              supports_start_end_lib = False,
          )
          BUILD
        '';
      }
    ];

    meta = {
      description = "Linux-hosted Bazel C++ toolchain for the Darwin Workers runtime";
      license = "Apache-2.0";
    };
  }
