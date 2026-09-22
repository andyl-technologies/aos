##! Bazel C++ platform and toolchain registration for ARM64 Linux.
{
  buildPackages,
  callPackage,
  stdenv,
  glibc,
  lib,
}: let
  compiler = callPackage ./_cross-clang.nix {};
  llvm = buildPackages.llvm;
  gcc = stdenv.cc.cc;
  triple = stdenv.hostPlatform.config;
  llvmMajor = builtins.head (lib.splitString "." llvm.version);
in
  buildPackages.mkDerivation {
    pname = "workerd-arm64-bazel-toolchain";
    version = "1";
    targetPlatform = stdenv.hostPlatform;
    runtimeDeps = [compiler llvm gcc glibc.dev];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          touch "$out/REPO.bazel"
          cat > "$out/BUILD.bazel" <<'BUILD'
          load("@rules_cc//cc:defs.bzl", "cc_toolchain")
          load("@rules_cc//cc/private/toolchain:unix_cc_toolchain_config.bzl", "cc_toolchain_config")

          package(default_visibility = ["//visibility:public"])

          platform(
              name = "target-platform",
              constraint_values = ["@platforms//cpu:aarch64", "@platforms//os:linux"],
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
              target_compatible_with = ["@platforms//cpu:aarch64", "@platforms//os:linux"],
              toolchain = ":compiler",
              toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
          )

          cc_toolchain_config(
              name = "config",
              cpu = "aarch64",
              compiler = "clang",
              toolchain_identifier = "aos-${triple}",
              host_system_name = "${stdenv.buildPlatform.config}",
              target_system_name = "${triple}",
              target_libc = "glibc",
              abi_version = "gnu",
              abi_libc_version = "glibc",
              cxx_builtin_include_directories = [
                  "${glibc.dev}/include",
                  "${gcc}/lib/gcc/${triple}/${gcc.version}/include",
                  "${gcc}/lib/gcc/${triple}/${gcc.version}/include-fixed",
                  "${gcc}/${triple}/include/c++/${gcc.version}",
                  "${gcc}/${triple}/include/c++/${gcc.version}/${triple}",
                  "${llvm}/lib/clang/${llvmMajor}/include",
              ],
              tool_paths = {
                  "gcc": "${compiler}/bin/compiler",
                  "cpp": "${compiler}/bin/compiler",
                  "ld": "${compiler}/bin/compiler",
                  "ar": "${llvm}/bin/llvm-ar",
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
      description = "Bazel C++ toolchain for the ARM64 Workers runtime";
      license = "Apache-2.0";
    };
  }
