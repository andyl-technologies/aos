##! LLVM 22 — compiler infrastructure
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  zstd,
  libxml2,
  libedit,
  bootstrapTools,
  stdenv,
  buildPackages,
}: let
  mkLLVM = import ./_llvm.nix {
    inherit
      mkDerivation
      fetchurl
      gnumake
      cmake
      ninja
      python3
      zlib
      bootstrapTools
      stdenv
      buildPackages
      ;
  };
in
  mkLLVM {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "llvm-as accepts the typed IR and writes the bitcode output.";
      "files" = {
        "answer.ll" = "define i32 @main() {\n  ret i32 0\n}\n";
      };
      "input" = "A well-formed LLVM IR module whose main function returns zero.";
      "operation" = "Assemble the textual module into LLVM bitcode.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/llvm-as"
            "answer.ll"
            "-o"
            "answer.bc"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "llvm-as rejects the type mismatch with its parse-failure status.";
      "files" = {
        "invalid.ll" = "define i32 @main() {\n  ret i8 0\n}\n";
      };
      "input" = "LLVM IR whose i32 function returns an i8 value.";
      "operation" = "Assemble the ill-typed textual module.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/llvm-as"
            "invalid.ll"
            "-o"
            "invalid.bc"
          ];
          "exit_code" = 1;
          "observes_rejection" = true;
        }
      ];
    };
  };

    version = "22.1.0";
    srcHash = "sha256-JdLircQ1bXWEBd2IX8/WRHvOgqkOt4trh84JNL0HcXM=";
    extraRuntimeDeps = [zstd libxml2 libedit];
    extraCmakeFlags = [
      "-DLLVM_ENABLE_ZSTD=FORCE_ON"
      "-Dzstd_INCLUDE_DIR=${zstd}/include"
      "-Dzstd_LIBRARY=${zstd}/lib/libzstd.${
        if stdenv.hostPlatform.isDarwin
        then "dylib"
        else "so"
      }"
      "-DLLVM_ENABLE_LIBXML2=FORCE_ON"
      "-DLIBXML2_INCLUDE_DIR=${libxml2}/include/libxml2"
      "-DLIBXML2_LIBRARY=${libxml2}/lib/libxml2.${
        if stdenv.hostPlatform.isDarwin
        then "dylib"
        else "so"
      }"
      "-DLLVM_ENABLE_LIBEDIT=FORCE_ON"
      "-DLibEdit_INCLUDE_DIRS=${libedit}/include"
      "-DLibEdit_LIBRARIES=${libedit}/lib/libedit.${
        if stdenv.hostPlatform.isDarwin
        then "dylib"
        else "so"
      }"
    ];
    # The default LLVM 22 is the one the from-source `rust` toolchain links
    # (`link-shared`), so it carries the WebAssembly backend on top of the
    # shared default targets — letting rustc emit `wasm32-unknown-unknown`, the
    # Cloudflare Worker target for `aos-registry-worker`. Without it rustc
    # rejects `-wasm-enable-eh`. Scoped here (not in the shared `_llvm.nix`
    # default) so the bootstrap LLVMs 17–21 and the rust-bootstrap ladder are
    # not needlessly rebuilt.
    targets = ["X86" "AArch64" "BPF" "WebAssembly"];
  }
