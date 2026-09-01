##! LLVM 22 — compiler infrastructure
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
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
    version = "22.1.0";
    srcHash = "sha256-JdLircQ1bXWEBd2IX8/WRHvOgqkOt4trh84JNL0HcXM=";
    # The default LLVM 22 is the one the from-source `rust` toolchain links
    # (`link-shared`), so it carries the WebAssembly backend on top of the
    # shared default targets — letting rustc emit `wasm32-unknown-unknown`, the
    # Cloudflare Worker target for `aos-registry-worker`. Without it rustc
    # rejects `-wasm-enable-eh`. Scoped here (not in the shared `_llvm.nix`
    # default) so the bootstrap LLVMs 17–21 and the rust-bootstrap ladder are
    # not needlessly rebuilt.
    targets = ["X86" "AArch64" "BPF" "WebAssembly"];
  }
