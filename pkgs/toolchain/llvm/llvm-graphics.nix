##! LLVM with the AMDGPU and NVPTX backends required by graphics drivers
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bootstrapTools,
  stdenv,
  zlib,
  zstd,
  libxml2,
  libedit,
  gcc-libs,
}: let
  mkLLVM = import ./_llvm.nix {
    inherit fetchurl buildPackages bootstrapTools stdenv zlib;
    mkDerivation = attrs: mkDerivation (attrs // {pname = "llvm-graphics";});
    gnumake = buildPackages.gnumake;
    cmake = buildPackages.cmake;
    ninja = buildPackages.ninja;
    python3 = buildPackages.python3;
  };
in
  mkLLVM {
    version = "22.1.0";
    srcHash = "sha256-JdLircQ1bXWEBd2IX8/WRHvOgqkOt4trh84JNL0HcXM=";

    # Add device code generation without changing the ordinary LLVM package
    # used by the bootstrap and Rust toolchains.
    targets = ["X86" "AArch64" "BPF" "WebAssembly" "AMDGPU" "NVPTX"];
    # The bootstrap G++ otherwise finds its static libstdc++ before the
    # separately built shared library. LLVM must share C++ runtime state with
    # graphics clients that also link libstdc++.
    extraRuntimeDeps = [gcc-libs zstd libxml2 libedit];
    extraCmakeFlags = [
      "-DCMAKE_EXE_LINKER_FLAGS=-L${gcc-libs}/lib"
      "-DCMAKE_SHARED_LINKER_FLAGS=-L${gcc-libs}/lib"
      "-DCMAKE_MODULE_LINKER_FLAGS=-L${gcc-libs}/lib"
      "-DLLVM_ENABLE_ZSTD=FORCE_ON"
      "-Dzstd_INCLUDE_DIR=${zstd}/include"
      "-Dzstd_LIBRARY=${zstd}/lib/libzstd.so"
      "-DLLVM_ENABLE_LIBXML2=FORCE_ON"
      "-DLIBXML2_INCLUDE_DIR=${libxml2}/include/libxml2"
      "-DLIBXML2_LIBRARY=${libxml2}/lib/libxml2.so"
      "-DLLVM_ENABLE_LIBEDIT=FORCE_ON"
      "-DLibEdit_INCLUDE_DIRS=${libedit}/include"
      "-DLibEdit_LIBRARIES=${libedit}/lib/libedit.so"
    ];
  }
