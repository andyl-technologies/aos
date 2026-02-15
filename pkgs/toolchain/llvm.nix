##! LLVM — compiler infrastructure (foundation for Rust)
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  ninja,
  python3,
  zlib,
}:

let
  version = "19.1.7";
in
mkDerivation {
  pname = "llvm";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/llvm/llvm-project/releases/download/llvmorg-${version}/llvm-project-${version}.src.tar.xz"
    ];
    hash = "sha256-gkAf6nt50AeAQ/dZi4NShNZlCnW5PmS292Hqe2MJdQE=";
  };

  buildDeps = [
    make
    cmake
    ninja
    python3
  ];
  runtimeDeps = [ zlib ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd llvm-project-${version}.src
      '';
    }
    {
      name = "configure";
      script = ''
        cmake -S llvm -B build -G Ninja \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=$out \
          -DLLVM_ENABLE_PROJECTS="clang;lld" \
          -DLLVM_TARGETS_TO_BUILD="X86;AArch64" \
          -DLLVM_LINK_LLVM_DYLIB=ON \
          -DLLVM_INSTALL_UTILS=ON \
          -DLLVM_ENABLE_ZLIB=ON \
          -DLLVM_ENABLE_TERMINFO=OFF \
          -DLLVM_ENABLE_LIBXML2=OFF \
          -DLLVM_ENABLE_LIBEDIT=OFF \
          -DLLVM_INCLUDE_BENCHMARKS=OFF \
          -DLLVM_INCLUDE_EXAMPLES=OFF \
          -DLLVM_INCLUDE_TESTS=OFF \
          -DLLVM_INCLUDE_DOCS=OFF
      '';
    }
    {
      name = "build";
      script = ''
        ninja -C build -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        ninja -C build install
      '';
    }
  ];

  meta = {
    description = "LLVM compiler infrastructure";
    homepage = "https://llvm.org";
    license = "Apache-2.0";
  };
}
