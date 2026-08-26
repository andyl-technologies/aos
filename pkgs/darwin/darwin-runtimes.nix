##! Darwin C, C++, unwind, and compiler runtime libraries from LLVM sources.
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  python3,
  stdenv,
}: let
  version = "22.1.0";
in
  mkDerivation {
    pname = "darwin-runtimes";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${version}/llvm-project-${version}.src.tar.xz"
      ];
      hash = "sha256-JdLircQ1bXWEBd2IX8/WRHvOgqkOt4trh84JNL0HcXM=";
    };

    buildDeps = [
      cmake
      ninja
      python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd "llvm-project-${version}.src"
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S runtimes -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DLLVM_ENABLE_RUNTIMES="compiler-rt;libunwind;libcxxabi;libcxx" \
            -DLLVM_INCLUDE_TESTS=OFF \
            -DLLVM_INCLUDE_BENCHMARKS=OFF \
            -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
            -DCOMPILER_RT_BUILD_BUILTINS=ON \
            -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
            -DCOMPILER_RT_BUILD_XRAY=OFF \
            -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
            -DCOMPILER_RT_BUILD_PROFILE=OFF \
            -DCOMPILER_RT_BUILD_ORC=OFF \
            -DLIBUNWIND_ENABLE_SHARED=ON \
            -DLIBUNWIND_ENABLE_STATIC=ON \
            -DLIBUNWIND_ENABLE_ASSERTIONS=OFF \
            -DLIBCXXABI_ENABLE_SHARED=ON \
            -DLIBCXXABI_ENABLE_STATIC=ON \
            -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
            -DLIBCXXABI_ENABLE_ASSERTIONS=OFF \
            -DLIBCXX_ENABLE_SHARED=ON \
            -DLIBCXX_ENABLE_STATIC=ON \
            -DLIBCXX_CXX_ABI=libcxxabi \
            -DLIBCXX_ENABLE_ABI_LINKER_SCRIPT=OFF \
            -DLIBCXX_ENABLE_ASSERTIONS=OFF \
            $cmakeFlags
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
        '';
      }
    ];

    meta = {
      description = "LLVM runtimes for ${stdenv.hostPlatform.system}";
      homepage = "https://llvm.org/";
      license = "Apache-2.0 WITH LLVM-exception";
      platforms = [
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    };
  }
