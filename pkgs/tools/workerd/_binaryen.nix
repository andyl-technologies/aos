##! Binaryen revision selected by Emscripten 5.0.3 for Pyodide.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  revision = "2eb472cd650b183ffe0f88b0365908d0aa669ea3";
  googletest = fetchurl {
    urls = ["https://github.com/google/googletest/archive/e2239ee6043f73722e7aa812a459f54a28552929.tar.gz"];
    hash = "1qcga1ymcxmapxfj3fv2nnqnbgh5jwmjzg3phhf0vsbqm7xgnr97";
  };
in
  mkDerivation {
    pname = "pyodide-binaryen";
    version = "127-${builtins.substring 0 12 revision}";
    src = fetchurl {
      urls = ["https://github.com/WebAssembly/binaryen/archive/${revision}.tar.gz"];
      hash = "0zxcx39bab5x4cidaasf2sw403z3nd789pnsmhfckj57ip46cvig";
    };
    buildDeps = [buildPackages.cmake buildPackages.ninja buildPackages.python3 buildPackages.llvm];
    runtimeDeps = [];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd binaryen-${revision}
            tar xf ${googletest} --strip-components=1 -C third_party/googletest
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build -G Ninja $cmakeFlags \
              -DCMAKE_C_COMPILER=${buildPackages.llvm}/bin/clang \
              -DCMAKE_CXX_COMPILER=${buildPackages.llvm}/bin/clang++ \
                -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
                -DCMAKE_BUILD_TYPE=Release -DENABLE_WERROR=OFF
          '';
        }
        {
          name = "build";
          script = ''cmake --build build -j "$NIX_BUILD_CORES"'';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''build/bin/binaryen-unittests'';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/pyodide-binaryen"
            cp LICENSE "$out/share/licenses/pyodide-binaryen/"
            cp third_party/googletest/LICENSE "$out/share/licenses/pyodide-binaryen/googletest-LICENSE"
          '';
        }
      ];
    passthru.evidenceSources = [googletest];
    meta = {
      description = "WebAssembly optimizer for Pyodide's Emscripten toolchain";
      homepage = "https://github.com/WebAssembly/binaryen";
      license = "Apache-2.0";
    };
  }
